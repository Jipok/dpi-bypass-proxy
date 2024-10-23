package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue"

	nfNetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
)

const GID = 2354

var (
	interfaceName = flag.String("interface", "wg0", "interface for proxying domains from list")
	proxyListFile = flag.String("proxyList", "proxy.lst", "File with list of domains to proxy")
	blockListFile = flag.String("blockList", "blocks.lst", "File with list of domains to BLOCK")
	silent        = flag.Bool("s", false, "Dont't print new DNS entries")
	verbose       = flag.Bool("v", false, "Print every :433 connection status")
	noClear       = flag.Bool("noClear", false, "Do not clear routing table on exit")

	blockIPset = NewIPv4Set(1000)
	proxyIPset = NewIPv4Set(1000)
)

func red(str string) string {
	return "\033[31m" + str + "\033[0m"
}

func green(str string) string {
	return "\033[32m" + str + "\033[0m"
}

func yellow(str string) string {
	return "\033[33m" + str + "\033[0m"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func main() {
	flag.Parse()

	if os.Getuid() != 0 {
		log.Fatal(red("Must be run as root"))
	}

	if err := syscall.Setgid(GID); err != nil {
		log.Fatalf(red("Can't change GID: %v\n"), err)
	}

	if *proxyListFile == "proxy.lst" && !fileExists(*proxyListFile) {
		fmt.Printf(red("Error:")+" The proxy list file '%s' does not exist.\n", *proxyListFile)
		fmt.Println("To download a sample proxy list, you can use the following command:")
		fmt.Println(green("  wget https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst -O proxy.lst"))
		os.Exit(1)
	}
	if *blockListFile == "blocks.lst" && !fileExists(*blockListFile) {
		fmt.Printf(red("Error:")+" The block list file '%s' does not exist.\n", *blockListFile)
		fmt.Println("To download a sample block list, you can use the following command:")
		fmt.Println(green("  wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst"))
		os.Exit(1)
	}

	// Catch Ctrl-C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	//
	readDomains(*proxyListFile, addProxiedDomain)
	log.Printf("Proxies %d top-level domains, %d globs\n", len(proxiedDomains), len(proxiedPatterns))
	runtime.GC()

	readDomains(*blockListFile, addBlockedDomain)
	log.Printf("Block %d domains, %d globs\n", len(blockedDomains), len(blockedPatterns))
	runtime.GC()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("Total mem usage: %v MiB\n", m.TotalAlloc/1024/1024)

	if *silent {
		fmt.Println("Silent mode, run without -s for verbose output")
	}

	var err error
	link, err = netlink.LinkByName(*interfaceName)
	if err != nil {
		log.Fatalf(red("Error:")+" getting `%s` interface: %v", *interfaceName, err)
	}

	// Setup iptables
	setupRouting()
	defer cleanupRouting()

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      2034,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Fatal("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(nfNetlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			nfNetlink.NoENOBUFS, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		nf.SetVerdict(id, processPacket(*a.Payload))
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")
}

// processPacket обрабатывает перехваченный пакет
func processPacket(packet []byte) int {
	dnsPayload, err := extractDNSPayload(packet)
	if err != nil {
		// Not a DNS-answer
		return nfqueue.NfAccept // TODO or drop?
	}
	dnsResponse := parseDNSResponse(dnsPayload)

	// Block?
	for _, resolved := range dnsResponse {
		_, blocked := blockedDomains[resolved.name]
		if blocked || checkPatterns(resolved.name, blockedPatterns) != "" {
			if blockIPset.Add(resolved.ip) && !*silent {
				log.Printf("Blocking DNS-answer for %s", resolved.name)
			}
			return nfqueue.NfDrop
		}

	}

	// Proxy?
	direct := true
	for _, resolved := range dnsResponse {
		trimmedDomain := trimDomain(resolved.name)
		_, proxied := proxiedDomains[trimmedDomain]
		if proxied || checkPatterns(resolved.name, proxiedPatterns) != "" {
			direct = false
			if proxyIPset.Add(resolved.ip) {
				go addRoute(resolved.ip)
				if !*silent {
					log.Printf("New proxy route %s :: %v", resolved.name, resolved.ip)
				}
			} else if *verbose {
				log.Printf("Old proxy route %s :: %v", resolved.name, resolved.ip)
			}
		}

	}

	if *verbose && direct {
		for _, resolved := range dnsResponse {
			log.Printf("Direct %s :: %v\n", resolved.name, resolved.ip)
		}
	}

	return nfqueue.NfAccept
}
