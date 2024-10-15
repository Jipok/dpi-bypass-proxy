package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/miekg/dns"

	"github.com/vishvananda/netlink"
)

const GID = 2354

var (
	dnsPort       = flag.String("dnsPort", "3053", "port for DNS proxy-server")
	interfaceName = flag.String("interface", "wg0", "interface for proxying domains from list")
	proxyListFile = flag.String("proxyList", "proxy.lst", "File with list of domains to proxy")
	blockListFile = flag.String("blockList", "blocks.lst", "File with list of domains to BLOCK")
	router        = flag.Bool("router", true, "Is router?")
	silent        = flag.Bool("s", false, "Dont't print new DNS entries")
	verbose       = flag.Bool("v", false, "Print every :433 connection status")

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
	counter := 0
	proxiedDomains, counter = readDomains(*proxyListFile, true)
	log.Printf("Proxies %d top-level domains\n", counter)
	runtime.GC()

	blockedDomains, counter = readDomains(*blockListFile, false)
	log.Printf("Block %d domains\n", counter)
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

	// Start dns server
	server := &dns.Server{Addr: ":" + *dnsPort, Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)
	log.Printf("Starting DNS-proxy-server on :%s \n", *dnsPort)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("DNS-server error: %v", err)
		}
	}()

	// Setup iptables
	setupRouting()
	defer cleanupRouting()

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	domain, _ := strings.CutSuffix(question.Name, ".")
	domain = strings.ToLower(domain)
	// qtype := dns.TypeToString[question.Qtype]

	// Пересылаем запрос на целевой DNS-сервер
	client := new(dns.Client)
	response, _, err := client.Exchange(r, "8.8.8.8:53")
	if err != nil || response == nil {
		dns.HandleFailed(w, r)
		return
	}
	response.Id = r.Id

	// Обрабатываем ответы
	var ips []net.IP
	for _, ans := range response.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			ips = append(ips, aRecord.A)
		}
		// Для IPv6:
		// if aaaaRecord, ok := ans.(*dns.AAAA); ok {
		// 	ips = append(ips, aaaaRecord.AAAA.String())
		// }
	}

	_, blocked := blockedDomains[domain]
	if blocked {
		for _, ip := range ips {
			if blockIPset.Add(ip) && !*silent {
				log.Printf("Blocking %s %v", domain, ip)
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return
	}

	if len(ips) == 0 {
		w.WriteMsg(response)
		return
	}

	domain = trimDomain(domain)
	_, proxied := proxiedDomains[domain]
	if proxied || testDomain(domain) {
		for _, ip := range ips {
			if proxyIPset.Add(ip) {
				addRoute(ip)
				if !*silent {
					log.Printf("New proxy route %s %v", domain, ip)
				}
			}
		}
		w.WriteMsg(response)
		return
	}

	if *verbose {
		fmt.Printf("Direct %s, IP: %v\n", domain, ips)
	}
	w.WriteMsg(response)
}
