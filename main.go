package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/vishvananda/netlink"
)

const (
	GID            = 2354
	NFQUEUE        = 2034
	INTERFACE_NAME = "dnsr-wg"
)

type Args struct {
	WGConfig  string `arg:"positional" help:"Path to WireGuard configuration file"`
	Interface string `arg:"-i,--interface" help:"Use existing WireGuard interface instead of creating new one from config"`
	ProxyList string `arg:"-p,--proxy-list" default:"proxy.lst" help:"File with list of domains to proxy through WireGuard(or specified interface)"`
	BlockList string `arg:"-b,--block-list" default:"blocks.lst" help:"File with list of domains to block completely"`
	Silent    bool   `arg:"-s,--silent" help:"Suppress output of new DNS entries"`
	Verbose   bool   `arg:"-v,--verbose" help:"Enable verbose output for all DNS-answers"`
	NoClear   bool   `arg:"--no-clear" help:"Do not clear routing table on program exit"`
}

func (Args) Version() string {
	return "dnsr 2.0.0"
}

var args Args

func main() {
	arg.MustParse(&args)

	// Validate
	if args.WGConfig != "" && args.Interface != "" {
		log.Fatal(red("Mutually exclusive options: use either config file or -i flag"))
	}
	if args.WGConfig == "" && args.Interface == "" {
		println(red("Required: ") + "specify either WireGuard config file or existing interface with -i flag")
		println("EXAMPLE:")
		println(green("  sudo ./dnsr ~/my-wireguard.conf"))
		println("OR")
		println(green("  sudo ./dnsr --interface wg0"))
		os.Exit(1)
	}

	if args.ProxyList == "proxy.lst" && !fileExists(args.ProxyList) {
		fmt.Printf(red("Error:")+" The proxy list file '%s' does not exist.\n", args.ProxyList)
		fmt.Println("To download a good proxy list, you can use the following command:")
		fmt.Println(green("  wget https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst -O proxy.lst"))
		os.Exit(1)
	}
	if args.BlockList == "blocks.lst" && !fileExists(args.BlockList) {
		fmt.Printf(yellow("Warning:")+" The block list file '%s' does not exist.\n", args.BlockList)
		fmt.Println("To download a sample block list, you can use the following command:")
		fmt.Println(green("  wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst\n"))
	}

	if os.Getuid() != 0 {
		log.Fatal(red("Must be run as root"))
	}

	if err := syscall.Setgid(GID); err != nil {
		log.Fatalf(red("Can't change GID: %v\n"), err)
	}

	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		log.Fatalf(red("Failed to enable IP forwarding: %v"), err)
	}

	// Catch Ctrl-C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	//
	readDomains(args.ProxyList, addProxiedDomain)
	log.Printf("Proxies %d top-level domains, %d globs\n", len(proxiedDomains), len(proxiedPatterns))
	runtime.GC()

	if fileExists(args.BlockList) {
		readDomains(args.BlockList, addBlockedDomain)
		log.Printf("Block %d domains, %d globs\n", len(blockedDomains), len(blockedPatterns))
		runtime.GC()
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("Total mem usage: %v MiB\n", m.TotalAlloc/1024/1024)

	if args.Silent {
		fmt.Println("Silent mode, run without -s for verbose output")
	}

	// Check for existing interface
	var err error
	link, err = netlink.LinkByName(INTERFACE_NAME)
	if err == nil {
		log.Print(yellow("An existing `dnsr-wg` interface was found, was the process terminated last time?"))
		log.Print(yellow("We assume so. The interface will be removed and we will try to remove the iptables rules."))
		removeWireguard()
		removeNfqueue()
		log.Print(green("It seems that everything was successfully cleaned up. Normal startup\n"))
	}

	// Configure interface
	if args.WGConfig != "" {
		setupWireguard()
		defer removeWireguard()
	} else {
		link, err = netlink.LinkByName(args.Interface)
		if err != nil {
			log.Fatalf(red("Error:")+" getting `%s` interface: %v", args.Interface, err)
		}
		execCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", args.Interface))
		log.Printf(green("Using `%s` interface"), args.Interface)
	}

	setupRouting()
	defer cleanupRouting()

	setupNfqueue()
	defer removeNfqueue()

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")

	if args.Interface != "" {
		execCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", args.Interface))
	}
}

///////////////////////////////////////////////////////////////////////////////

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

func execCommand(cmdargs ...string) {
	cmd := strings.Join(cmdargs, " ")
	if args.Verbose {
		fmt.Println(yellow("EXEC") + "  " + cmd)
	}
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		if !args.Verbose {
			fmt.Println(yellow("EXEC") + "  " + cmd)
		}
		log.Fatalf(red("%v")+", output: %s \n", err, output)
	}
}
