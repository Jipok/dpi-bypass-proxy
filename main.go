package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"

	// "github.com/AkihiroSuda/go-netfilter-queue"
	nfNetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
)

const GID = 2354

var (
	queueNumber   = flag.Uint("queueNumber", 5123, "NFQUEUE number")
	markNumber    = flag.Int("markNumber", 350, "Number for FWMARK, second +1")
	tableNumber   = flag.Int("tableNumber", 3050, "Number for routing table")
	dnsPort       = flag.String("dnsPort", "3053", "port for DNS proxy-server")
	interfaceName = flag.String("interface", "wg0", "interface for proxying domains from list")
	proxyListFile = flag.String("proxyList", "proxy.lst", "File with list of domains to proxy")
	blockListFile = flag.String("blockList", "blocks.lst", "File with list of domains to BLOCK")
	router        = flag.Bool("router", true, "Is router?")
	silent        = flag.Bool("s", false, "Dont't print new DNS entries")
	verbose       = flag.Bool("v", false, "Print every :433 connection status")
	nf            *nfqueue.Nfqueue
	rule          *netlink.Rule
	route         *netlink.Route
	blockIPset    = NewIPv4Set(1000)
	proxyIPset    = NewIPv4Set(1000)
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
		log.Fatalf("Can't change GID: %v\n", err)
	}

	if *proxyListFile == "proxy.lst" && !fileExists(*proxyListFile) {
		fmt.Printf(red("Error:")+" The proxy list file '%s' does not exist.\n", *proxyListFile)
		fmt.Println("To download a sample proxy list, you can use the following command:")
		fmt.Println(green("  wget https://antifilter.download/list/domains.lst -O proxy.lst"))
		os.Exit(1)
	}
	if *blockListFile == "blocks.lst" && !fileExists(*blockListFile) {
		fmt.Printf(red("Error:")+" The block list file '%s' does not exist.\n", *blockListFile)
		fmt.Println("To download a sample block list, you can use the following command:")
		fmt.Println(green("  wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst"))
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	// Настройка NFQUEUE
	config := nfqueue.Config{
		NfQueue:      uint16(*queueNumber),
		MaxPacketLen: 65535,
		MaxQueueLen:  1000,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	var err error
	nf, err = nfqueue.Open(&config)
	if err != nil {
		log.Fatalf(red("Error:")+" opening nfqueue: %v", err)
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

	// Обработчик пакетов
	err = nf.RegisterWithErrorFunc(ctx, nfPacketHandler, nfErrorHandler)
	if err != nil {
		log.Fatalf(red("Error:")+" registering callback: %v", err)
	}

	server := &dns.Server{Addr: ":" + *dnsPort, Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)
	log.Println("Запуск DNS-прокси на порту 53")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}()

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
		// if aaaaRecord, ok := ans.(*dns.AAAA); ok {
		// 	ips = append(ips, aaaaRecord.AAAA.String())
		// }
	}

	if len(ips) == 0 {
		w.WriteMsg(response)
		return
	}

	_, blocked := blockedDomains[domain]
	if blocked {
		for _, ip := range ips {
			if blockIPset.Add(ip) && !*silent {
				log.Printf("DNS: Blocking %s %v", domain, ip)
			}
		}
		w.WriteMsg(response)
		return
	}

	domain = trimDomain(domain)
	_, proxied := proxiedDomains[domain]
	if proxied || testDomain(domain) {
		for _, ip := range ips {
			if proxyIPset.Add(ip) && !*silent {
				log.Printf("DNS: Proxy %s %v", domain, ip)
			}
		}
		w.WriteMsg(response)
		return
	}

	// Выводим домен и IP-адреса в консоль
	fmt.Printf("DNS: Direct %s, IP: %v\n", domain, ips)
	w.WriteMsg(response)
}

// To improve your libnetfilter_queue application in terms of performance, you may consider the following tweaks:

//     increase the default socket buffer size by means of nfnl_rcvbufsiz().
//     set nice value of your process to -20 (maximum priority).
//     set the CPU affinity of your process to a spare core that is not used to handle NIC interruptions.
//     set NETLINK_NO_ENOBUFS socket option to avoid receiving ENOBUFS errors (requires Linux kernel >= 2.6.30).
//     see –queue-balance option in NFQUEUE target for multi-threaded apps (it requires Linux kernel >= 2.6.31).
//     consider using fail-open option see nfq_set_queue_flags() (it requires Linux kernel >= 3.6)
//     increase queue max length with nfq_set_queue_maxlen() to resist to packets burst

func nfErrorHandler(e error) int {
	fmt.Printf(red("Error:")+" %v\n", e)
	return 0
}

func nfPacketHandler(attr nfqueue.Attribute) int {
	packet := gopacket.NewPacket(*attr.Payload, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		// Not a ipv4 packet
		nf.SetVerdict(*attr.PacketID, nfqueue.NfAccept)
		return 0
	}
	ip, _ := ipLayer.(*layers.IPv4)
	// tcp, _ := tcpLayer.(*layers.TCP)
	// fmt.Printf("TCP IPv4   %s:%d  ->  %s:%d   Len: %d\n",
	// 	ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, len(*attr.Payload))

	var err error
	if blockIPset.Exists(ip.DstIP) {
		if *verbose {
			log.Printf("Block connection to %s", ip.DstIP)
		}
		err = nf.SetVerdict(*attr.PacketID, nfqueue.NfDrop)
	} else if proxyIPset.Exists(ip.DstIP) {
		if *verbose {
			log.Printf("Routing connection to %s via %s", ip.DstIP, *interfaceName)
		}
		err = nf.SetVerdictWithMark(*attr.PacketID, nfqueue.NfAccept, *markNumber)
	} else {
		if *verbose {
			log.Printf("Direct connection to %s", ip.DstIP)
		}
		err = nf.SetVerdictWithMark(*attr.PacketID, nfqueue.NfAccept, *markNumber+1)
	}

	if err != nil {
		log.Printf(red("Error:")+" setting mark: %v", err)
	}

	return 0 // No errors
}
