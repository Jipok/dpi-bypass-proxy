package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	// "github.com/AkihiroSuda/go-netfilter-queue"
	nfNetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
)

var (
	queueNumber   = flag.Uint("queueNumber", 5123, "NFQUEUE number")
	markNumber    = flag.Int("markNumber", 350, "Number for FWMARK, second +1")
	tableNumber   = flag.Int("tableNumber", 3050, "Number for routing table")
	interfaceName = flag.String("interface", "wg0", "interface for proxying domains from list")
	proxyListFile = flag.String("proxyList", "proxy.lst", "File with list of domains to proxy")
	blockListFile = flag.String("blockList", "blocks.lst", "File with list of domains to BLOCK")
	silent        = flag.Bool("s", false, "Dont't print detected parsed domains")
	nf            *nfqueue.Nfqueue
	rule          *netlink.Rule
	route         *netlink.Route

	connections = make(map[ConnectionKey]bool)
	connMutex   = &sync.Mutex{}
	link        netlink.Link
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

	// configureNetwork()
	// defer restoreNetwork()
	// Код для режима с пониженными привилегиями

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var err error
	link, err = netlink.LinkByName(*interfaceName)
	if err != nil {
		log.Fatalf(red("Error:")+" getting `%s` interface: %v", *interfaceName, err)
	}

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

	setupRouting()
	defer cleanupRouting()

	configureNetwork()
	defer restoreNetwork()

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")
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

type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	DstPort layers.TCPPort
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
	tcp, _ := tcpLayer.(*layers.TCP)
	fmt.Printf("TCP IPv4   %s:%d  ->  %s:%d   Len: %d\n",
		ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, len(*attr.Payload))

	serverName, err := extractSNI(attr.Payload)
	if err != nil {
		nf.SetVerdict(*attr.PacketID, nfqueue.NfAccept)
		return 0
	}

	_, blocked := blockedDomains[serverName]
	if blocked {
		if !*silent {
			log.Printf("Blocking %s", serverName)
		}
		nf.SetVerdict(*attr.PacketID, nfqueue.NfDrop)
		return 0
	}

	domain := trimDomain(serverName)
	_, proxied := proxiedDomains[domain]
	useVpn := proxied || testDomain(domain)

	if useVpn {
		if !*silent {
			log.Printf("Routing connection to %s via %s", serverName, *interfaceName)
		}
		// Add route via wg0
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &net.IPNet{IP: ip.DstIP, Mask: net.CIDRMask(32, 32)},
			Table:     0,
		}

		err = netlink.RouteAdd(route)
		if err != nil {
			log.Printf("Error adding route: %v", err)
		}

		// Send TCP RST to the client
		err = sendTCPRST(ip, tcp)
		if err != nil {
			log.Printf("Error sending TCP RST: %v", err)
		}

		err = nf.SetVerdict(*attr.PacketID, nfqueue.NfDrop)
	} else {
		if !*silent && serverName != "" {
			log.Printf("Direct connection to %s", serverName)
		}
		err = nf.SetVerdict(*attr.PacketID, nfqueue.NfAccept)
	}

	if err != nil {
		log.Printf(red("Error:")+" setting mark: %v", err)
	}

	return 0 // No errors
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func sendTCPRST(ip *layers.IPv4, tcp *layers.TCP) error {
	// Swap source and destination IPs and Ports
	srcIP := ip.DstIP.To4()
	dstIP := ip.SrcIP.To4()
	srcPort := uint16(tcp.DstPort)
	dstPort := uint16(tcp.SrcPort)
	seqNum := tcp.Ack
	ackNum := tcp.Seq + uint32(len(tcp.Payload))

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("Failed to create raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set IP_HDRINCL to tell the kernel that headers are included in the packet
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("Failed to set IP_HDRINCL: %v", err)
	}

	// Build IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45     // Version (4 bits) + IHL (4 bits)
	ipHeader[1] = 0x00     // Type of Service
	totalLength := 20 + 20 // IP header + TCP header
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(totalLength))
	binary.BigEndian.PutUint16(ipHeader[4:], 0) // Identification
	binary.BigEndian.PutUint16(ipHeader[6:], 0) // Flags + Fragment Offset
	ipHeader[8] = 64                            // TTL
	ipHeader[9] = syscall.IPPROTO_TCP           // Protocol
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)
	ipChecksum := checksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:], ipChecksum)

	// Build TCP header
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:], seqNum)
	binary.BigEndian.PutUint32(tcpHeader[8:], ackNum)
	tcpHeader[12] = (5 << 4)                      // Data Offset (5 words) << 4
	tcpHeader[13] = 0x14                          // Flags (RST + ACK)
	binary.BigEndian.PutUint16(tcpHeader[14:], 0) // Window Size
	binary.BigEndian.PutUint16(tcpHeader[16:], 0) // Checksum (initially zero)
	binary.BigEndian.PutUint16(tcpHeader[18:], 0) // Urgent Pointer

	// Pseudo-header for TCP checksum calculation
	pseudoHeader := make([]byte, 12+20)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(len(tcpHeader)))
	copy(pseudoHeader[12:], tcpHeader)

	tcpChecksum := checksum(pseudoHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:], tcpChecksum)

	// Combine IP and TCP headers
	packet := append(ipHeader, tcpHeader...)

	// Destination address
	addr := &syscall.SockaddrInet4{
		Port: 0, // Port is zero for raw sockets
		Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
	}

	// Send the packet
	if err := syscall.Sendto(fd, packet, 0, addr); err != nil {
		return fmt.Errorf("Failed to send packet: %v", err)
	}

	return nil
}

func setupRouting() {
	route = &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:     *tableNumber,
	}

	err := netlink.RouteAdd(route)
	if err != nil {
		log.Printf(red("Error:")+" adding route: %v", err)
	}

	// Правила маршрутизации на основе меток
	rule = netlink.NewRule()
	rule.Mark = *markNumber
	rule.Table = *tableNumber

	err = netlink.RuleAdd(rule)
	if err != nil {
		log.Printf(red("Error:")+" adding rule: %v", err)
	}
	log.Println("Routing setup completed")
}

func cleanupRouting() {
	err := netlink.RuleDel(rule)
	if err != nil {
		log.Printf(red("Error:")+" deleting rule: %v", err)
	}

	err = netlink.RouteDel(route)
	if err != nil {
		log.Printf(red("Error:")+" deleting route: %v", err)
	}

	log.Println("Routing cleanup completed")
}

func extractSNI(data *[]byte) (string, error) {
	// Поиск начала TLS-сообщения
	var tlsStart int = -1
	for i := 0; i <= len(*data)-5; i++ {
		if (*data)[i] == 0x16 && (*data)[i+1] == 0x03 && (*data)[i+2] == 0x01 {
			tlsStart = i
			break
		}
	}

	if tlsStart == -1 {
		return "", errors.New("TLS ClientHello not found in payload")
	}

	// Проверка, достаточно ли данных для TLS record header
	if len(*data) < tlsStart+5 {
		return "", errors.New("insufficient data for TLS record header")
	}

	// Получение длины ClientHello
	length := int(binary.BigEndian.Uint16((*data)[tlsStart+3 : tlsStart+5]))

	// Проверка, достаточно ли данных
	if len(*data) < tlsStart+5+length {
		return "", errors.New("insufficient data for ClientHello")
	}

	// Выделение ClientHello
	clientHello := (*data)[tlsStart+5 : tlsStart+5+length]

	// Пропуск фиксированных полей
	pos := 38 // 2 (версия) + 32 (random) + 1 (session id length) + 3 (cipher suites length)

	// Пропуск session id
	sessionIDLength := int(clientHello[pos])
	pos += 1 + sessionIDLength

	// Пропуск cipher suites
	cipherSuitesLength := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
	pos += 2 + cipherSuitesLength

	// Пропуск compression methods
	compMethodsLength := int(clientHello[pos])
	pos += 1 + compMethodsLength

	// Проверка наличия расширений
	if pos+2 > len(clientHello) {
		return "", errors.New("no extensions in ClientHello")
	}

	// Получение длины расширений
	extensionsLength := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
	pos += 2

	// Парсинг расширений
	endPos := pos + extensionsLength
	for pos < endPos {
		// Получение типа и длины расширения
		extType := binary.BigEndian.Uint16(clientHello[pos : pos+2])
		extLength := int(binary.BigEndian.Uint16(clientHello[pos+2 : pos+4]))
		pos += 4

		// Проверка, является ли расширение SNI (тип 0)
		if extType == 0 {
			// Пропуск длину списка имен серверов
			// sniListLength := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
			pos += 2

			// Проверка типа имени (должен быть 0 для hostname)
			if clientHello[pos] != 0 {
				return "", errors.New("unexpected server name type")
			}
			pos++

			// Получение длины имени хоста
			hostnameLength := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
			pos += 2

			// Извлечение и возврат имени хоста
			return string(clientHello[pos : pos+hostnameLength]), nil
		}

		// Переход к следующему расширению
		pos += extLength
	}

	return "", errors.New("SNI not found in ClientHello")
}
