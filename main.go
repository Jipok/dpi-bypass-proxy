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
	conKey := ConnectionKey{ip.SrcIP.String(), ip.DstIP.String(), tcp.DstPort}
	fmt.Printf("TCP IPv4   %s:%d  ->  %s:%d   Len: %d\n",
		ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, len(*attr.Payload))
	_, exists := connections[conKey]
	if exists || ip.DstIP.Equal(net.IPv4(104, 21, 54, 91)) {
		println("conKey из списка обнаружен")
		nf.SetVerdictWithMark(*attr.PacketID, nfqueue.NfAccept, *markNumber)
		return 0
	}

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
		err = nf.SetVerdict(*attr.PacketID, nfqueue.NfDrop)
		if err != nil {
			log.Printf(red("Error:")+" dropping package: %v", err)
		}
		return 0
	}

	domain := trimDomain(serverName)
	_, proxied := proxiedDomains[domain]
	useVpn := proxied || testDomain(domain)

	if useVpn {
		if !*silent {
			log.Printf("Routing connection to %s via %s", serverName, *interfaceName)
		}
		connMutex.Lock()
		connections[conKey] = true
		connMutex.Unlock()
		sendRst(*tcp, *ip)
		// err = nf.SetVerdict(*attr.PacketID, nfqueue.NfDrop)
		err = nf.SetVerdictWithMark(*attr.PacketID, nfqueue.NfDrop, *markNumber+1)
	} else {
		if !*silent && serverName != "" {
			log.Printf("Direct connection to %s", serverName)
		}
		err = nf.SetVerdictWithMark(*attr.PacketID, nfqueue.NfAccept, *markNumber+1)
	}

	if err != nil {
		log.Printf(red("Error:")+" setting mark: %v", err)
	}

	return 0 // No errors
}

func sendRst(tcp layers.TCP, ip layers.IPv4) {
	rstTCP := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     tcp.Seq,
		ACK:     true,
		RST:     true,
		Ack:     tcp.Seq + 1,
		Window:  0,
	}

	rstIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	err := rstTCP.SetNetworkLayerForChecksum(rstIP)
	if err != nil {
		log.Printf("SetNetworkLayerForChecksum error: %v", err)

		return
	}

	rstream := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(rstream, opts, rstIP, rstTCP)
	if err != nil {
		log.Printf("Ошибка сериализации: %v", err)
		return
	}

	rawBytes := rstream.Bytes()

	// Отправляем RST пакет через сырой сокет
	err = sendRawPacket(rawBytes, ip.DstIP)
	if err != nil {
		log.Printf("Ошибка отправки RST пакета: %v", err)
	}
}

func sendRawPacket(packet []byte, dstIP net.IP) error {
	// Открываем сырой сокет
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}

	defer syscall.Close(fd)

	// Устанавливаем опцию IP_HDRINCL
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return err
	}

	// Адрес назначения
	sockaddr := &syscall.SockaddrInet4{
		Port: 0, // Не используется для IPPROTO_RAW
	}
	copy(sockaddr.Addr[:], dstIP.To4())

	// Отправляем пакет
	return syscall.Sendto(fd, packet, 0, sockaddr)
}

func setupRouting() {
	link, err := netlink.LinkByName(*interfaceName)
	if err != nil {
		log.Fatalf(red("Error:")+" getting `%s` interface: %v", *interfaceName, err)
	}

	route = &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:     *tableNumber,
	}

	err = netlink.RouteAdd(route)
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
