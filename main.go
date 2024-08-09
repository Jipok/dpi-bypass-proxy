package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

const UID = 2354

var (
	mainPort = flag.String("mainPort", "21345", "Port to listen for iptables REDIRECT")
	// Этот размер буфера можно настроить для повышения производительности
	spliceBufferSize = flag.Int("spliceBufferSize", 16384, "Buffer size for linux splice(2)")
	socksAddr        = flag.String("socks5", "127.0.0.1:1080", "SOCKS5 proxy address")
	interfaceName    = flag.String("interface", "", "proxy through interface instead of socks5")
	proxyListFile    = flag.String("proxyList", "proxy.lst", "File with list of domains to proxy")
	blockListFile    = flag.String("blockList", "blocks.lst", "File with list of domains to BLOCK")
	verbose          = flag.Bool("v", false, "Print all dials")
	socksDialer      proxy.Dialer
	interfaceAddr    *net.TCPAddr
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

	interfaceAddr = getInterfaceIP(*interfaceName)

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

	if os.Getuid() == 0 {
		// Запущено с root-правами
		if err := setupIPTables(); err != nil {
			log.Fatalf("Can't set iptables: %v", err)
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Перезапуск себя с другим UID
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: UID, Gid: UID},
		}

		if err := cmd.Start(); err != nil {
			log.Fatalf("Failed to start low-privilege process: %v", err)
		}

		// Горутина для ожидания завершения дочернего процесса
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		// Ожидание сигнала или завершения дочернего процесса
		select {
		case sig := <-sigChan:
			log.Printf("Received signal: %v", sig)
			// Отправляем сигнал дочернему процессу
			if err := cmd.Process.Signal(sig); err != nil {
				log.Printf("Failed to send signal to child process: %v", err)
			}
			// Ожидаем завершения дочернего процесса
			<-done
		case err := <-done:
			if err != nil {
				log.Printf("Low-privilege process exited with error: %v", err)
			}
		}

		cleanupIPTables()
		return
	}

	if os.Getuid() != UID {
		log.Fatal(red("Must be run as root"))
	}
	// Код для режима с пониженными привилегиями

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	counter := 0
	proxiedDomains, counter = readDomains(*proxyListFile)
	log.Printf("Proxies %d domains\n", counter)
	runtime.GC()

	blockedDomains, counter = readDomains(*blockListFile)
	log.Printf("Block %d domains\n", counter)
	runtime.GC()

	ln, err := net.Listen("tcp", ":"+*mainPort)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", ":"+*mainPort, err)
	}
	defer ln.Close()
	log.Printf("Listening on %s", ":"+*mainPort)

	socksDialer, err = proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		return
	}

	if interfaceAddr == nil {
		log.Println(green("Proxying will be done via socks5"))
	} else {
		log.Printf(green("Proxying will be done via `%s` interface"), *interfaceName)
	}

	if !*verbose {
		fmt.Println("Silent mode, run with -v for verbose output")
	}
	fmt.Println("====================")

	// var m runtime.MemStats
	// runtime.ReadMemStats(&m)
	// fmt.Printf("Alloc = %v MiB", m.Alloc/1024/1024)
	// fmt.Printf("\nTotalAlloc = %v MiB", m.TotalAlloc/1024/1024)
	// fmt.Printf("\nSys = %v MiB", m.Sys/1024/1024)
	// fmt.Printf("\nNumGC = %v\n", m.NumGC)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}

			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				log.Println("Not a TCP connection")
				conn.Close()
				continue
			}

			go handleConnection(tcpConn, *socksAddr)
		}
	}()

	<-sigChan
	log.Println("Shutting down...")
}

func handleConnection(conn *net.TCPConn, socks5Addr string) {
	defer conn.Close()
	peeked, serverName, _ := readServerName(conn)
	// if err != nil {
	// 	log.Printf("Failed to read server name: %v", err)
	// 	return
	// }

	_, blocked := blockedDomains[serverName]
	if blocked {
		if *verbose {
			log.Printf("Blocking %s", serverName)
		}
		return
	}

	_, proxied := proxiedDomains[serverName]
	useSocks := proxied || testDomain(serverName)

	originalDst, err := getOriginalDst(conn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}
	if serverName == "" {
		serverName = originalDst.String()
	}

	if useSocks {
		if *verbose {
			log.Printf("Proxying connection to %s", serverName)
		}
		if interfaceAddr == nil {
			proxyThroughSocks5(conn, originalDst, peeked)
		} else {
			proxyThroughInterface(conn, originalDst, peeked)
		}
	} else {
		if *verbose {
			log.Printf("Directly connection to %s", serverName)
		}
		handleDirectly(conn, originalDst, peeked)
	}
}

func readServerName(conn *net.TCPConn) ([]byte, string, error) {
	// Чтение TLS record header
	header := make([]byte, 5)
	_, err := conn.Read(header)
	if err != nil {
		return []byte{}, "", err
	}

	// Проверка, что это ClientHello
	if header[0] != 0x16 || header[1] != 0x03 || header[2] != 0x01 {
		return header, "", errors.New("not a TLS ClientHello")
	}

	// Получение длины ClientHello
	length := int(binary.BigEndian.Uint16(header[3:5]))

	// Чтение ClientHello
	clientHello := make([]byte, length)
	_, err = conn.Read(clientHello)
	// _, err = io.ReadFull(conn, clientHello)
	peeked := append(header, clientHello...)
	if err != nil {
		return peeked, "", err
	}

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
		return peeked, "", errors.New("no extensions in ClientHello")
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
				return peeked, "", errors.New("unexpected server name type")
			}
			pos++

			// Получение длины имени хоста
			hostnameLength := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
			pos += 2

			// Извлечение и возврат имени хоста
			return peeked, string(clientHello[pos : pos+hostnameLength]), nil
		}

		// Переход к следующему расширению
		pos += extLength
	}

	return peeked, "", errors.New("SNI not found in ClientHello")
}

func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fd := int(file.Fd())
	addr, err := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, 80) // SO_ORIGINAL_DST
	if err != nil {
		return nil, err
	}

	ip := net.IPv4(addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])
	port := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}, nil
}

func proxyThroughInterface(incomingConn *net.TCPConn, originalDst *net.TCPAddr, peeked []byte) {
	upstreamConn, err := net.DialTCP(originalDst.Network(), interfaceAddr, originalDst)
	if err != nil {
		log.Printf("Failed to dial %s directly: %v", originalDst.String(), err)
		return
	}
	defer upstreamConn.Close()

	// Отправляем ранее прочитанные данные
	_, err = upstreamConn.Write(peeked)
	if err != nil {
		log.Printf("Failed to write initial data: %v", err)
		return
	}

	pipe(incomingConn, upstreamConn)
}

func proxyThroughSocks5(incomingConn *net.TCPConn, originalDst net.Addr, peeked []byte) {
	proxyConn, err := socksDialer.Dial(originalDst.Network(), originalDst.String())
	if err != nil {
		log.Printf("Failed to dial %s through SOCKS5: %v", originalDst.String(), err)
		return
	}
	defer proxyConn.Close()

	// Отправляем ранее прочитанные данные
	_, err = proxyConn.Write(peeked)
	if err != nil {
		log.Printf("Failed to write initial data: %v", err)
		return
	}

	pipe(incomingConn, proxyConn.(*net.TCPConn))
}

func handleDirectly(incomingConn *net.TCPConn, originalDst net.Addr, peeked []byte) {
	upstreamConn, err := net.Dial("tcp", originalDst.String())
	if err != nil {
		log.Printf("Failed to dial %s directly: %v", originalDst.String(), err)
		return
	}
	defer upstreamConn.Close()

	// Отправляем ранее прочитанные данные
	_, err = upstreamConn.Write(peeked)
	if err != nil {
		log.Printf("Failed to write initial data: %v", err)
		return
	}

	pipe(incomingConn, upstreamConn.(*net.TCPConn))
}

// pipe sets up bidirectional data transfer between two TCP connections using splice.
func pipe(incomingConn, upstreamConn *net.TCPConn) {
	// Create pipes for splice
	var pipeFdsIncomingToUpstream [2]int
	var pipeFdsUpstreamToIncoming [2]int
	if err := unix.Pipe2(pipeFdsIncomingToUpstream[:], unix.O_NONBLOCK); err != nil {
		log.Fatalf("failed to create pipe: %v", err)
	}
	if err := unix.Pipe2(pipeFdsUpstreamToIncoming[:], unix.O_NONBLOCK); err != nil {
		log.Fatalf("failed to create pipe: %v", err)
	}

	transfer := func(srcFd, dstFd int, pipeFds [2]int) error {
		for {
			bytes, err := unix.Splice(srcFd, nil, pipeFds[1], nil, *spliceBufferSize, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MORE)
			if err != nil {
				if err == unix.EAGAIN {
					continue
				}
				return err
			}
			if bytes == 0 {
				return nil
			}

			for bytes > 0 {
				written, err := unix.Splice(pipeFds[0], nil, dstFd, nil, int(bytes), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MORE)
				if err != nil {
					if err == unix.EAGAIN {
						continue
					}
					// Hide "broken pipe" and "bad file descriptor" spam due to closed connection
					if err == unix.EPIPE || err == unix.EBADFD {
						return nil
					}
					return err
				}
				bytes -= written
			}
		}
	}

	srcFdIncoming, err := incomingConn.File()
	if err != nil {
		log.Printf("failed to get file descriptor for incomingConn: %v", err)
	}
	defer srcFdIncoming.Close()
	srcFdUpstream, err := upstreamConn.File()
	if err != nil {
		log.Printf("failed to get file descriptor for upstreamConn: %v", err)
	}
	defer srcFdUpstream.Close()

	// Transfer data from incomingConn to upstreamConn
	go func() {
		if err := transfer(int(srcFdIncoming.Fd()), int(srcFdUpstream.Fd()), pipeFdsIncomingToUpstream); err != nil {
			log.Printf("error during transfer from incoming to upstream: %v", err)
		}
	}()

	// Transfer data from upstreamConn to incomingConn
	if err := transfer(int(srcFdUpstream.Fd()), int(srcFdIncoming.Fd()), pipeFdsUpstreamToIncoming); err != nil {
		log.Printf("error during transfer from upstream to incoming: %v", err)
	}
}

func getInterfaceIP(interfaceName string) *net.TCPAddr {
	if interfaceName == "" {
		return nil
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return &net.TCPAddr{IP: net.ParseIP(ipnet.IP.String())}
			}
		}
	}

	log.Fatalf(red("Error:")+"no suitable IP address found for `%s`", interfaceName)
	return nil
}
