package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/net/proxy"
)

const UID = 2354

var (
	mainPort       = flag.String("mainPort", "21345", "Port to listen for iptables REDIRECT")
	socksAddr      = flag.String("socks5", "127.0.0.1:1080", "SOCKS5 proxy address")
	proxyListFile  = flag.String("proxyList", "https://antifilter.download/list/urls.lst", "File/URL with list of domains to redirect")
	blockListFile  = flag.String("blockList", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts", "File/URL with list of domains to BLOCK")
	verbose        = flag.Bool("v", false, "Print all dials")
	proxiedDomains map[string]bool
	blockedDomains map[string]bool
	NoOUTPUT       = false
	socksDialer    proxy.Dialer
)

func main() {
	flag.Parse()

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
		log.Fatal("Must be run as root")
	}
	// Код для режима с пониженными привилегиями

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	proxiedDomains = readDomains(*proxyListFile)
	log.Printf("Proxies %d domains\n", len(proxiedDomains))
	blockedDomains = readDomains(*blockListFile)
	log.Printf("Block %d domains\n", len(blockedDomains))

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

	// if err := syscall.Setuid(2354); err != nil {
	// 	fmt.Println("syscall.Setuid error:", err)
	// 	os.Exit(1)
	// }

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

	if blockedDomains[serverName] {
		if *verbose {
			log.Printf("Blocking %s", serverName)
		}
		return
	}

	useSocks := proxiedDomains[serverName]

	socksRequiredDomains := []string{
		"rutracker",
		"youtube",
		"ytimg.com",
		"gstatic.com",
		"googleapis.com",
		"googlevideo.com",
	}
	for _, domain := range socksRequiredDomains {
		if strings.Contains(serverName, domain) {
			useSocks = true
			break
		}
	}

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
		proxyThroughSocks5(conn, originalDst, peeked)
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

func getOriginalDst(conn *net.TCPConn) (net.Addr, error) {
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

func proxyThroughSocks5(conn net.Conn, originalDst net.Addr, peeked []byte) {
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

	pipe(conn, proxyConn)
}

func handleDirectly(conn net.Conn, originalDst net.Addr, peeked []byte) {
	upstreamConn, err := net.Dial(originalDst.Network(), originalDst.String())
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

	pipe(conn, upstreamConn)
}

func pipe(src, dst net.Conn) {
	go func() {
		io.Copy(dst, src)
		dst.Close()
	}()
	io.Copy(src, dst)
	src.Close()
}

func readDomains(source string) map[string]bool {
	var reader io.Reader
	var closer io.Closer

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		}
		resp, err := client.Get(source)
		if err != nil {
			log.Fatal(err)
		}
		reader = resp.Body
		closer = resp.Body
	} else {
		file, err := os.Open(source)
		if err != nil {
			log.Fatal(err)
		}
		reader = file
		closer = file
	}
	defer closer.Close()

	result := make(map[string]bool)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		domain, _ = strings.CutPrefix(domain, "https-")
		domain, _ = strings.CutPrefix(domain, "https.")
		domain, _ = strings.CutPrefix(domain, "http-")
		domain, _ = strings.CutPrefix(domain, "http.")
		domain, _ = strings.CutPrefix(domain, "0.0.0.0 ")
		if domain != "" {
			if domain[0] == '#' {
				continue
			}
			result[domain] = true
		}
	}

	return result
}

func setupIPTables() error {
	command := fmt.Sprintf(`iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %v, output: %s", err, output)
	}

	command = fmt.Sprintf(`iptables -t nat -A OUTPUT -m owner ! --uid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, UID, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err = exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		str := strings.ToLower(string(output))
		if strings.Contains(str, "no") && strings.Contains(str, "chain") && strings.Contains(str, "by that name") {
			fmt.Println("No OUTPUT found in iptables. OK for router")
			NoOUTPUT = true
		} else {
			return fmt.Errorf("iptables: %v, output: %s", err, output)
		}
	}
	log.Println("iptables successfully configured")
	return nil
}

func cleanupIPTables() {
	ok := true
	command := fmt.Sprintf(`iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		fmt.Printf("Can't delete iptables rule: %v, output: %s", err, output)
		ok = false
	}

	if !NoOUTPUT {
		command := fmt.Sprintf(`iptables -t nat -D OUTPUT -m owner ! --uid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, UID, *mainPort)
		fmt.Printf("Trying run:\n    %s\n", command)
		output, err = exec.Command("sh", "-c", command).CombinedOutput()
		if err != nil {
			fmt.Printf("Can't delete iptables rule: %v, output: %s", err, output)
			ok = false
		}
	}
	if ok {
		log.Println("iptables successfully cleaned")
	}
}
