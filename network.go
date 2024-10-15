package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
)

var (
	NoOUTPUT = false
	useNFT   = false
	link     netlink.Link
)

func checkCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func checkRules(cmd string) bool {
	output, err := exec.Command("sh", "-c", cmd).Output()
	return err == nil && len(output) > 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func runCommand(cmd string) {
	fmt.Println("  " + cmd)
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Fatalf(red("%v")+", output: %s \n", err, output)
	}
}

func setupRouting() {
	if *router {
		runCommand(fmt.Sprintf(`iptables -t nat -A PREROUTING ! -i lo -p udp --dport 53 -j REDIRECT --to-port %s`, *dnsPort))

		// runCommand("iptables -A FORWARD -t mangle -j CONNMARK --restore-mark")
		// runCommand(fmt.Sprintf(`iptables -t mangle -A FORWARD -p tcp --dport 443 -m mark --mark 0 -j NFQUEUE --queue-num %d`, *queueNumber))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -A OUTPUT -m owner ! --gid-owner %d -p udp --dport 53 -j REDIRECT --to-port %s`, GID, *dnsPort))

		// runCommand("iptables -A OUTPUT -t mangle -j CONNMARK --restore-mark")
		// runCommand(fmt.Sprintf(`iptables -A OUTPUT -m mark --mark 0 -p tcp --destination-port 443 -j NFQUEUE --queue-num %d`, *queueNumber))
	}

	// runCommand("iptables -A POSTROUTING -t mangle -j CONNMARK --save-mark")
	// runCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", *interfaceName))

	var err error
	link, err = netlink.LinkByName(*interfaceName)
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
	if *router {
		runCommand(fmt.Sprintf(`iptables -t nat -D PREROUTING ! -i lo -p udp --dport 53 -j REDIRECT --to-port %s`, *dnsPort))

		// runCommand("iptables -D FORWARD -t mangle -j CONNMARK --restore-mark")
		// runCommand(fmt.Sprintf(`iptables -t mangle -D FORWARD -p tcp --dport 443 -m mark --mark 0 -j NFQUEUE --queue-num %d`, *queueNumber))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -D OUTPUT -m owner ! --gid-owner %d -p udp --dport 53 -j REDIRECT --to-port %s`, GID, *dnsPort))

		// runCommand("iptables -D OUTPUT -t mangle -j CONNMARK --restore-mark")
		// runCommand(fmt.Sprintf(`iptables -D OUTPUT -m mark --mark 0 -p tcp --destination-port 443 -j NFQUEUE --queue-num %d`, *queueNumber))
	}

	// runCommand("iptables -D POSTROUTING -t mangle -j CONNMARK --save-mark")
	// runCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", *interfaceName))

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
