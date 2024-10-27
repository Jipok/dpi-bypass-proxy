package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

type ResolvedName struct {
	name string
	ip   net.IP
}

// extractDNSPayload извлекает DNS полезную нагрузку из IP пакета
func extractDNSPayload(packet []byte) ([]byte, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	// Парсим IPv4 заголовок
	versionIHL := packet[0]
	version := versionIHL >> 4
	if version != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}

	ihl := versionIHL & 0x0F
	ipHeaderLen := int(ihl) * 4
	if len(packet) < ipHeaderLen {
		return nil, fmt.Errorf("invalid IP header length")
	}

	// srcIP := net.IP(packet[12:16])
	// println(srcIP.String())

	protocol := packet[9]
	if protocol != 17 { // Протокол UDP имеет номер 17
		return nil, fmt.Errorf("not a UDP packet")
	}

	// Парсим UDP заголовок
	if len(packet) < ipHeaderLen+8 {
		return nil, fmt.Errorf("packet too short for UDP header")
	}

	udpHeaderStart := ipHeaderLen
	srcPort := binary.BigEndian.Uint16(packet[udpHeaderStart : udpHeaderStart+2])
	// dstPort := binary.BigEndian.Uint16(packet[udpHeaderStart+2 : udpHeaderStart+4])
	udpLength := binary.BigEndian.Uint16(packet[udpHeaderStart+4 : udpHeaderStart+6])

	// Проверяем длину UDP пакета
	if len(packet) < ipHeaderLen+int(udpLength) {
		return nil, fmt.Errorf("packet too short for UDP payload")
	}

	// Проверяем, является ли пакет DNS ответом (исходный порт 53)
	if srcPort != 53 {
		return nil, fmt.Errorf("not a DNS response (source port != 53)")
	}

	dnsPayload := packet[udpHeaderStart+8 : ipHeaderLen+int(udpLength)]
	return dnsPayload, nil
}

// parseDNSResponse парсит DNS ответ и выводит доменное имя и IP адреса
func parseDNSResponse(dnsPayload []byte) (result []ResolvedName) {
	var parser dnsmessage.Parser

	if _, err := parser.Start(dnsPayload); err != nil {
		fmt.Println("Failed to parse DNS message:", err)
		return
	}

	// Пропускаем вопросы
	for {
		_, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			fmt.Println("Failed to parse Question:", err)
			return
		}
	}

	// Карта для отслеживания CNAME цепочек
	cnameMap := make(map[string]string)
	// Карта для хранения IP адресов, связанных с именами
	ipMap := make(map[string][]net.IP)
	// Список для сбора всех имен, которые нужно обработать
	var names []string

	// Первый проход - собираем все ответы
	for {
		rr, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			fmt.Println("Failed to parse Answer:", err)
			return
		}

		name := strings.ToLower(strings.TrimSuffix(rr.Header.Name.String(), "."))

		switch rr.Header.Type {
		case dnsmessage.TypeCNAME:
			if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
				target := strings.ToLower(strings.TrimSuffix(cname.CNAME.String(), "."))
				cnameMap[name] = target
				// Добавляем имя в список для обработки
				names = append(names, name)
			}
		case dnsmessage.TypeA:
			if aBody, ok := rr.Body.(*dnsmessage.AResource); ok {
				ipMap[name] = append(ipMap[name], net.IP(aBody.A[:]))
				// Добавляем имя в список для обработки, если еще не добавлено
				if _, exists := cnameMap[name]; !exists {
					names = append(names, name)
				}
			}
		}
	}

	// Функция для разворачивания CNAME цепочки и получения конечного имени
	resolveCNAME := func(name string) string {
		for {
			target, exists := cnameMap[name]
			if !exists {
				break
			}
			name = target
		}
		return name
	}

	// Множество для отслеживания уже обработанных пар (имя, IP)
	seen := make(map[string]struct{})

	// Проходим по всем собранным именам и сопоставляем их с IP
	for _, name := range names {
		finalName := resolveCNAME(name)
		ips, exists := ipMap[finalName]
		if !exists {
			continue
		}
		// Собираем всю цепочку имен от исходного до конечного
		chain := []string{name}
		for {
			target, exists := cnameMap[name]
			if !exists || target == name {
				break
			}
			chain = append(chain, target)
			name = target
		}
		// Для каждого имени в цепочке добавляем все связанные IP адреса
		for _, cname := range chain {
			for _, ip := range ips {
				key := cname + ip.String()
				if _, processed := seen[key]; !processed {
					result = append(result, ResolvedName{cname, ip})
					seen[key] = struct{}{}
				}
			}
		}
	}

	return
}
