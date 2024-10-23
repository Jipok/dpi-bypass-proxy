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

	// Начинаем парсинг DNS сообщения
	if _, err := parser.Start(dnsPayload); err != nil {
		fmt.Println("Failed to parse DNS message:", err)
		return
	}

	// Пропускаем вопросы (Questions)
	for {
		_, err := parser.Question()
		// qq.Name TODO CNAME?
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			fmt.Println("Failed to parse Question:", err)
			return
		}
	}

	// Читаем ответы (Answers)
	for {
		rr, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			fmt.Println("Failed to parse Answer:", err)
			return
		}

		domainName := rr.Header.Name.String()
		domainName = strings.ToLower(domainName)
		domainName, _ = strings.CutSuffix(domainName, ".")

		switch rr.Header.Type {
		case dnsmessage.TypeAAAA:
			// fallthrough          IPv6 disabled
		case dnsmessage.TypeA:
			if aBody, ok := rr.Body.(*dnsmessage.AResource); ok {
				pair := ResolvedName{domainName, net.IP(aBody.A[:])}
				result = append(result, pair)
			}
		default:
			// Обрабатываем другие типы записей при необходимости
		}
	}
	return
}
