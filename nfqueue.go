package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/florianl/go-nfqueue"
	nfNetlink "github.com/mdlayher/netlink"
)

var (
	blockIPset = NewIPv4Set(1000)
	proxyIPset = NewIPv4Set(1000)
	nf         *nfqueue.Nfqueue
	nfCancel   context.CancelFunc
)

func setupNfqueue() {
	config := nfqueue.Config{
		NfQueue:      NFQUEUE,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	var err error
	nf, err = nfqueue.Open(&config)
	if err != nil {
		log.Fatal("could not open nfqueue socket:", err)
		return
	}
	// defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(nfNetlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			nfNetlink.NoENOBUFS, err)
		return
	}

	var ctx context.Context
	ctx, nfCancel = context.WithCancel(context.Background())
	// defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		nf.SetVerdict(id, processPacket(*a.Payload))
		return 0
	}

	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		log.Fatal(err)
	}

	execCommand("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	execCommand("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	execCommand("iptables -I OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	log.Printf(green("NFQUEUE `%d` successfully configured"), NFQUEUE)
}

func removeNfqueue() {
	if nf != nil {
		nfCancel()
		nf.Close()
	}
	execCommand("iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	execCommand("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	execCommand("iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	log.Printf(green("NFQUEUE `%d` cleanup completed"), NFQUEUE)
}

// processPacket обрабатывает перехваченный пакет
func processPacket(packet []byte) int {
	dnsPayload, err := extractDNSPayload(packet)
	if err != nil {
		// Not a DNS-answer
		return nfqueue.NfAccept // TODO or drop?
	}
	dnsResponse := parseDNSResponse(dnsPayload)

	// Block?
	for _, resolved := range dnsResponse {
		_, blocked := blockedDomains[resolved.name]
		if blocked || checkPatterns(resolved.name, blockedPatterns) != "" {
			if blockIPset.Add(resolved.ip) && !args.Silent {
				log.Printf("Blocking DNS-answer for %s", resolved.name)
			}
			return nfqueue.NfDrop
		}

	}

	// Proxy?
	direct := true
	for _, resolved := range dnsResponse {
		trimmedDomain := trimDomain(resolved.name)
		_, proxied := proxiedDomains[trimmedDomain]
		if proxied || checkPatterns(resolved.name, proxiedPatterns) != "" {
			direct = false
			if proxyIPset.Add(resolved.ip) {
				go addRoute(resolved.ip)
				if !args.Silent {
					log.Printf("New proxy route %s :: %v", resolved.name, resolved.ip)
				}
			} else if args.Verbose {
				log.Printf("Old proxy route %s :: %v", resolved.name, resolved.ip)
			}
		}
	}

	// Direct
	if args.Verbose && direct {
		for _, resolved := range dnsResponse {
			log.Printf("Direct %s :: %v\n", resolved.name, resolved.ip)
		}
	}
	return nfqueue.NfAccept
}
