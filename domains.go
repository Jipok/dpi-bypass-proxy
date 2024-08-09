package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

var (
	proxiedDomains map[string]struct{}
	blockedDomains map[string]struct{}
)

func testDomain(domain string) bool {
	socksRequiredDomains := []string{
		"rutracker",
		"youtube",
		"ytimg.com",
		"gstatic.com",
		"googleapis.com",
		"googlevideo.com",
		"ggpht.com",
		//
		"casino",
		"online",
		"vavada",
		"cloudfront",
	}
	for _, sub := range socksRequiredDomains {
		if strings.Contains(domain, sub) {
			return true
		}
	}
	return false
}

func readDomains(sources string) (map[string]struct{}, int) {
	result := make(map[string]struct{})
	counter := 0

	for _, source := range strings.Split(sources, ";") {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		file, err := os.Open(source)
		if err != nil {
			log.Fatalf(red("Error")+" opening file %s: %v", source, err)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			domain, _ = strings.CutPrefix(domain, "https-")
			domain, _ = strings.CutPrefix(domain, "https.")
			domain, _ = strings.CutPrefix(domain, "http-")
			domain, _ = strings.CutPrefix(domain, "http.")
			domain, _ = strings.CutPrefix(domain, "0.0.0.0 ")
			domain, _ = strings.CutPrefix(domain, "127.0.0.1 ")
			if domain != "" {
				if domain[0] == '#' || testDomain(domain) {
					continue
				}
				if _, exists := result[domain]; !exists {
					result[domain] = struct{}{}
					counter++
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf(red("Error")+" reading file %s: %v", source, err)
		}
	}

	return result, counter
}
