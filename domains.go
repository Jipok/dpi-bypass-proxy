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

// a.b.site.com   -> site.com
// aboba.ru       -> aboba.ru
// localhost      -> localhost
// a.test.co.uk   -> test.co.uk
// a.b.c.test.com -> test.com
func trimDomain(domain string) string {
	parts := strings.Split(domain, ".")

	if len(parts) < 3 {
		return domain
	}
	lastTwo := parts[len(parts)-2:]

	// Если предпоследняя часть короче 3 символов (например, "co.uk"), берем три последние части
	if len(lastTwo[0]) <= 2 {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
		return domain
	}

	return strings.Join(lastTwo, ".")
}

func testDomain(domain string) bool {
	proxyRequiredDomains := []string{
		"youtube",
		"ytimg.com",
		"gstatic.com",
		"google",
		"ggpht.com",
		"discord",
		//
		"casino",
		"online",
		"vavada",
		"cloudfront",
	}
	for _, sub := range proxyRequiredDomains {
		if strings.Contains(domain, sub) {
			return true
		}
	}
	return false
}

func readDomains(sources string, trim bool) (map[string]struct{}, int) {
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
			domain = strings.TrimSpace(domain)
			domain = strings.ToLower(domain)
			if trim {
				domain = trimDomain(domain)
			}
			if domain == "" {
				continue
			}
			if domain[0] == '#' {
				continue
			}
			if testDomain(domain) {
				continue
			}
			if _, exists := result[domain]; !exists {
				result[domain] = struct{}{}
				counter++
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf(red("Error")+" reading file %s: %v", source, err)
		}
	}

	return result, counter
}
