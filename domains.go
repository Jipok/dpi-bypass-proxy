package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	proxiedDomains  = make(map[string]struct{})
	proxiedPatterns []string
	blockedDomains  = make(map[string]struct{})
	blockedPatterns []string
)

// Check for pattern for filepath.Match
func isPattern(s string) bool {
	specialChars := "*?[]{}"
	return strings.ContainsAny(s, specialChars)
}

func testDomain(domain string, list []string) bool {
	for _, pattern := range list {
		match, err := filepath.Match(pattern, domain)
		if err != nil {
			log.Fatalf("Pattern `%s` error:", pattern, err)
		}
		if match {
			return true
		}
	}
	return false
}

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

func readDomains(sources string, fn func(domain string) bool) int {
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
			if domain == "" {
				continue
			}
			if domain[0] == '#' {
				continue
			}
			fn(domain)
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf(red("Error")+" reading file %s: %v", source, err)
		}
	}

	return counter
}

func addProxiedDomain(domain string) bool {
	if testDomain(domain, proxiedPatterns) {
		return false
	}
	if isPattern(domain) {
		proxiedPatterns = append(proxiedPatterns, domain)
		return true
	}
	domain = trimDomain(domain)
	if _, exists := proxiedDomains[domain]; !exists {
		proxiedDomains[domain] = struct{}{}
		return true
	}
	return false
}

func addBlockedDomain(domain string) bool {
	if testDomain(domain, blockedPatterns) {
		return false
	}
	if isPattern(domain) {
		blockedPatterns = append(blockedPatterns, domain)
		return true
	}
	if _, exists := blockedDomains[domain]; !exists {
		blockedDomains[domain] = struct{}{}
		return true
	}
	return false
}
