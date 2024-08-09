package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net/http"
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

func readDomains(source string) (map[string]struct{}, int) {
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

	result := make(map[string]struct{})
	counter := 0
	scanner := bufio.NewScanner(reader)
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
			result[domain] = struct{}{}
			counter += 1
		}
	}

	return result, counter
}
