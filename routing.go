package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

var (
	link netlink.Link
)

func setupRouting() {
	// Find collisions
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     0,
	}, netlink.RT_FILTER_OIF)
	if err != nil {
		log.Fatalf(red("Error:")+" can't read netlink.RouteList: %v", err)
		return
	}

	for _, route := range routes {
		if route.Dst != nil {
			proxyIPset.Add(route.Dst.IP)
		}
	}
	if len(proxyIPset.set) > 0 {
		log.Printf(yellow("WARNING! ")+"found %d collisions in routes table! Will be treated as own.", len(proxyIPset.set))
	}

	// Load user preset
	count := 0
	for _, source := range strings.Split(args.PresetIPs, ";") {
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
			line := scanner.Text()
			// Remove comment
			if idx := strings.Index(line, "#"); idx != -1 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Parse IP
			ip := net.ParseIP(line)
			if ip == nil {
				log.Printf(yellow("Can't parse line in %s: ")+"%s", source, line)
				continue
			}
			if addRoute(ip) {
				count++
			} else {
				log.Printf(yellow("  %s"), ip.String())
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf(red("Error")+" reading file %s: %v", source, err)
		}
	}

	if args.PresetIPs != "" {
		log.Printf("Routing %d preset IP addresses", count)
	}
}

func cleanupRouting() {
	if !args.Persistent {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Table:     0,
		}, netlink.RT_FILTER_OIF)
		if err != nil {
			log.Fatalf(red("Error:")+" can't read netlink.RouteList: %v", err)
			return
		}

		for ip := range proxyIPset.set {
			delRoute(net.ParseIP(ip))
		}

		for _, route := range routes {
			if route.Dst != nil {
				proxyIPset.Add(route.Dst.IP)
			}
		}
		log.Println(green("Routing cleanup completed"))
	} else {
		if len(proxyIPset.set) > 0 {
			fmt.Printf(yellow("There are %d entries in the routing table, there will be no cleaning.\n"), len(proxyIPset.set))
		}
	}
}

func singleHostRoute(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(128, 128),
	}
}

func addRoute(ip net.IP) bool {
	newRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       singleHostRoute(ip),
		Table:     0,
	}
	err := netlink.RouteAdd(newRoute)
	if err != nil {
		log.Printf(red("Error:")+" adding route: %v", err)
		return false
	}
	return true
}

func delRoute(ip net.IP) {
	newRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       singleHostRoute(ip),
		Table:     0,
	}
	err := netlink.RouteDel(newRoute)
	if err != nil {
		log.Printf(red("Error:")+" deleting route: %v", err)
	}
}
