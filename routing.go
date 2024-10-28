package main

import (
	"fmt"
	"log"
	"net"

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
	// log.Println(green("Routing setup completed"))
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

func addRoute(ip net.IP) {
	ip.DefaultMask()
	newRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       singleHostRoute(ip),
		Table:     0,
	}
	err := netlink.RouteAdd(newRoute)
	if err != nil {
		log.Printf(red("Error:")+" adding route: %v", err)
	}
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
