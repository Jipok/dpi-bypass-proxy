package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/vishvananda/netlink"
)

var (
	link netlink.Link
)

func runCommand(cmd string) {
	fmt.Println("  " + cmd)
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Fatalf(red("%v")+", output: %s \n", err, output)
	}
}

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

	runCommand("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 2034")
	runCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", *interfaceName))
	log.Println(green("Routing setup completed"))
}

func cleanupRouting() {
	runCommand("iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 2034")
	runCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", *interfaceName))

	if !*noClear {
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
	} else {
		if len(proxyIPset.set) > 0 {
			fmt.Printf(yellow("There are %d entries in the routing table, there will be no cleaning.\n"), len(proxyIPset.set))
		}
	}

	log.Println(green("Routing cleanup completed"))
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
		log.Printf(red("Error:")+" adding route: %v", err)
	}
}
