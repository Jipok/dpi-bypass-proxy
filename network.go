package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
)

var (
	NoOUTPUT = false
	useNFT   = false
	link     netlink.Link
)

func checkCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func checkRules(cmd string) bool {
	output, err := exec.Command("sh", "-c", cmd).Output()
	return err == nil && len(output) > 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

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

	if *router {
		runCommand(fmt.Sprintf(`iptables -t nat -A PREROUTING ! -i lo -p udp --dport 53 -j REDIRECT --to-port %s`, *dnsPort))
		runCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", *interfaceName))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -A OUTPUT -m owner ! --gid-owner %d -p udp --dport 53 -j REDIRECT --to-port %s`, GID, *dnsPort))
	}

	log.Println(green("Routing setup completed"))
}

func cleanupRouting() {
	if *router {
		runCommand(fmt.Sprintf(`iptables -t nat -D PREROUTING ! -i lo -p udp --dport 53 -j REDIRECT --to-port %s`, *dnsPort))
		runCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", *interfaceName))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -D OUTPUT -m owner ! --gid-owner %d -p udp --dport 53 -j REDIRECT --to-port %s`, GID, *dnsPort))
	}

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
}

func addRoute(ip net.IP) {
	newRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
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
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Table:     0,
	}
	err := netlink.RouteDel(newRoute)
	if err != nil {
		log.Printf(red("Error:")+" adding route: %v", err)
	}
}
