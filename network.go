package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

var (
	NoOUTPUT = false
	useNFT   = false
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

func configureNetwork() {
	// runCommand("nft add table ip mangle")
	// runCommand("nft 'add chain ip mangle prerouting { type filter hook output priority mangle; policy accept; }'")
	// runCommand("nft 'add rule ip mangle prerouting tcp dport 443 ct state new queue num 5123'")
	// // runCommand("nft 'add rule ip mangle prerouting ct state new ct mark set mark'")
	// runCommand("nft 'add rule ip mangle prerouting ct mark != 0 meta mark set ct mark'")
	// runCommand("nft 'add chain ip mangle output { type route hook output priority mangle; policy accept; }'")
	// runCommand("nft 'add rule ip mangle output ct mark != 0 meta mark set ct mark'")

	// runCommand("nft add table ip nat")
	// runCommand("nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'")
	// runCommand("nft 'add rule ip nat postrouting oifname 'wg0' meta mark 350 masquerade'")

	// runCommand("iptables -A FORWARD -t mangle -j CONNMARK --restore-mark")
	// runCommand("iptables -A OUTPUT -t mangle -j CONNMARK --restore-mark")
	// runCommand("iptables -A FORWARD -m mark --mark 0 -p tcp --destination-port 443 -j NFQUEUE --queue-num 5123")
	runCommand("iptables -A OUTPUT -o usb0 -p tcp --dport 443 -j NFQUEUE --queue-num 5123")
	runCommand("iptables -A OUTPUT -m mark --mark 1 -p tcp -j REJECT --reject-with tcp-reset")
	// runCommand("iptables -A POSTROUTING -t mangle -j CONNMARK --save-mark")
	runCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", *interfaceName))

	// runCommand("nft add table ip dpi-bypass")

	// runCommand("nft add chain ip dpi-bypass output0 '{type filter hook output priority -120; }'")
	// runCommand("nft add rule ip dpi-bypass output0 dup to @daddr device 'wg0'")

	// runCommand("nft add chain ip dpi-bypass output '{type filter hook output priority -100; }'")
	// runCommand("nft add rule ip dpi-bypass output tcp dport 443 oifname 'usb0' meta mark != 350 queue num 5123")
	// runCommand("nft add rule ip dpi-bypass output mark set ct mark")

	// runCommand("nft add chain ip dpi-bypass output2 '{type filter hook postrouting priority 0; }'")
	// // runCommand("nft add rule ip dpi-bypass output2 ct mark set meta mark")

	// // runCommand("nft add rule ip dpi-bypass output tcp dport 443 ct state new counter queue num 5123")
	// runCommand("nft add chain ip dpi-bypass postrouting '{ type nat hook postrouting priority 0; }'")
	// runCommand("nft add rule ip dpi-bypass postrouting oifname 'wg0' meta mark 350 masquerade")
	// // runCommand("nft add rule ip dpi-bypass postrouting mark set ct mark")

	// runCommand(fmt.Sprintf("iptables -A OUTPUT -p tcp --dport 443 -m mark ! --mark %d -m mark ! --mark %d -j NFQUEUE --queue-num %d", *markNumber, *markNumber+1, *queueNumber))
	// runCommand(fmt.Sprintf("iptables -A FORWARD -p tcp --dport 443 -m mark ! --mark %d -m mark ! --mark %d -j NFQUEUE --queue-num %d", *markNumber, *markNumber+1, *queueNumber))
	// runCommand(fmt.Sprintf("iptables -t mangle -A POSTROUTING -m mark --mark %d -j CONNMARK --save-mark", *markNumber))
	// runCommand("iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark")
	// runCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", *interfaceName))
	return
	iptablesAvailable := checkCommand("iptables")
	nftablesAvailable := checkCommand("nft")

	iptablesActive := checkRules("iptables -L") || fileExists("/proc/net/ip_tables_names")
	nftablesActive := checkRules("nft list ruleset") || fileExists("/proc/net/nf_tables")

	if nftablesAvailable && nftablesActive {
		fmt.Println(green("Detected nftables"))
		useNFT = true
	} else if iptablesAvailable && iptablesActive {
		fmt.Println(green("Detected iptables"))
	} else if nftablesAvailable {
		fmt.Println(yellow("Warning! Detected nftables, but may not be active"))
		useNFT = true
	} else if iptablesAvailable {
		fmt.Println(yellow("Warning! Detected iptables, but may not be active"))

	} else {
		log.Fatal(red("Neither iptables nor nftables were found."))
	}

	fmt.Printf("Trying run:\n")
	if useNFT {
		rule := ""
		if *interfaceName != "" {
			rule = fmt.Sprintf(`oifname != "%s"`, *interfaceName)
		}
		runCommand("nft add table inet dpi-bypass")
		runCommand("nft add chain inet dpi-bypass prerouting '{ type nat hook prerouting priority -150; }'")
		runCommand(fmt.Sprintf(`nft add rule inet dpi-bypass prerouting %s tcp dport 443 redirect to %s`, rule, 1))
		runCommand("nft add chain inet dpi-bypass output '{ type nat hook output priority -150; }'")
		runCommand(fmt.Sprintf(`nft add rule inet dpi-bypass output %s tcp dport 443 meta skgid != %d redirect to :%s`, rule, 1, 1))
		log.Println(green("nftables successfully configured"))
	} else {
		rule := ""
		if *interfaceName != "" {
			rule = fmt.Sprintf(`! -i %s`, *interfaceName)
		}
		runCommand(fmt.Sprintf(`iptables -t nat -A PREROUTING %s -p tcp --dport 443 -j REDIRECT --to-port %s`, rule, 1))
		command := fmt.Sprintf(`iptables -t nat -A OUTPUT %s -m owner ! --gid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, rule, 1, 1)
		fmt.Println("  " + command)
		output, err := exec.Command("sh", "-c", command).CombinedOutput()
		if err != nil {
			str := strings.ToLower(string(output))
			if strings.Contains(str, "no") && strings.Contains(str, "chain") && strings.Contains(str, "by that name") {
				fmt.Println("No OUTPUT found in iptables. OK for router")
				NoOUTPUT = true
			}
		}
		log.Println(green("iptables successfully configured"))
	}
}

func restoreNetwork() {
	fmt.Printf("Trying run:\n")
	// runCommand("iptables -D FORWARD -t mangle -j CONNMARK --restore-mark")
	// runCommand("iptables -D OUTPUT -t mangle -j CONNMARK --restore-mark")
	runCommand("iptables -D OUTPUT -o usb0 -p tcp --dport 443 -j NFQUEUE --queue-num 5123")
	runCommand("iptables -D OUTPUT -m mark --mark 1 -p tcp -j REJECT --reject-with tcp-reset")
	// runCommand("iptables -D FORWARD -m mark --mark 0 -p tcp --destination-port 443 -j NFQUEUE --queue-num 5123")
	// runCommand("iptables -D POSTROUTING -t mangle -j CONNMARK --save-mark")
	runCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", *interfaceName))

	// runCommand("nft flush ruleset")
	// runCommand("nft flush table ip mangle")
	// runCommand("nft delete table ip mangle")
	// runCommand(fmt.Sprintf("iptables -D OUTPUT -p tcp --dport 443 -m mark ! --mark %d -m mark ! --mark %d -j NFQUEUE --queue-num %d", *markNumber, *markNumber+1, *queueNumber))
	// runCommand(fmt.Sprintf("iptables -D FORWARD -p tcp --dport 443 -m mark ! --mark %d -m mark ! --mark %d -j NFQUEUE --queue-num %d", *markNumber, *markNumber+1, *queueNumber))
	// runCommand(fmt.Sprintf("iptables -t mangle -D POSTROUTING -m mark --mark %d -j CONNMARK --save-mark", *markNumber))
	// runCommand("iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark")
	// runCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", *interfaceName))
	return
	if useNFT {
		runCommand("nft flush table inet dpi-bypass")
		runCommand("nft delete table inet dpi-bypass")
		log.Println(green("nftables successfully cleaned"))
	} else {
		rule := ""
		if *interfaceName != "" {
			rule = fmt.Sprintf(`! -i %s`, *interfaceName)
		}
		runCommand(fmt.Sprintf(`iptables -t nat -D PREROUTING %s -p tcp --dport 443 -j REDIRECT --to-port %s`, rule, 1))
		if !NoOUTPUT {
			runCommand(fmt.Sprintf(`iptables -t nat -D OUTPUT %s -m owner ! --gid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, rule, 1, 1))
		}
		log.Println(green("iptables successfully cleaned"))
	}
}
