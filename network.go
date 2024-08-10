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
		runCommand("nft add table inet dpi-bypass")
		runCommand("nft add chain inet dpi-bypass prerouting '{ type nat hook prerouting priority -100; }'")
		runCommand(fmt.Sprintf(`nft add rule inet dpi-bypass prerouting tcp dport 443 redirect to %s`, *mainPort))
		runCommand("nft add chain inet dpi-bypass output '{ type nat hook output priority -100; }'")
		runCommand(fmt.Sprintf(`nft add rule inet dpi-bypass output tcp dport 443 meta skgid != %d redirect to :%s`, GID, *mainPort))
		log.Println(green("nftables successfully configured"))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort))
		command := fmt.Sprintf(`iptables -t nat -A OUTPUT -m owner ! --gid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, GID, *mainPort)
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
	if useNFT {
		runCommand("nft flush table inet dpi-bypass")
		runCommand("nft delete table inet dpi-bypass")
		log.Println(green("nftables successfully cleaned"))
	} else {
		runCommand(fmt.Sprintf(`iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort))
		if !NoOUTPUT {
			runCommand(fmt.Sprintf(`iptables -t nat -D OUTPUT -m owner ! --gid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, GID, *mainPort))
		}
		log.Println(green("iptables successfully cleaned"))
	}
}
