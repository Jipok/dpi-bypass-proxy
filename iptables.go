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

func setupIPTables() error {
	iptablesAvailable := checkCommand("iptables")
	nftablesAvailable := checkCommand("nft")

	iptablesActive := checkRules("iptables -L") || fileExists("/proc/net/ip_tables_names")
	nftablesActive := checkRules("nft list ruleset") || fileExists("/proc/net/nf_tables")

	if iptablesAvailable && iptablesActive {
		fmt.Println("Detected iptables")
	} else if nftablesAvailable && nftablesActive {
		fmt.Println("Detected nftables")
		useNFT = true
	} else if iptablesAvailable {
		fmt.Println("Warning! Detected iptables, but may not be active")
	} else if nftablesAvailable {
		fmt.Println("Warning! Detected nftables, but may not be active")
	} else {
		log.Fatal("Neither iptables nor nftables were found.")
	}

	if useNFT {
		fmt.Println("You must configure the routing yourself. For router, do:")
		fmt.Printf(`  nft add table ip nat\n`)
		fmt.Printf(`  nft add chain ip nat prerouting '{ type nat hook prerouting priority -100; }'\n`)
		fmt.Printf(`  nft add rule ip nat prerouting tcp dport 443 redirect to %s\n`, *mainPort)
		// fmt.Printf(`  nft add rule ip nat output tcp dport 443 meta skuid != %d redirect to :%s\n`, UID, *mainPort)
		fmt.Println("Don't forget to delete the rules after closing the program.")
		return nil
	}
	command := fmt.Sprintf(`iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Println("M.b. run with -nft ?")
		return fmt.Errorf("%v, output: %s", err, output)
	}

	command = fmt.Sprintf(`iptables -t nat -A OUTPUT -m owner ! --uid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, UID, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err = exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		str := strings.ToLower(string(output))
		if strings.Contains(str, "no") && strings.Contains(str, "chain") && strings.Contains(str, "by that name") {
			fmt.Println("No OUTPUT found in iptables. OK for router")
			NoOUTPUT = true
		} else {
			return fmt.Errorf("iptables: %v, output: %s", err, output)
		}
	}
	log.Println("iptables successfully configured")
	return nil
}

func cleanupIPTables() {
	if useNFT {
		fmt.Println("Don't forget to delete the nftables rules!")
		return
	}
	ok := true
	command := fmt.Sprintf(`iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s`, *mainPort)
	fmt.Printf("Trying run:\n    %s\n", command)
	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		fmt.Printf("Can't delete iptables rule: %v, output: %s", err, output)
		ok = false
	}

	if !NoOUTPUT {
		command := fmt.Sprintf(`iptables -t nat -D OUTPUT -m owner ! --uid-owner %d -p tcp --dport 443 -j REDIRECT --to-port %s`, UID, *mainPort)
		fmt.Printf("Trying run:\n    %s\n", command)
		output, err = exec.Command("sh", "-c", command).CombinedOutput()
		if err != nil {
			fmt.Printf("Can't delete iptables rule: %v, output: %s", err, output)
			ok = false
		}
	}
	if ok {
		log.Println("iptables successfully cleaned")
	}
}
