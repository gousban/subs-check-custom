package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"subs-check-custom/parsers"
	"subs-check-custom/types"
)

func fetchContent(config types.Config, updateProgress func(string)) (string, error) {
	updateProgress("Fetching")
	var allContent strings.Builder
	for _, subURL := range config.SubURLs {
		if subURL == "" {
			continue
		}
		log.Printf("Fetching subscription data from %s", subURL)
		cmd := exec.Command("curl", "-s", subURL)
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Failed to fetch from %s: %v", subURL, err)
			continue
		}
		err = os.WriteFile("original.b64", output, 0644)
		if err != nil {
			log.Printf("Failed to write original.b64 for %s: %v", subURL, err)
			continue
		}

		log.Println("Decoding original.b64 to decodedOriginal.txt using certutil")
		cmd = exec.Command("certutil", "-decode", "-f", "original.b64", "decodedOriginal.txt")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err = cmd.Run()
		if err != nil {
			log.Printf("Failed to decode original.b64 with certutil: %v, stderr: %s", err, stderr.String())
			log.Printf("Directly copy original.b64 to decodedOriginal.txt")
			cmd = exec.Command("cmd", "/c", "copy", "original.b64", "decodedOriginal.txt")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err = cmd.Run()
			if err != nil {
				log.Printf("Cannot copy original.b64 to decodedOriginal.txt")
				continue
			}
		}

		content, err := os.ReadFile("decodedOriginal.txt")
		if err != nil {
			log.Printf("Failed to read decodedOriginal.txt for %s: %v", subURL, err)
			log.Printf("Subscription maybe not in base64 format.")
			allContent.WriteString(string(output) + "\n")
		} else {
			allContent.WriteString(string(content) + "\n")
		}
	}

	if allContent.Len() == 0 {
		log.Printf("No content fetched from any subscription URLs")
		return "", fmt.Errorf("no content fetched")
	}

	return allContent.String(), nil
}

func fetchNodes(subscriptionContent string, simpleLogger *log.Logger, stats *types.ProxyStats) []types.Proxy {
	decodedBody, err := base64.StdEncoding.DecodeString(subscriptionContent)
	if err != nil {
		log.Printf("Initial Base64 decode failed, treating as raw data: %v", err)
		decodedBody = []byte(subscriptionContent)
	}

	var proxies []types.Proxy
	lines := strings.Split(string(decodedBody), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, "\r\n")
		if line == "" {
			continue
		}

		log.Printf("Processing line %d: %s", i, line)

		var proxy *types.Proxy
		switch {
		case strings.HasPrefix(line, "vmess://"):
			proxy = parsers.ParseVMess(line, i, simpleLogger, stats)
		case strings.HasPrefix(line, "ss://"):
			proxy = parsers.ParseSS(line, i, simpleLogger, stats)
		case strings.HasPrefix(line, "trojan://"):
			proxy = parsers.ParseTrojan(line, i, simpleLogger, stats)
		case strings.HasPrefix(line, "hysteria2://"):
			proxy = parsers.ParseHysteria2(line, i, simpleLogger, stats)
		case strings.HasPrefix(line, "vless://"):
			proxy = parsers.ParseVLess(line, i, simpleLogger, stats)
		default:
			simpleLogger.Printf("Line %d: Fail - Unknown proxy type", i)
			stats.TotalFail++
		}

		if proxy != nil {
			if proxy.Name == "SS_Proxy_0" || proxy.Name == "Trojan_Proxy_0" || proxy.Name == "Hysteria2_Proxy_0" || proxy.Name == "VLess_Proxy_0" {
				proxy.Name = fmt.Sprintf("%s_Proxy_%d", proxy.Type, len(proxies))
			}
			proxies = append(proxies, *proxy)
		}
	}

	// Deduplicate nodes based on Server:Port
	if len(proxies) > 0 {
		seen := make(map[string]bool)
		uniqueProxies := []types.Proxy{}
		for _, proxy := range proxies {
			key := fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
			if !seen[key] {
				seen[key] = true
				uniqueProxies = append(uniqueProxies, proxy)
			}
		}
		log.Printf("Parsed %d nodes, reduced to %d unique nodes after deduplication", len(proxies), len(uniqueProxies))
		simpleLogger.Printf("Parsed %d nodes, reduced to %d unique nodes after deduplication", len(proxies), len(uniqueProxies))
		fmt.Printf("Parsed nodes after deduplication: %d\n", len(uniqueProxies)) // Print to screen
		proxies = uniqueProxies
	}

	if len(proxies) == 0 {
		log.Printf("No valid proxies parsed, adding default node")
		proxies = []types.Proxy{{Name: "No usable nodes"}}
		simpleLogger.Printf("No valid proxies parsed - Added default node")
		fmt.Printf("Fetch nodes after deduplication: %d\n", len(proxies)) // Print even if no nodes
	}

	return proxies
}
