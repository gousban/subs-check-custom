package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"subs-check-custom/types"
)

func saveResults(cfg types.Config, nodes []types.Proxy) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Speed == nodes[j].Speed {
			return nodes[i].Name < nodes[j].Name
		}
		return nodes[i].Speed > nodes[j].Speed
	})

	seen := make(map[string]bool)
	uniqueNodes := []types.Proxy{}
	nameCount := make(map[string]int)

	for _, node := range nodes {
		if node.Server == "" && node.Type != "No usable nodes" {
			continue
		}

		key := fmt.Sprintf("%s:%d", node.Server, node.Port)
		if seen[key] && node.Type != "No usable nodes" {
			continue
		}
		seen[key] = true

		originalName := node.Name
		parts := strings.Split(originalName, "|")
		if len(parts) < 1 {
			continue
		}
		namePart := strings.TrimSpace(parts[0])
		speedMBs := node.Speed / 1024
		speedPart := fmt.Sprintf("⬇️ %.1fMB/s", speedMBs)

		flagCountry := namePart
		flagCountry = strings.ReplaceAll(flagCountry, "CloudFlare节点", "")
		flagCountry = strings.ReplaceAll(flagCountry, "特殊", "")
		flagCountry = strings.TrimSpace(flagCountry)

		counter := ""
		nameWords := strings.Split(flagCountry, " ")
		if len(nameWords) > 1 {
			lastWord := nameWords[len(nameWords)-1]
			if (strings.HasPrefix(lastWord, "(") && strings.HasSuffix(lastWord, ")")) || strings.HasPrefix(lastWord, "0") {
				counter = lastWord
				flagCountry = strings.Join(nameWords[:len(nameWords)-1], " ")
			}
		}

		newName := flagCountry
		if counter != "" {
			newName += " " + counter
		}
		if node.Speed > 0 {
			newName += " | " + speedPart
		}

		nameCount[newName]++
		if nameCount[newName] > 1 {
			newCounter := fmt.Sprintf("(%d)", nameCount[newName]-1)
			newName = flagCountry + " " + newCounter
			if node.Speed > 0 {
				newName += " | " + speedPart
			}
		}

		proxy := node
		proxy.Name = newName
		proxy.Speed = 0
		uniqueNodes = append(uniqueNodes, proxy)
	}

	err := saveUniqueNodesToTxt(uniqueNodes, cfg.UniqueNodesFile)
	if err != nil {
		log.Printf("Failed to save unique nodes to %s: %v", cfg.UniqueNodesFile, err)
	} else {
		log.Printf("Saved unique nodes to %s", cfg.UniqueNodesFile)
	}

	data := map[string][]types.Proxy{"proxies": uniqueNodes}
	if len(uniqueNodes) == 0 {
		data["proxies"] = []types.Proxy{{Name: "No usable nodes | ⬇️ 0.0MB/s"}}
	}

	file, err := yaml.Marshal(data)
	if err != nil {
		log.Printf("Marshal failed: %v", err)
		return
	}
	savePath := cfg.AllOutputFile
	if err := os.WriteFile(savePath, file, 0644); err != nil {
		log.Printf("Local save failed: %v", err)
	} else {
		log.Printf("Saved locally to %s", savePath)
	}

	logMessage := fmt.Sprintf("Number of remaining nodes after removing duplicates: %d\n", len(uniqueNodes))
	f, err := os.OpenFile("parsingLog.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Failed to open parsingLog.txt for appending: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(logMessage); err != nil {
		log.Printf("Failed to write to parsingLog.txt: %v", err)
	} else {
		log.Printf("Logged remaining nodes to parsingLog.txt")
	}

	if cfg.SaveMethod == "gist" && cfg.GistToken != "" && cfg.GistID != "" {
		// Gist saving logic can be implemented here
	}
}

func saveUniqueNodesToTxt(nodes []types.Proxy, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, node := range nodes {
		var uri string
		switch node.Type {
		case "vmess":
			vmessConfig := types.VMessConfig{
				V:    "2",
				Ps:   node.Name,
				Add:  node.Server,
				Port: node.Port,
				ID:   node.UUID,
				Aid:  node.AlterID,
				Scy:  node.Cipher,
				Net:  node.Network,
				Type: "none",
				Tls:  map[bool]string{true: "tls", false: ""}[node.TLS],
				Sni:  node.SNI,
			}
			if node.Network == "ws" && len(node.WSOpts) > 0 {
				if path, ok := node.WSOpts["path"]; ok {
					vmessConfig.Path = path
				}
				if host, ok := node.WSOpts["host"]; ok {
					vmessConfig.Host = host
				}
			}
			jsonData, err := json.Marshal(vmessConfig)
			if err != nil {
				log.Printf("Failed to marshal VMess config for %s: %v", node.Name, err)
				continue
			}
			encoded := base64.StdEncoding.EncodeToString(jsonData)
			uri = "vmess://" + encoded

		case "ss":
			auth := base64.StdEncoding.EncodeToString([]byte(node.Cipher + ":" + node.Password))
			uri = fmt.Sprintf("ss://%s@%s:%d#%s", auth, node.Server, node.Port, url.QueryEscape(node.Name))

		case "trojan":
			query := url.Values{}
			if node.SNI != "" {
				query.Set("sni", node.SNI)
			}
			if node.SkipCertVerify {
				query.Set("allowInsecure", "1")
			}
			queryStr := ""
			if len(query) > 0 {
				queryStr = "?" + query.Encode()
			}
			uri = fmt.Sprintf("trojan://%s@%s:%d%s#%s", node.Password, node.Server, node.Port, queryStr, url.QueryEscape(node.Name))

		case "hysteria2":
			query := url.Values{}
			if node.SNI != "" {
				query.Set("sni", node.SNI)
			}
			if node.SkipCertVerify {
				query.Set("insecure", "1")
			}
			if node.Obfs != "" {
				query.Set("obfs", node.Obfs)
			}
			if node.ObfsPassword != "" {
				query.Set("obfs-password", node.ObfsPassword)
			}
			queryStr := ""
			if len(query) > 0 {
				queryStr = "?" + query.Encode()
			}
			uri = fmt.Sprintf("hysteria2://%s@%s:%d%s#%s", node.Password, node.Server, node.Port, queryStr, url.QueryEscape(node.Name))

		case "vless":
			query := url.Values{}
			if node.SNI != "" {
				query.Set("sni", node.SNI)
			}
			if node.SkipCertVerify {
				query.Set("allowInsecure", "1")
			}
			if node.Network != "" {
				query.Set("type", node.Network)
			}
			if node.TLS {
				query.Set("security", "tls")
			}
			if node.Network == "ws" && len(node.WSOpts) > 0 {
				if path, ok := node.WSOpts["path"]; ok {
					query.Set("path", path)
				}
				if host, ok := node.WSOpts["host"]; ok {
					query.Set("host", host)
				}
			}
			queryStr := ""
			if len(query) > 0 {
				queryStr = "?" + query.Encode()
			}
			uri = fmt.Sprintf("vless://%s@%s:%d%s#%s", node.UUID, node.Server, node.Port, queryStr, url.QueryEscape(node.Name))

		default:
			continue
		}

		if uri != "" {
			_, err = writer.WriteString(uri + "\r\n")
			if err != nil {
				return err
			}
		}
	}
	return writer.Flush()
}