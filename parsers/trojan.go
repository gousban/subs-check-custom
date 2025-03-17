package parsers

import (
	"log"
	"net/url"
	"strconv"
	"strings"

	"subs-check-custom/types"
)

// ParseTrojan parses a Trojan proxy URL
func ParseTrojan(line string, i int, simpleLogger *log.Logger, stats *types.ProxyStats) *types.Proxy {
	trojanPart := strings.TrimPrefix(line, "trojan://")
	parts := strings.SplitN(trojanPart, "@", 2)
	if len(parts) != 2 {
		log.Printf("Invalid Trojan format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid Trojan format", i)
		stats.TrojanFail++
		stats.TotalFail++
		return nil
	}
	password := parts[0]
	serverPortPart := parts[1]
	serverPort := strings.SplitN(serverPortPart, ":", 2)
	if len(serverPort) != 2 {
		log.Printf("Invalid server:port format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid server:port format", i)
		stats.TrojanFail++
		stats.TotalFail++
		return nil
	}
	server := serverPort[0]
	portQuery := strings.SplitN(serverPort[1], "?", 2)
	portStr := portQuery[0]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Invalid port for line %d (%s): %v", i, line, err)
		simpleLogger.Printf("Line %d: Fail - Invalid port: %v", i, err)
		stats.TrojanFail++
		stats.TotalFail++
		return nil
	}
	hashIndex := strings.Index(serverPortPart, "#")
	var name string
	if hashIndex > -1 {
		name = strings.TrimSpace(serverPortPart[hashIndex+1:])
	} else {
		name = "Trojan_Proxy_0" // Will be overridden later if needed
	}
	sni := ""
	skipCert := false
	if len(portQuery) > 1 {
		query := portQuery[1]
		queryParams := strings.Split(query, "&")
		for _, param := range queryParams {
			if strings.HasPrefix(param, "sni=") {
				sni = strings.TrimPrefix(param, "sni=")
			}
			if strings.HasPrefix(param, "allowInsecure=") {
				allowInsecure := strings.TrimPrefix(param, "allowInsecure=")
				skipCert = (allowInsecure == "1")
			}
		}
	}

	if strings.Contains(name, "%") {
		decodedName, err := url.QueryUnescape(name)
		if err == nil {
			name = decodedName
		}
	}
	name = strings.Split(name, " |")[0]

	proxy := &types.Proxy{
		Name:           name,
		Server:         server,
		Port:           port,
		Type:           "trojan",
		Cipher:         "",
		Password:       password,
		SkipCertVerify: skipCert,
		SNI:            sni,
		Network:        "tcp",
	}
	simpleLogger.Printf("Line %d: Success - Trojan proxy parsed", i)
	stats.TrojanSuccess++
	stats.TotalSuccess++
	return proxy
}
