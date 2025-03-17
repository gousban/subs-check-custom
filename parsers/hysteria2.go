package parsers

import (
	"log"
	"net/url"
	"strconv"
	"strings"

	"subs-check-custom/types" // Updated import
)

// ParseHysteria2 parses a Hysteria2 proxy URL
func ParseHysteria2(line string, i int, simpleLogger *log.Logger, stats *types.ProxyStats) *types.Proxy {
	hysteriaPart := strings.TrimPrefix(line, "hysteria2://")
	parts := strings.SplitN(hysteriaPart, "@", 2)
	if len(parts) != 2 {
		log.Printf("Invalid Hysteria2 format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid Hysteria2 format", i)
		stats.Hysteria2Fail++
		stats.TotalFail++
		return nil
	}
	password := parts[0]
	serverPortPart := parts[1]
	serverPortQuery := strings.SplitN(serverPortPart, "?", 2)
	serverPort := strings.SplitN(serverPortQuery[0], ":", 2)
	if len(serverPort) != 2 {
		log.Printf("Invalid server:port format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid server:port format", i)
		stats.Hysteria2Fail++
		stats.TotalFail++
		return nil
	}
	server := serverPort[0]
	port, err := strconv.Atoi(serverPort[1])
	if err != nil {
		log.Printf("Invalid port for line %d (%s): %v", i, line, err)
		simpleLogger.Printf("Line %d: Fail - Invalid port: %v", i, err)
		stats.Hysteria2Fail++
		stats.TotalFail++
		return nil
	}
	hashIndex := strings.Index(serverPortPart, "#")
	var name string
	if hashIndex > -1 {
		name = strings.TrimSpace(serverPortPart[hashIndex+1:])
	} else {
		name = "Hysteria2_Proxy_0" // Will be overridden later if needed
	}
	sni := ""
	skipCert := false
	obfs := ""
	obfsPassword := ""
	if len(serverPortQuery) > 1 {
		query := serverPortQuery[1]
		queryParams := strings.Split(query, "&")
		for _, param := range queryParams {
			if strings.HasPrefix(param, "sni=") {
				sni = strings.TrimPrefix(param, "sni=")
			}
			if strings.HasPrefix(param, "insecure=") {
				insecure := strings.TrimPrefix(param, "insecure=")
				skipCert = (insecure == "1")
			}
			if strings.HasPrefix(param, "obfs=") {
				obfs = strings.TrimPrefix(param, "obfs=")
			}
			if strings.HasPrefix(param, "obfs-password=") {
				obfsPassword = strings.TrimPrefix(param, "obfs-password=")
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
		Type:           "hysteria2",
		Password:       password,
		SkipCertVerify: skipCert,
		SNI:            sni,
		Obfs:           obfs,
		ObfsPassword:   obfsPassword,
		Network:        "udp",
	}
	simpleLogger.Printf("Line %d: Success - Hysteria2 proxy parsed", i)
	stats.Hysteria2Success++
	stats.TotalSuccess++
	return proxy
}
