package parsers

import (
	"log"
	"net/url"
	"strconv"
	"strings"

	"subs-check-custom/types"
)

// ParseVLess parses a VLess proxy URL
func ParseVLess(line string, i int, simpleLogger *log.Logger, stats *types.ProxyStats) *types.Proxy {
	vlessPart := strings.TrimPrefix(line, "vless://")
	parts := strings.SplitN(vlessPart, "@", 2)
	if len(parts) != 2 {
		log.Printf("Invalid VLess format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid VLess format", i)
		stats.VLessFail++
		stats.TotalFail++
		return nil
	}
	uuid := parts[0]
	serverPortPart := parts[1]
	serverPortQuery := strings.SplitN(serverPortPart, "?", 2)
	serverPort := strings.SplitN(serverPortQuery[0], ":", 2)
	if len(serverPort) != 2 {
		log.Printf("Invalid server:port format for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid server:port format", i)
		stats.VLessFail++
		stats.TotalFail++
		return nil
	}
	server := serverPort[0]
	port, err := strconv.Atoi(serverPort[1])
	if err != nil {
		log.Printf("Invalid port for line %d (%s): %v", i, line, err)
		simpleLogger.Printf("Line %d: Fail - Invalid port: %v", i, err)
		stats.VLessFail++
		stats.TotalFail++
		return nil
	}
	hashIndex := strings.Index(serverPortPart, "#")
	var name string
	if hashIndex > -1 {
		name = strings.TrimSpace(serverPortPart[hashIndex+1:])
	} else {
		name = "VLess_Proxy_0" // Will be overridden later if needed
	}
	sni := ""
	skipCert := false
	network := "tcp"
	wsOpts := make(map[string]string)
	tls := false
	if len(serverPortQuery) > 1 {
		query := serverPortQuery[1]
		queryParams := strings.Split(query, "&")
		for _, param := range queryParams {
			if strings.HasPrefix(param, "sni=") {
				sni = strings.TrimPrefix(param, "sni=")
			}
			if strings.HasPrefix(param, "allowInsecure=") {
				allowInsecure := strings.TrimPrefix(param, "allowInsecure=")
				skipCert = (allowInsecure == "1")
			}
			if strings.HasPrefix(param, "type=") {
				network = strings.TrimPrefix(param, "type=")
			}
			if strings.HasPrefix(param, "host=") {
				wsOpts["host"] = strings.TrimPrefix(param, "host=")
			}
			if strings.HasPrefix(param, "path=") {
				wsOpts["path"] = strings.TrimPrefix(param, "path=")
			}
			if strings.HasPrefix(param, "security=") {
				security := strings.TrimPrefix(param, "security=")
				if security == "tls" {
					tls = true
				}
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
		Type:           "vless",
		UUID:           uuid,
		Network:        network,
		WSOpts:         wsOpts,
		SkipCertVerify: skipCert,
		TLS:            tls,
		SNI:            sni,
	}
	simpleLogger.Printf("Line %d: Success - VLess proxy parsed", i)
	stats.VLessSuccess++
	stats.TotalSuccess++
	return proxy
}
