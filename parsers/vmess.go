package parsers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"subs-check-custom/types"
)

// ParseVMess parses a VMess proxy URL
func ParseVMess(line string, i int, simpleLogger *log.Logger, stats *types.ProxyStats) *types.Proxy {
	base64Part := strings.TrimPrefix(line, "vmess://")
	decodedConfig, err := base64.StdEncoding.DecodeString(base64Part)
	if err != nil {
		log.Printf("Fail: Base64 decode for line %d (%s): %v", i, line, err)
		simpleLogger.Printf("Line %d: Fail - Base64 decode error: %v", i, err)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}
	var vmess types.VMessConfig
	if err := json.Unmarshal(decodedConfig, &vmess); err != nil {
		log.Printf("Fail: JSON unmarshal for line %d (%s): %v", i, line, err)
		simpleLogger.Printf("Line %d: Fail - JSON unmarshal error: %v", i, err)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}
	var port int
	switch p := vmess.Port.(type) {
	case string:
		port, err = strconv.Atoi(p)
		if err != nil {
			log.Printf("Invalid port for line %d (%s): %v", i, line, err)
			simpleLogger.Printf("Line %d: Fail - Invalid port: %v", i, err)
			stats.VMessFail++
			stats.TotalFail++
			return nil
		}
	case float64:
		port = int(p)
	default:
		log.Printf("Invalid port type for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid port type", i)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}
	if vmess.V != nil {
		switch vmess.V.(type) {
		case string, float64:
		default:
			log.Printf("Warning: Invalid v type for line %d (%s), proceeding anyway", i, line)
		}
	} else {
		log.Printf("Warning: 'v' field missing for line %d (%s), proceeding anyway", i, line)
	}

	switch vmess.Aid.(type) {
	case string, float64:
		_, err := strconv.Atoi(fmt.Sprintf("%v", vmess.Aid))
		if err != nil {
			log.Printf("Warning: Invalid aid value for line %d (%s): %v", i, line, err)
		}
	case nil:
		log.Printf("Warning: 'aid' field missing for line %d (%s), defaulting to 0", i, line)
	default:
		log.Printf("Invalid aid type for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid aid type", i)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}
	switch vmess.Tls.(type) {
	case string, bool:
	case nil:
	default:
		log.Printf("Invalid tls type for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid tls type", i)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}
	switch vmess.Type.(type) {
	case string, nil:
	default:
		log.Printf("Invalid type type for line %d (%s)", i, line)
		simpleLogger.Printf("Line %d: Fail - Invalid type type", i)
		stats.VMessFail++
		stats.TotalFail++
		return nil
	}

	wsOpts := make(map[string]string)
	if vmess.Net == "ws" {
		if headers, ok := vmess.WSOptsHeaders.(map[string]interface{}); ok {
			for k, v := range headers {
				if strVal, ok := v.(string); ok {
					wsOpts[k] = strVal
				}
			}
		}
		if path, ok := vmess.Path.(string); ok {
			wsOpts["path"] = path
		}
	}

	tls := false
	if tlsVal, ok := vmess.Tls.(bool); ok {
		tls = tlsVal
	} else if tlsStr, ok := vmess.Tls.(string); ok && tlsStr == "tls" {
		tls = true
	}

	skipCert := false
	if skipVal, ok := vmess.SkipCert.(bool); ok {
		skipCert = skipVal
	}

	name := vmess.Ps
	if strings.Contains(name, "%") {
		decodedName, err := url.QueryUnescape(name)
		if err == nil {
			name = decodedName
		}
	}
	name = strings.Split(name, " |")[0]

	alterID := 0
	if aid, ok := vmess.Aid.(float64); ok {
		alterID = int(aid)
	} else if aidStr, ok := vmess.Aid.(string); ok {
		if aidInt, err := strconv.Atoi(aidStr); err == nil {
			alterID = aidInt
		}
	}

	cipher := "auto"
	if vmess.Scy != "" {
		cipher = vmess.Scy
	}

	proxy := &types.Proxy{
		Name:           name,
		Server:         vmess.Add,
		Port:           port,
		Type:           "vmess",
		Cipher:         cipher,
		Password:       vmess.ID,
		Network:        vmess.Net,
		WSOpts:         wsOpts,
		SkipCertVerify: skipCert,
		TLS:            tls,
		SNI:            vmess.Sni,
		UUID:           vmess.ID,
		AlterID:        alterID,
	}
	simpleLogger.Printf("Line %d: Success - VMess proxy parsed", i)
	stats.VMessSuccess++
	stats.TotalSuccess++
	return proxy
}
