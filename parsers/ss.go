package parsers

import (
	"encoding/base64"
	"log"
	"net/url"
	"strconv"
	"strings"
	"subs-check-custom/types"
)

// SSParseResult holds the parsed result of a Shadowsocks proxy
type SSParseResult struct {
	cipher   string
	password string
	server   string
	port     int
}

// ParseSS parses a Shadowsocks proxy URL
func ParseSS(line string, i int, simpleLogger *log.Logger, stats *types.ProxyStats) *types.Proxy {
	ssPart := strings.TrimPrefix(line, "ss://")
	hashIndex := strings.Index(ssPart, "#")
	var name string
	if hashIndex > -1 {
		name = strings.TrimSpace(ssPart[hashIndex+1:])
		ssPart = ssPart[:hashIndex]
	} else {
		name = "SS_Proxy_0" // Will be overridden later if needed
	}

	log.Printf("Full SS part for line %d: %s (length: %d)", i, ssPart, len(ssPart))

	decoded := tryDecodeSS(ssPart, i, line)
	if decoded == nil {
		log.Printf("Failed to parse SS proxy for line %d (%s), skipping", i, line)
		simpleLogger.Printf("Line %d: Fail - SS parsing failed", i)
		stats.SSFail++
		stats.TotalFail++
		return nil
	}

	cipher := decoded.cipher
	if cipher == "" || !isValidCipher(cipher) {
		log.Printf("Invalid or empty cipher '%s' for line %d (%s), defaulting to aes-256-gcm", cipher, i, line)
		cipher = "aes-256-gcm"
	}

	if strings.Contains(name, "%") {
		decodedName, err := url.QueryUnescape(name)
		if err == nil {
			name = decodedName
		}
	}
	name = strings.Split(name, " |")[0]

	proxy := &types.Proxy{
		Name:     name,
		Server:   decoded.server,
		Port:     decoded.port,
		Type:     "ss",
		Cipher:   cipher,
		Password: decoded.password,
		Network:  "tcp",
	}
	simpleLogger.Printf("Line %d: Success - SS proxy parsed", i)
	stats.SSSuccess++
	stats.TotalSuccess++
	return proxy
}

func addBase64Padding(s string) string {
	remainder := len(s) % 4
	if remainder == 0 {
		return s
	}
	padding := strings.Repeat("=", 4-remainder)
	return s + padding
}

func isValidCipher(cipher string) bool {
	validCiphers := []string{
		"aes-256-gcm", "aes-192-gcm", "aes-128-gcm",
		"chacha20-ietf-poly1305", "chacha20-ietf", "xchacha20-ietf-poly1305",
		"aes-256-cfb", "aes-192-cfb", "aes-128-cfb",
		"aes-256-ctr", "aes-192-ctr", "aes-128-ctr",
		"rc4-md5", "rc4-md5-6",
	}
	for _, valid := range validCiphers {
		if strings.EqualFold(cipher, valid) {
			return true
		}
	}
	return false
}

func tryDecodeSS(ssPart string, lineNum int, originalLine string) *SSParseResult {
	var result SSParseResult

	log.Printf("Attempting to decode SS part for line %d: %s", lineNum, ssPart)
	log.Printf("Raw SS part length for line %d: %d", lineNum, len(ssPart))

	padded := addBase64Padding(ssPart)
	log.Printf("Padded SS part: %s", padded)

	decodedFull, err := base64.StdEncoding.DecodeString(padded)
	if err == nil {
		log.Printf("Success: Full base64 decode for line %d: %s", lineNum, string(decodedFull))
		atIndex := strings.Index(string(decodedFull), "@")
		if atIndex > -1 {
			authPart := string(decodedFull[:atIndex])
			serverPort := string(decodedFull[atIndex+1:])
			log.Printf("Extracted auth part from decoded string for line %d: %s", lineNum, authPart)
			log.Printf("Extracted serverPort from decoded string for line %d: %s", lineNum, serverPort)

			if strings.Contains(authPart, ":") {
				authParts := strings.SplitN(authPart, ":", 2)
				if len(authParts) == 2 {
					result.cipher = authParts[0]
					result.password = authParts[1]
				} else {
					log.Printf("Invalid auth format in decoded string for line %d: %s", lineNum, authPart)
					return nil
				}
			} else {
				log.Printf("No colon in decoded auth for line %d: %s", lineNum, authPart)
				return nil
			}

			serverPortParts := strings.SplitN(serverPort, ":", 2)
			if len(serverPortParts) == 2 {
				result.server = serverPortParts[0]
				port, err := strconv.Atoi(serverPortParts[1])
				if err != nil {
					log.Printf("Invalid port in decoded string for line %d (%s): %v", lineNum, serverPortParts[1], err)
					return nil
				}
				result.port = port
				return &result
			} else {
				log.Printf("Invalid server:port format in decoded string for line %d: %s", lineNum, serverPort)
				return nil
			}
		}
	}

	log.Printf("Full base64 decode failed, trying fallback for line %d: %v", lineNum, err)
	padded = addBase64Padding(ssPart)
	atIndex := strings.Index(padded, "@")
	if atIndex == -1 {
		for i, b := range []byte(padded) {
			if b == 0x40 {
				atIndex = i
				break
			}
		}
	}
	if atIndex > -1 {
		authPart := padded[:atIndex]
		serverPort := padded[atIndex+1:]

		processedAuthPart := addBase64Padding(authPart)
		decodedAuth, err := base64.StdEncoding.DecodeString(processedAuthPart)
		if err != nil {
			log.Printf("Fail: Base64 decode for auth part in line %d (%s): %v", lineNum, originalLine, err)
			return nil
		}
		log.Printf("Decoded auth part for line %d: %s", lineNum, string(decodedAuth))

		decodedStr := string(decodedAuth)
		if strings.Contains(decodedStr, ":") {
			authParts := strings.SplitN(decodedStr, ":", 2)
			if len(authParts) == 2 {
				result.cipher = authParts[0]
				result.password = authParts[1]
			} else {
				log.Printf("Invalid auth format for line %d: %s", lineNum, decodedStr)
				return nil
			}
		} else {
			log.Printf("No colon in decoded auth for line %d: %s", lineNum, decodedStr)
			return nil
		}

		serverPort = strings.ReplaceAll(serverPort, "=", "")
		serverPortParts := strings.SplitN(serverPort, ":", 2)
		if len(serverPortParts) == 2 {
			result.server = serverPortParts[0]
			port, err := strconv.Atoi(serverPortParts[1])
			if err != nil {
				log.Printf("Invalid port for line %d (%s): %v", lineNum, serverPortParts[1], err)
				return nil
			}
			result.port = port
			return &result
		}
	}
	log.Printf("No @ delimiter found for line %d, returning nil", lineNum)
	return nil
}
