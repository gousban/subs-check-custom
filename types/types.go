package types

// Config holds the application configuration
type Config struct {
	SpeedTestURL    string   `yaml:"speed-test-url"`
	Concurrent      int      `yaml:"concurrent"`
	Timeout         int      `yaml:"timeout"`   // in milliseconds
	MinSpeed        int      `yaml:"min-speed"` // in KB/s
	SaveMethod      string   `yaml:"save-method"`
	GistToken       string   `yaml:"github-token"`
	GistID          string   `yaml:"github-gist-id"`
	SubURLs         []string `yaml:"sub-urls"`
	ProxyAddr       string   `yaml:"proxyAddr"`       // New field for SOCKS5 proxy address
	ApiAddr         string   `yaml:"api-addr"`        // New field for API address
	AllOutputFile   string   `yaml:"allOutputFile"`   // New field for all.yaml
	UniqueNodesFile string   `yaml:"uniqueNodesFile"` // New field for uniqueNodes.txt
	TCPTestURL      string   `yaml:"tcp-test-url"`
	TCPTestMaxSpeed int      `yaml:"tcp-test-max-speed"`
}

// Proxy represents a parsed proxy configuration
type Proxy struct {
	Name           string            `yaml:"name"`
	Server         string            `yaml:"server"`
	Host           string            `yaml:"host"`
	Port           int               `yaml:"port"`
	Type           string            `yaml:"type"`
	Cipher         string            `yaml:"cipher,omitempty"`
	Password       string            `yaml:"password,omitempty"`
	Network        string            `yaml:"network,omitempty"`
	WSOpts         map[string]string `yaml:"ws-opts,omitempty"`
	SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty"`
	TLS            bool              `yaml:"tls,omitempty"`
	SNI            string            `yaml:"sni,omitempty"`
	Path           string            `yaml:"path,omitempty"`
	UUID           string            `yaml:"uuid,omitempty"`
	AlterID        int               `yaml:"alterId"`
	Obfs           string            `yaml:"obfs,omitempty"`
	ObfsPassword   string            `yaml:"obfs-password,omitempty"`
	Speed          float64
	Latency        int64 // New field to store TCP test latency
}

// VMessConfig represents the JSON structure of a VMess proxy
type VMessConfig struct {
	V             interface{} `json:"v"`
	Ps            string      `json:"ps"`
	Add           string      `json:"add"`
	Port          interface{} `json:"port"`
	ID            string      `json:"id"`
	Aid           interface{} `json:"aid"`
	Scy           string      `json:"scy"`
	Net           string      `json:"net"`
	Type          interface{} `json:"type"`
	Host          string      `json:"host"`
	Path          interface{} `json:"path"`
	Tls           interface{} `json:"tls"`
	Sni           string      `json:"sni"`
	SkipCert      interface{} `json:"skip-cert-verify"`
	WSOptsHeaders interface{} `json:"ws-opts"`
}

// ProxyStats tracks success and failure counts
type ProxyStats struct {
	TotalSuccess     int
	TotalFail        int
	SSSuccess        int
	SSFail           int
	VMessSuccess     int
	VMessFail        int
	TrojanSuccess    int
	TrojanFail       int
	Hysteria2Success int
	Hysteria2Fail    int
	VLessSuccess     int
	VLessFail        int
}
