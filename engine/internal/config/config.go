package config

// Config holds the application configuration.
type Config struct {
	ListenHost               string     `json:"LISTEN_HOST"`
	ListenPort               int        `json:"LISTEN_PORT"`
	LogLevel                 string     `json:"LOG_LEVEL,omitempty"`
	ConnectIP                string     `json:"CONNECT_IP"`
	ConnectPort              int        `json:"CONNECT_PORT"`
	FakeSNI                  string     `json:"FAKE_SNI"`
	Listeners                []Listener `json:"LISTENERS,omitempty"`
	BypassMethod             string     `json:"BYPASS_METHOD"`
	FragmentStrategy         string     `json:"FRAGMENT_STRATEGY"`
	FragmentDelay            float64    `json:"FRAGMENT_DELAY"`
	UseTTLTrick              bool       `json:"USE_TTL_TRICK"`
	FakeSNIMethod            string     `json:"FAKE_SNI_METHOD"`
	Endpoints                []Endpoint `json:"ENDPOINTS,omitempty"`
	LoadBalance              string     `json:"LOAD_BALANCE,omitempty"`
	EndpointProbe            bool       `json:"ENDPOINT_PROBE,omitempty"`
	AutoFailover             bool       `json:"AUTO_FAILOVER,omitempty"`
	FailoverRetries          int        `json:"FAILOVER_RETRIES,omitempty"`
	ProbeTimeoutMS           int        `json:"PROBE_TIMEOUT_MS,omitempty"`
	WrongSeqConfirmTimeoutMS int        `json:"WRONG_SEQ_CONFIRM_TIMEOUT_MS,omitempty"`
	Interface                string     `json:"INTERFACE,omitempty"`
	// UTLS selects a real-browser ClientHello fingerprint for the fake hello:
	// firefox|chrome|safari|ios|edge|randomized, or "none"/"" for the legacy
	// hand-built hello.
	UTLS string `json:"UTLS,omitempty"`
}

// Listener represents a single listener configuration in multi-listener mode.
type Listener struct {
	Name         string `json:"NAME,omitempty"`
	ListenHost   string `json:"LISTEN_HOST"`
	ListenPort   int    `json:"LISTEN_PORT"`
	ConnectIP    string `json:"CONNECT_IP"`
	ConnectPort  int    `json:"CONNECT_PORT"`
	FakeSNI      string `json:"FAKE_SNI"`
	BypassMethod string `json:"BYPASS_METHOD,omitempty"`
}

// Endpoint represents a target upstream endpoint.
type Endpoint struct {
	Name    string `json:"NAME,omitempty"`
	IP      string `json:"IP"`
	Port    int    `json:"PORT"`
	SNI     string `json:"SNI"`
	Enabled bool   `json:"ENABLED,omitempty"`
}

// DefaultConfig provides sensible default configuration values.
var DefaultConfig = Config{
	ListenHost:               "0.0.0.0",
	ListenPort:               40443,
	LogLevel:                 "info",
	ConnectIP:                "104.19.229.21",
	ConnectPort:              443,
	FakeSNI:                  "hcaptcha.com",
	BypassMethod:             "wrong_seq",
	UTLS:                     "firefox",
	Interface:                "auto",
	FragmentStrategy:         "sni_split",
	FragmentDelay:            0.05,
	UseTTLTrick:              false,
	FakeSNIMethod:            "raw_inject",
	EndpointProbe:            false,
	AutoFailover:             false,
	FailoverRetries:          0,
	ProbeTimeoutMS:           2500,
	WrongSeqConfirmTimeoutMS: 2000,
}
