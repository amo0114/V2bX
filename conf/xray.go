package conf

type XrayConfig struct {
	LogConfig *XrayLogConfig `json:"Log"`
	// Audit is the optional structured event outlet. Absent or disabled, the
	// process behaves exactly as upstream v0.4.0.
	AuditConfig        *AuditConfig          `json:"Audit,omitempty"`
	AssetPath          string                `json:"AssetPath"`
	DnsConfigPath      string                `json:"DnsConfigPath"`
	RouteConfigPath    string                `json:"RouteConfigPath"`
	ConnectionConfig   *XrayConnectionConfig `json:"XrayConnectionConfig"`
	InboundConfigPath  string                `json:"InboundConfigPath"`
	OutboundConfigPath string                `json:"OutboundConfigPath"`
}

type XrayLogConfig struct {
	Level      string `json:"Level"`
	AccessPath string `json:"AccessPath"`
	ErrorPath  string `json:"ErrorPath"`
}

type XrayConnectionConfig struct {
	Handshake    uint32 `json:"handshake"`
	ConnIdle     uint32 `json:"connIdle"`
	UplinkOnly   uint32 `json:"uplinkOnly"`
	DownlinkOnly uint32 `json:"downlinkOnly"`
	BufferSize   int32  `json:"bufferSize"`
}

// AuditConfig mirrors the `Audit` block of a core configuration.
type AuditConfig struct {
	Enabled              bool             `json:"enabled"`
	SourceID             string           `json:"source_id"`
	NodeIDs              []int64          `json:"node_ids"`
	InboundNodeIDs       map[string]int64 `json:"inbound_node_ids"`
	SocketPath           string           `json:"socket_path"`
	CaptureMode          string           `json:"capture_mode"`
	EmitAllowUserIDs     []int64          `json:"emit_allow_user_ids"`
	QueueMaxEvents       int              `json:"queue_max_events"`
	QueueMaxBytes        int              `json:"queue_max_bytes"`
	MaxFrameBytes        int              `json:"max_frame_bytes"`
	SocketWriteTimeoutMS int              `json:"socket_write_timeout_ms"`
	CollectClientIP      bool             `json:"collect_client_ip"`
	CollectPayload       bool             `json:"collect_payload"`
}

func NewXrayConfig() *XrayConfig {
	return &XrayConfig{
		AuditConfig: NewAuditConfig(),
		LogConfig: &XrayLogConfig{
			Level:      "warning",
			AccessPath: "",
			ErrorPath:  "",
		},
		AssetPath:          "/etc/V2bX/",
		DnsConfigPath:      "",
		InboundConfigPath:  "",
		OutboundConfigPath: "",
		RouteConfigPath:    "",
		ConnectionConfig: &XrayConnectionConfig{
			Handshake:    4,
			ConnIdle:     30,
			UplinkOnly:   2,
			DownlinkOnly: 4,
			BufferSize:   64,
		},
	}
}

// NewAuditConfig returns the disabled default matching the documented fragment.
func NewAuditConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:              false,
		CaptureMode:          "allowlist",
		QueueMaxEvents:       1024,
		QueueMaxBytes:        2 << 20,
		MaxFrameBytes:        4096,
		SocketWriteTimeoutMS: 50,
		CollectClientIP:      false,
		CollectPayload:       false,
	}
}

type XrayOptions struct {
	EnableProxyProtocol bool                    `json:"EnableProxyProtocol"`
	EnableDNS           bool                    `json:"EnableDNS"`
	DNSType             string                  `json:"DNSType"`
	EnableUot           bool                    `json:"EnableUot"`
	EnableTFO           bool                    `json:"EnableTFO"`
	DisableIVCheck      bool                    `json:"DisableIVCheck"`
	DisableSniffing     bool                    `json:"DisableSniffing"`
	EnableFallback      bool                    `json:"EnableFallback"`
	FallBackConfigs     []FallBackConfigForXray `json:"FallBackConfigs"`
}

type FallBackConfigForXray struct {
	SNI              string `json:"SNI"`
	Alpn             string `json:"Alpn"`
	Path             string `json:"Path"`
	Dest             string `json:"Dest"`
	ProxyProtocolVer uint64 `json:"ProxyProtocolVer"`
}

func NewXrayOptions() *XrayOptions {
	return &XrayOptions{
		EnableProxyProtocol: false,
		EnableDNS:           false,
		DNSType:             "AsIs",
		EnableUot:           false,
		EnableTFO:           false,
		DisableIVCheck:      false,
		DisableSniffing:     false,
		EnableFallback:      false,
	}
}
