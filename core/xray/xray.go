package xray

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"encoding/json/v2"

	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/core/xray/app/dispatcher"
	_ "github.com/InazumaV/V2bX/core/xray/distro/all"

	"github.com/deadloop/node-audit/adapters/v2bx/audit"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

var _ vCore.Core = (*Xray)(nil)

func init() {
	vCore.RegisterCore("xray", New)
}

// Xray Structure
type Xray struct {
	access                    sync.Mutex
	Server                    *core.Instance
	ihm                       inbound.Manager
	ohm                       outbound.Manager
	dispatcher                *dispatcher.DefaultDispatcher
	users                     *UserMap
	nodeReportMinTrafficBytes map[string]int64
	// audit is nil unless the core config enables it. Its lifecycle is tied to
	// this Xray instance, so multiple cores never share an emitter.
	audit *audit.Emitter
	// auditCfg keeps the validated config for the user resolver below.
	auditCfg *conf.AuditConfig
	// auditUsers is the immutable label->id snapshot the request path reads.
	// Rebuilding publishes a new map and swaps the pointer, so hot-path readers
	// never take a lock that AddUsers/DelUsers can hold.
	auditUsers atomic.Pointer[map[string]int64]
	// auditSnapshotMu serialises snapshot publication only; it is never touched
	// by the request path.
	auditSnapshotMu sync.Mutex
	// auditGen orders snapshot publications. Every mutation of the user map
	// takes a new generation, and only a snapshot at least as new as the last
	// published one may be stored, so two concurrent publishes cannot leave an
	// older identity table in place.
	auditGen     uint64
	publishedGen uint64
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	x := &Xray{
		Server: getCore(c.XrayConfig),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		nodeReportMinTrafficBytes: make(map[string]int64),
	}
	// Audit is wired here but started in Start(), after the dispatcher exists.
	// A configuration or socket error is reported to the operator and audit is
	// left disabled: it must never prevent the proxy from starting.
	if ac := c.XrayConfig.AuditConfig; ac != nil && ac.Enabled {
		cfg := audit.Config{
			Enabled:              ac.Enabled,
			SourceID:             ac.SourceID,
			NodeIDs:              ac.NodeIDs,
			InboundNodeIDs:       ac.InboundNodeIDs,
			SocketPath:           ac.SocketPath,
			CaptureMode:          ac.CaptureMode,
			EmitAllowUserIDs:     ac.EmitAllowUserIDs,
			QueueMaxEvents:       ac.QueueMaxEvents,
			QueueMaxBytes:        ac.QueueMaxBytes,
			MaxFrameBytes:        ac.MaxFrameBytes,
			SocketWriteTimeoutMS: ac.SocketWriteTimeoutMS,
			CollectClientIP:      ac.CollectClientIP,
			CollectPayload:       ac.CollectPayload,
		}
		if err := cfg.Validate(); err != nil {
			log.WithField("err", err).Error("audit config rejected; audit stays disabled")
		} else {
			x.auditCfg = ac
			x.audit = audit.New(cfg, x.resolveAuditUser)
		}
	}
	return x, nil
}

// resolveAuditUser maps the internal Xray user label to the numeric panel user
// id. The label never leaves the process. An unknown or removed user resolves to
// false, which the emitter turns into an unattributed event rather than a guess.
//
// This runs on the request goroutine, so it must never block. It reads a
// published snapshot with one atomic load instead of locking the user map.
func (x *Xray) resolveAuditUser(email string) (int64, bool) {
	snap := x.auditUsers.Load()
	if snap == nil {
		return 0, false
	}
	id, ok := (*snap)[email]
	if !ok || id <= 0 {
		return 0, false
	}
	return id, true
}

// snapshotLocked copies the identity map. The caller must hold users.mapLock.
// Only positive ids are published: an id of 0 is not a user.
func (x *Xray) snapshotLocked() map[string]int64 {
	snap := make(map[string]int64, len(x.users.uidMap))
	for label, id := range x.users.uidMap {
		if id > 0 {
			snap[label] = int64(id)
		}
	}
	return snap
}

// nextAuditGen must be called while users.mapLock is held, so generations are
// assigned in the same order as the mutations they describe.
func (x *Xray) nextAuditGen() uint64 {
	x.auditGen++
	return x.auditGen
}

// publishAuditSnapshot stores a snapshot that was copied under the user-map
// lock. Publication is ordered by generation: a snapshot older than the one
// already published is discarded, so concurrent AddUsers/DelUsers cannot leave
// a stale identity table behind.
//
// This must NOT be called while users.mapLock is held (that is why the copy is
// taken separately), and it never blocks a request.
func (x *Xray) publishAuditSnapshot(snap map[string]int64, gen uint64) {
	if x.audit == nil {
		return
	}
	x.auditSnapshotMu.Lock()
	defer x.auditSnapshotMu.Unlock()
	if gen < x.publishedGen {
		return
	}
	x.publishedGen = gen
	x.auditUsers.Store(&snap)
}

func parseConnectionConfig(c *conf.XrayConnectionConfig) (policy *coreConf.Policy) {
	policy = &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &c.Handshake,
		ConnectionIdle:    &c.ConnIdle,
		UplinkOnly:        &c.UplinkOnly,
		DownlinkOnly:      &c.DownlinkOnly,
		BufferSize:        &c.BufferSize,
	}
	return
}

func getCore(c *conf.XrayConfig) *core.Instance {
	os.Setenv("XRAY_LOCATION_ASSET", c.AssetPath)
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.AccessPath,
		ErrorLog:  c.LogConfig.ErrorPath,
	}
	// DNS config
	coreDnsConfig := &coreConf.DNSConfig{}
	os.Setenv("XRAY_DNS_PATH", "")
	if c.DnsConfigPath != "" {
		data, err := os.ReadFile(c.DnsConfigPath)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to read xray dns config file: %v", err))
			coreDnsConfig = &coreConf.DNSConfig{}
		} else {
			if err := json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Error(fmt.Sprintf("Failed to unmarshal xray dns config: %v. Using default DNS options.", err))
				coreDnsConfig = &coreConf.DNSConfig{}
			}
		}
		os.Setenv("XRAY_DNS_PATH", c.DnsConfigPath)
	}
	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.WithField("err", err).Panic("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help")
	}
	// Routing config
	coreRouterConfig := &coreConf.RouterConfig{}
	if c.RouteConfigPath != "" {
		data, err := os.ReadFile(c.RouteConfigPath)
		if err != nil {
			log.WithField("err", err).Panic("Failed to read Routing config file")
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.WithField("err", err).Panic("Failed to unmarshal Routing config")
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.WithField("err", err).Panic("Failed to understand Routing config. Please check: https://xtls.github.io/config/routing.html for help")
	}
	// Custom Inbound config
	var coreCustomInboundConfig []coreConf.InboundDetourConfig
	if c.InboundConfigPath != "" {
		data, err := os.ReadFile(c.InboundConfigPath)
		if err != nil {
			log.WithField("err", err).Panic("Failed to read Custom Inbound config file")
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.WithField("err", err).Panic("Failed to unmarshal Custom Inbound config")
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.WithField("err", err).Panic("Failed to understand Inbound config. Please check: https://xtls.github.io/config/inbound.html for help")
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []coreConf.OutboundDetourConfig
	if c.OutboundConfigPath != "" {
		data, err := os.ReadFile(c.OutboundConfigPath)
		if err != nil {
			log.WithField("err", err).Panic("Failed to read Custom Outbound config file")
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.WithField("err", err).Panic("Failed to unmarshal Custom Outbound config")
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.WithField("err", err).Panic("Failed to understand Outbound config, Please check: https://xtls.github.io/config/outbound.html for help")
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(c.ConnectionConfig)
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.WithField("err", err).Panic("failed to create instance")
	}
	log.Info("Xray Core Version: ", core.Version())
	return server
}

// Start the Xray
func (c *Xray) Start() error {
	c.access.Lock()
	defer c.access.Unlock()
	if err := c.Server.Start(); err != nil {
		return err
	}
	c.ihm = c.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	c.ohm = c.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	c.dispatcher = c.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)

	// Attach the observation point and start the sender only after the core is
	// running, so a socket failure cannot abort core start-up.
	if c.audit != nil && c.dispatcher != nil {
		c.dispatcher.SetAuditEmitter(c.audit)
		if err := c.audit.Start(); err != nil {
			log.WithField("err", err).Error("audit emitter failed to start; forwarding is unaffected")
		}
	}
	return nil
}

// Close  the core
func (c *Xray) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.dispatcher != nil {
		c.dispatcher.SetAuditEmitter(nil)
	}
	if c.audit != nil {
		_ = c.audit.Close()
	}
	c.ihm = nil
	c.ohm = nil
	c.dispatcher = nil
	err := c.Server.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *Xray) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
	}
}

func (c *Xray) Type() string {
	return "xray"
}
