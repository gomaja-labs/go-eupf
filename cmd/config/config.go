// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/rs/zerolog/log"

	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	commonConfigPathName = "./config.yml"
	pccConfigPathName    = "./pcc.yaml"
	validate             *validator.Validate
	commonConfigV        = viper.New()
	configMu             sync.Mutex
	// RFC 9110 section 11.2: token68 excludes whitespace and control bytes.
	apiTokenRegex  = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
	pccConfigV     = viper.New()
	SDFFilterRegex = regexp.MustCompile(`^permit (out|in) (icmp|ip|tcp|udp|\d+) from (assigned|any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?: (\d+|\d+-\d+))? to (assigned|any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?: (\d+|\d+-\d+))?$`)
)

type PCCRulesConfig struct {
	PccRules []PccRule `mapstructure:"pcc_rules" json:"pcc_rules" validate:"dive"`
}

// PccRule describes the structure of the pcc rule representation
type PccRule struct {
	PccName   string `mapstructure:"pcc_name" validate:"required"`
	Notify    bool   `mapstructure:"notify"`
	SdfFilter string `mapstructure:"sdf_filter" validate:"required,sdfFilter"`
	Far       Far    `mapstructure:"far"`
	Qer       Qer    `mapstructure:"qer"`
	Urr       Urr    `mapstructure:"urr"`
}

type Urr struct {
	Urrid uint32 `mapstructure:"urrid" default:"0"`
}

// Far Forwarding Action Rule in the pcc config view
type Far struct {
	Action                uint8  `mapstructure:"action"`
	OuterHeaderCreation   uint8  `mapstructure:"outer_header_creation"`
	Teid                  uint32 `mapstructure:"teid"`
	RemoteIP              uint32 `mapstructure:"remote_ip"`
	TransportLevelMarking uint16 `mapstructure:"transport_level_marking"`
}

// Qer QoS Enforcement Rule in the pcc config view
type Qer struct {
	Qfi          uint8  `mapstructure:"qfi" validate:"min=1,max=255"`
	MaxBitrateUl uint32 `mapstructure:"max_bitrate_ul"`
	MaxBitrateDl uint32 `mapstructure:"max_bitrate_dl"`
}

type UpfConfig struct {
	PfcpPeerAllowList         []string `mapstructure:"pfcp_peer_allow_list" json:"pfcp_peer_allow_list"`
	PfcpRequestTimeout        uint32   `mapstructure:"pfcp_request_timeout" json:"pfcp_request_timeout"`
	PfcpRequestRetries        uint32   `mapstructure:"pfcp_request_retries" json:"pfcp_request_retries"`
	PfcpResponseRetention     uint32   `mapstructure:"pfcp_response_retention" json:"pfcp_response_retention"`
	PfcpMaxReplayEntries      uint32   `mapstructure:"pfcp_max_replay_entries" json:"pfcp_max_replay_entries"`
	PfcpMaxOriginatedRequests uint32   `mapstructure:"pfcp_max_originated_requests" json:"pfcp_max_originated_requests"`
	PfcpReplayMemoryMiB       uint32   `mapstructure:"pfcp_replay_memory_mib" json:"pfcp_replay_memory_mib"`
	PfcpMaxAssociations       uint32   `mapstructure:"pfcp_max_associations" json:"pfcp_max_associations"`
	HeartbeatFailureGrace     uint32   `mapstructure:"heartbeat_failure_grace" json:"heartbeat_failure_grace"`

	InterfaceName           []string       `mapstructure:"interface_name" json:"interface_name"`
	XDPAttachMode           string         `mapstructure:"xdp_attach_mode" validate:"oneof=generic native offload" json:"xdp_attach_mode"`
	ApiTLSCertFile          string         `mapstructure:"api_tls_cert_file" json:"api_tls_cert_file"`
	ApiTLSKeyFile           string         `mapstructure:"api_tls_key_file" json:"api_tls_key_file"`
	ApiToken                string         `mapstructure:"api_token" json:"-"`
	ApiAllowedOrigins       []string       `mapstructure:"api_allowed_origins" json:"api_allowed_origins"`
	ApiAddress              string         `mapstructure:"api_address" validate:"hostname_port" json:"api_address"`
	PfcpAddress             string         `mapstructure:"pfcp_address" validate:"hostname_port" json:"pfcp_address"`
	PfcpNodeId              string         `mapstructure:"pfcp_node_id" validate:"hostname|ip" json:"pfcp_node_id"`
	PfcpRemoteNode          []string       `mapstructure:"pfcp_remote_node" validate:"omitempty,dive,hostname|ip" json:"pfcp_node"`
	SxaRemoteNode           []string       `mapstructure:"sxa_remote_node" validate:"omitempty,dive,hostname|ip" json:"sxa_node"`
	SxbRemoteNode           []string       `mapstructure:"sxb_remote_node" validate:"omitempty,dive,hostname|ip" json:"sxb_node"`
	SxaLocalAddress         string         `mapstructure:"sxa_address" validate:"omitempty,hostname_port" json:"sxa_address"`
	SxbLocalAddress         string         `mapstructure:"sxb_address" validate:"omitempty,hostname_port" json:"sxb_address"`
	SxaLocalNodeId          string         `mapstructure:"sxa_node_id" validate:"omitempty,hostname|ip" json:"sxa_node_id"`
	SxbLocalNodeId          string         `mapstructure:"sxb_node_id" validate:"omitempty,hostname|ip" json:"sxb_node_id"`
	AssociationSetupTimeout uint32         `mapstructure:"association_setup_timeout" json:"association_setup_timeout"`
	MetricsAddress          string         `mapstructure:"metrics_address" validate:"hostname_port" json:"metrics_address"`
	N3Address               string         `mapstructure:"n3_address" validate:"ipv4" json:"n3_address"`
	N9Address               string         `mapstructure:"n9_address" validate:"ipv4" json:"n9_address"`
	N3AdvertisedAddress     string         `mapstructure:"n3_adv_address" validate:"ipv4" json:"n3_adv_address"`
	N3AdvertisedAddress5G   string         `mapstructure:"n3_adv_address_5g" validate:"ipv4" json:"n3_adv_address_5g"`
	N9AdvertisedAddress     string         `mapstructure:"n9_adv_address" validate:"ipv4" json:"n9_adv_address"`
	S1UAddress              string         `mapstructure:"s1u_address" validate:"omitempty,ipv4" json:"s1u_address"`
	S5S8Address             string         `mapstructure:"s5s8_address" validate:"omitempty,ipv4" json:"s5s8_address"`
	PAAddress               string         `mapstructure:"pa_address" validate:"omitempty,ipv4" json:"pa_address"`
	GtpPeer                 []string       `mapstructure:"gtp_peer" validate:"omitempty,dive,hostname_port" json:"gtp_peer"`
	GtpEchoInterval         uint32         `mapstructure:"gtp_echo_interval" json:"gtp_echo_interval"`
	QerMapSize              uint32         `mapstructure:"qer_map_size" json:"qer_map_size"`
	FarMapSize              uint32         `mapstructure:"far_map_size" json:"far_map_size"`
	UrrMapSize              uint32         `mapstructure:"urr_map_size" json:"urr_map_size"`
	PdrMapSize              uint32         `mapstructure:"pdr_map_size" json:"pdr_map_size"`
	MaxSessions             uint32         `mapstructure:"max_sessions" json:"max_sessions"`
	HeartbeatRetries        uint32         `mapstructure:"heartbeat_retries" json:"heartbeat_retries"`
	HeartbeatInterval       uint32         `mapstructure:"heartbeat_interval" json:"heartbeat_interval"`
	HeartbeatTimeout        uint32         `mapstructure:"heartbeat_timeout" json:"heartbeat_timeout"`
	LoggingLevel            string         `mapstructure:"logging_level" validate:"required" json:"logging_level"`
	LoggingCaller           bool           `mapstructure:"logging_caller" json:"logging_caller"`
	UEIPPool                string         `mapstructure:"ueip_pool" validate:"omitempty,cidr" json:"ueip_pool"`
	FTEIDPool               uint32         `mapstructure:"teid_pool" json:"teid_pool"`
	RestorationPeriod       uint32         `mapstructure:"restoration_period" json:"restoration_period"`
	FeatureUEIP             bool           `mapstructure:"feature_ueip" json:"feature_ueip"`
	Qci2DscpMapping         map[string]int `mapstructure:"qci_dscp_mapping" json:"qci_dscp_mapping"`
	AllowedApns             string         `mapstructure:"allowed_apns" json:"allowed_apns"`
	DeniedApns              string         `mapstructure:"denied_apns" json:"denied_apns"`
	PfcpProfile             string         `mapstructure:"pfcp_profile" json:"pfcp_profile"`
	TraceAssociation        bool           `mapstructure:"trace_association" json:"trace_association"`
	TraceHeartbeat          bool           `mapstructure:"trace_heartbeat" json:"trace_heartbeat"`
	TraceIn                 bool           `mapstructure:"trace_in" json:"trace_in"`
	TraceOut                bool           `mapstructure:"trace_out" json:"trace_out"`
	TraceBlocked            bool           `mapstructure:"trace_blocked" json:"trace_blocked"`
	TraceMaxDumpFiles       int            `mapstructure:"trace_files" json:"trace_files"`
	TraceMaxDumpSize        int            `mapstructure:"trace_max_size" json:"trace_max_size"`
	TraceMaxDumpPackets     int            `mapstructure:"trace_max_packets" json:"trace_max_packets"`
	IP6RaSupport            bool           `mapstructure:"ip6_ra_support" json:"ip6_ra_support"`
	Ip6RaPrefix             string         `mapstructure:"ip6_ra_prefix" validate:"cidrv6" json:"ip6_ra_prefix"`

	n3AdvertisedAddress5G net.IP
	// Set at startup from the effective file, flag and environment sources.
	n3AdvertisedExplicit   bool
	n3Advertised5GExplicit bool
	n9AdvertisedExplicit   bool
}

// Clone returns a configuration with independent slices, maps and parsed IPs.
func (c *UpfConfig) Clone() UpfConfig {
	configMu.Lock()
	defer configMu.Unlock()
	next := *c
	next.InterfaceName = slices.Clone(c.InterfaceName)
	next.PfcpPeerAllowList = slices.Clone(c.PfcpPeerAllowList)
	next.PfcpRemoteNode = slices.Clone(c.PfcpRemoteNode)
	next.SxaRemoteNode = slices.Clone(c.SxaRemoteNode)
	next.SxbRemoteNode = slices.Clone(c.SxbRemoteNode)
	next.GtpPeer = slices.Clone(c.GtpPeer)
	next.ApiAllowedOrigins = slices.Clone(c.ApiAllowedOrigins)
	next.Qci2DscpMapping = maps.Clone(c.Qci2DscpMapping)
	next.n3AdvertisedAddress5G = slices.Clone(c.n3AdvertisedAddress5G)
	return next
}

func initialize() error {
	defineFlags()
	initValidator()
	if err := initCommonConfig(); err != nil {
		return err
	}
	return initPccConfig()
}

func defineFlags() {
	// PCC flags
	pflag.String("pcc-config", pccConfigPathName, "Path to PCC config file")

	// Common flags
	pflag.String("config", commonConfigPathName, "Path to config file")
	// pflags defaults are ignored in this setup
	pflag.StringArray("iface", []string{}, "Interface list to bind XDP program to")
	pflag.String("attach", "generic", "XDP attach mode")
	pflag.String("api-tls-cert-file", "", "Management HTTPS certificate chain PEM file")
	pflag.String("api-tls-key-file", "", "Management HTTPS private key PEM file")
	pflag.String("api-token", "", "Bearer token required for administration API access")
	pflag.StringSlice("api-allowed-origins", nil, "Explicit CORS origins for the administration API")
	pflag.String("aaddr", "127.0.0.1:8080", "Address to bind api server to")
	pflag.String("paddr", "127.0.0.1:8805", "Address to bind PFCP server to")
	pflag.String("nodeid", "127.0.0.1", "PFCP Server Node ID")
	pflag.String("maddr", ":9090", "Address to bind metrics server to")
	pflag.String("n3addr", "127.0.0.1", "Address for communication over N3 interface")
	pflag.String("n9addr", "n3addr", "Address for communication over N9 interface")
	pflag.String("n3advaddr", "n3addr", "Advertised address for communication over N3 interface")
	pflag.String("n3advaddr5g", "n3addr5g", "Advertised address for communication over N3 interface for 5G")
	pflag.String("n9advaddr", "n9addr", "Advertised address for communication over N9 interface")
	pflag.String("s1uaddr", "127.0.0.1", "Address for communication over S1-U interface")
	pflag.String("s5s8addr", "127.0.0.1", "Address for communication over S5/S8 interface")
	pflag.String("paaddr", "127.0.0.1", "Address for communication over PA interface")
	pflag.StringArray("peer", []string{}, "Address of GTP peer")
	pflag.Uint32("echo", 60, "gtp_echo_interval in seconds (minimum 60; TS 29.281 V19.2.0 clause 7.2.1)")
	pflag.Uint32("qersize", 0, "Size of the QER ebpf map")
	pflag.Uint32("farsize", 0, "Size of the FAR ebpf map")
	pflag.Uint32("urrsize", 0, "Size of the URR ebpf map")
	pflag.Uint32("pdrsize", 0, "Size of the PDR ebpf map")
	pflag.Uint32("maxsessions", 65535, "Maximum number of sessions")
	pflag.StringSlice("pfcp-peer-allow-list", nil, "Allowed PFCP peer IP addresses or CIDR networks; empty admits all")
	pflag.Uint32("pfcp-request-timeout", 5, "PFCP T1 timeout in seconds")
	pflag.Uint32("pfcp-request-retries", 3, "PFCP N1 retransmissions after the initial request")
	pflag.Uint32("pfcp-response-retention", 60, "Duplicate PFCP request response retention in seconds")
	pflag.Uint32("pfcp-max-replay-entries", 131072, "Maximum retained request outcomes across the UPF process")
	pflag.Uint32("pfcp-max-originated-requests", 4096, "Maximum outstanding originated requests per PFCP connection")
	pflag.Uint32("pfcp-replay-memory-mib", 128, "Process-wide replay cache accounting budget in MiB")
	pflag.Uint32("pfcp-max-associations", 1024, "Maximum associations per PFCP connection")
	pflag.Uint32("heartbeat-failure-grace", 0, "Additional unreachable seconds after exhausting heartbeat retries before session deletion")
	pflag.Uint32("hbretries", 3, "Number of heartbeat retries")
	pflag.Uint32("hbinterval", 5, "Heartbeat interval in seconds")
	pflag.Uint32("hbtimeout", 5, "Heartbeat timeout in seconds")
	pflag.String("loglvl", "info", "Logging level")
	pflag.Bool("logcaller", false, "Enable or disable logging caller")
	pflag.Bool("ueip", false, "Enable or disable UEIP feature")
	pflag.String("ueippool", "10.60.0.0/24", "IP pool for UEIP feature")
	pflag.Uint32("teidpool", 65535, "TEID pool for FTUP feature")
	pflag.Uint32("restoration-period", 60, "Seconds after startup reserved for session restoration; holds automatic UE IPv4 allocation and suppresses unknown-tunnel Error Indications")
	pflag.StringArray("pfcprnode", []string{}, "Address of remote PFCP node")
	pflag.StringArray("sxanode", []string{}, "Address of remote Sxa node")
	pflag.StringArray("sxbnode", []string{}, "Address of remote Sxb node")
	pflag.String("sxaaddr", "", "Sxa Address to bind PFCP server to")
	pflag.String("sxbaddr", "", "Sxb Address to bind PFCP server to")
	pflag.String("sxanodeid", "127.0.0.2", "Sxa Server Node ID")
	pflag.String("sxbnodeid", "127.0.0.3", "Sxb Server Node ID")
	pflag.Uint32("astimeout", 5, "Association setup timeout in seconds")
	pflag.StringToInt("qdmap", map[string]int{}, "QCI to DSCP binding")
	pflag.String("aapns", ".*", "Allowed APNs mask")
	pflag.String("dapns", "", "Denied APNs mask")
	pflag.String("pfcp_profile", "default", "PFCP profile: \"default\" (standard 3GPP) or \"huawei\" (Huawei SPGW-C dialect)")
	pflag.Bool("traceassoc", true, "Trace PFCP Association messages (Establish/Modify/Release)")
	pflag.Bool("tracehb", false, "Trace PFCP Heartbeat messages")
	pflag.Bool("tracein", true, "Trace incomming dataplane packets")
	pflag.Bool("traceout", true, "Trace outcomming dataplane packets")
	pflag.Bool("traceblock", false, "Trace dropped dataplane packets")
	pflag.Int("tracefcnt", 10, "Maximum number of rotated trace dump files")
	pflag.Int("tracefsize", 10*1024*1024, "Maximum size (in bytes) of one trace dump file")
	pflag.Int("tracefpackets", 100000, "Maximum number of packets in one trace dump file")
	pflag.Bool("ip6ra", false, "Enable or disable IPv6 Router Advertisement support")
	pflag.String("ip6rapref", "2a03:d000:29a0:509::/64", "Subscriber IPv6 prefix")

	pflag.Parse()
}

func initPccConfig() error {
	configPath := pflag.Lookup("pcc-config").Value.String()

	pccConfigV.SetDefault("pcc_rules", []PccRule{})

	pccConfigV.SetConfigFile(configPath)
	pccConfigV.SetEnvPrefix("pcc")
	pccConfigV.AutomaticEnv()

	if err := readConfig(pccConfigV, pflag.Lookup("pcc-config").Changed); err != nil {
		return fmt.Errorf("PCC configuration: %w", err)
	}
	return nil
}

// readConfig allows only an absent implicit default file. A present unreadable
// or malformed file, and every explicitly selected missing file, are errors.
func readConfig(v *viper.Viper, explicit bool) error {
	if err := v.ReadInConfig(); err != nil {
		var absent viper.ConfigFileNotFoundError
		if !explicit && (errors.As(err, &absent) || errors.Is(err, os.ErrNotExist)) {
			return nil
		}
		return fmt.Errorf("read configuration: %w", err)
	}
	return nil
}

func initCommonConfig() error {
	configPath := pflag.Lookup("config").Value.String()
	// Bind flag errors only when flag is nil, and we ignore empty cli args
	_ = commonConfigV.BindPFlag("interface_name", pflag.Lookup("iface"))
	_ = commonConfigV.BindPFlag("xdp_attach_mode", pflag.Lookup("attach"))
	_ = commonConfigV.BindPFlag("api_tls_cert_file", pflag.Lookup("api-tls-cert-file"))
	_ = commonConfigV.BindPFlag("api_tls_key_file", pflag.Lookup("api-tls-key-file"))
	_ = commonConfigV.BindPFlag("api_token", pflag.Lookup("api-token"))
	_ = commonConfigV.BindPFlag("api_allowed_origins", pflag.Lookup("api-allowed-origins"))
	_ = commonConfigV.BindPFlag("api_address", pflag.Lookup("aaddr"))
	_ = commonConfigV.BindPFlag("pfcp_address", pflag.Lookup("paddr"))
	_ = commonConfigV.BindPFlag("pfcp_node_id", pflag.Lookup("nodeid"))
	_ = commonConfigV.BindPFlag("pfcp_remote_node", pflag.Lookup("pfcprnode"))
	_ = commonConfigV.BindPFlag("sxa_remote_node", pflag.Lookup("sxanode"))
	_ = commonConfigV.BindPFlag("sxb_remote_node", pflag.Lookup("sxbnode"))
	_ = commonConfigV.BindPFlag("sxa_address", pflag.Lookup("sxaaddr"))
	_ = commonConfigV.BindPFlag("sxb_address", pflag.Lookup("sxbaddr"))
	_ = commonConfigV.BindPFlag("sxa_node_id", pflag.Lookup("sxanodeid"))
	_ = commonConfigV.BindPFlag("sxb_node_id", pflag.Lookup("sxbnodeid"))
	_ = commonConfigV.BindPFlag("association_setup_timeout", pflag.Lookup("astimeout"))
	_ = commonConfigV.BindPFlag("metrics_address", pflag.Lookup("maddr"))
	_ = commonConfigV.BindPFlag("n3_address", pflag.Lookup("n3addr"))
	_ = commonConfigV.BindPFlag("n9_address", pflag.Lookup("n9addr"))
	_ = commonConfigV.BindPFlag("n3_adv_address", pflag.Lookup("n3advaddr"))
	_ = commonConfigV.BindPFlag("n3_adv_address_5g", pflag.Lookup("n3advaddr5g"))
	_ = commonConfigV.BindPFlag("n9_adv_address", pflag.Lookup("n9advaddr"))
	_ = commonConfigV.BindPFlag("s1u_address", pflag.Lookup("s1uaddr"))
	_ = commonConfigV.BindPFlag("s5s8_address", pflag.Lookup("s5s8addr"))
	_ = commonConfigV.BindPFlag("pa_address", pflag.Lookup("paaddr"))
	_ = commonConfigV.BindPFlag("gtp_peer", pflag.Lookup("peer"))
	_ = commonConfigV.BindPFlag("gtp_echo_interval", pflag.Lookup("echo"))
	_ = commonConfigV.BindPFlag("qer_map_size", pflag.Lookup("qersize"))
	_ = commonConfigV.BindPFlag("far_map_size", pflag.Lookup("farsize"))
	_ = commonConfigV.BindPFlag("urr_map_size", pflag.Lookup("urrsize"))
	_ = commonConfigV.BindPFlag("pdr_map_size", pflag.Lookup("pdrsize"))
	_ = commonConfigV.BindPFlag("max_sessions", pflag.Lookup("maxsessions"))
	_ = commonConfigV.BindPFlag("pfcp_peer_allow_list", pflag.Lookup("pfcp-peer-allow-list"))
	_ = commonConfigV.BindPFlag("pfcp_request_timeout", pflag.Lookup("pfcp-request-timeout"))
	_ = commonConfigV.BindPFlag("pfcp_request_retries", pflag.Lookup("pfcp-request-retries"))
	_ = commonConfigV.BindPFlag("pfcp_response_retention", pflag.Lookup("pfcp-response-retention"))
	_ = commonConfigV.BindPFlag("pfcp_max_replay_entries", pflag.Lookup("pfcp-max-replay-entries"))
	_ = commonConfigV.BindPFlag("pfcp_max_originated_requests", pflag.Lookup("pfcp-max-originated-requests"))
	_ = commonConfigV.BindPFlag("pfcp_replay_memory_mib", pflag.Lookup("pfcp-replay-memory-mib"))
	_ = commonConfigV.BindPFlag("restoration_period", pflag.Lookup("restoration-period"))
	_ = commonConfigV.BindPFlag("pfcp_max_associations", pflag.Lookup("pfcp-max-associations"))
	_ = commonConfigV.BindPFlag("heartbeat_failure_grace", pflag.Lookup("heartbeat-failure-grace"))
	_ = commonConfigV.BindPFlag("heartbeat_retries", pflag.Lookup("hbretries"))
	_ = commonConfigV.BindPFlag("heartbeat_interval", pflag.Lookup("hbinterval"))
	_ = commonConfigV.BindPFlag("heartbeat_timeout", pflag.Lookup("hbtimeout"))
	_ = commonConfigV.BindPFlag("logging_level", pflag.Lookup("loglvl"))
	_ = commonConfigV.BindPFlag("logging_caller", pflag.Lookup("logcaller"))
	_ = commonConfigV.BindPFlag("feature_ueip", pflag.Lookup("ueip"))
	_ = commonConfigV.BindPFlag("ueip_pool", pflag.Lookup("ueippool"))
	_ = commonConfigV.BindPFlag("teid_pool", pflag.Lookup("teidpool"))
	_ = commonConfigV.BindPFlag("qci_dscp_mapping", pflag.Lookup("qdmap"))
	_ = commonConfigV.BindPFlag("allowed_apns", pflag.Lookup("aapns"))
	_ = commonConfigV.BindPFlag("denied_apns", pflag.Lookup("dapns"))
	_ = commonConfigV.BindPFlag("pfcp_profile", pflag.Lookup("pfcp_profile"))
	_ = commonConfigV.BindPFlag("trace_association", pflag.Lookup("traceassoc"))
	_ = commonConfigV.BindPFlag("trace_heartbeat", pflag.Lookup("tracehb"))
	_ = commonConfigV.BindPFlag("trace_in", pflag.Lookup("tracein"))
	_ = commonConfigV.BindPFlag("trace_out", pflag.Lookup("traceout"))
	_ = commonConfigV.BindPFlag("trace_blocked", pflag.Lookup("traceblock"))
	_ = commonConfigV.BindPFlag("trace_files", pflag.Lookup("tracefcnt"))
	_ = commonConfigV.BindPFlag("trace_max_size", pflag.Lookup("tracefsize"))
	_ = commonConfigV.BindPFlag("trace_max_packets", pflag.Lookup("tracefpackets"))
	_ = commonConfigV.BindPFlag("ip6_ra_support", pflag.Lookup("ip6ra"))
	_ = commonConfigV.BindPFlag("ip6_ra_prefix", pflag.Lookup("ip6rapref"))

	commonConfigV.SetConfigFile(configPath)

	commonConfigV.SetEnvPrefix("upf")
	commonConfigV.AutomaticEnv()

	if err := readConfig(commonConfigV, pflag.Lookup("config").Changed); err != nil {
		return err
	}

	commonConfigV.SetDefault("n9_address", commonConfigV.GetString("n3_address"))
	commonConfigV.SetDefault("n3_adv_address", commonConfigV.GetString("n3_address"))
	commonConfigV.SetDefault("n3_adv_address_5g", commonConfigV.GetString("n3_address"))
	commonConfigV.SetDefault("n9_adv_address", commonConfigV.GetString("n9_address"))

	log.Print("Loaded startup configuration")
	return nil
}

func (c *UpfConfig) GetDscpMarkByQci(qci uint8) uint8 {
	dscp := c.Qci2DscpMapping[strconv.Itoa(int(qci))]
	return uint8(dscp)
}

// GetN3AdvertisedAddress5G returns an independent runtime address snapshot.
func (c *UpfConfig) GetN3AdvertisedAddress5G() net.IP {
	configMu.Lock()
	defer configMu.Unlock()
	return slices.Clone(c.n3AdvertisedAddress5G)
}

// SetRuntimeN3AdvertisedAddress5G publishes the address read by 5G session
// handlers without changing the immutable exported startup configuration.
func (c *UpfConfig) SetRuntimeN3AdvertisedAddress5G(address net.IP) {
	configMu.Lock()
	defer configMu.Unlock()
	c.n3AdvertisedAddress5G = slices.Clone(address)
}

// RefreshDerivedAdvertisedAddresses follows N3/N9 edits only for addresses
// which were not explicitly configured at startup.
func (c *UpfConfig) RefreshDerivedAdvertisedAddresses() {
	if !c.n3AdvertisedExplicit {
		c.N3AdvertisedAddress = c.N3Address
	}
	if !c.n3Advertised5GExplicit {
		c.N3AdvertisedAddress5G = c.N3Address
	}
	if !c.n9AdvertisedExplicit {
		c.N9AdvertisedAddress = c.N9Address
	}
}

func (c *UpfConfig) Validate() error {
	// TS 29.281 V19.2.0 clause 7.2.1 limits new Echo Requests per path.
	if c.GtpEchoInterval < 60 {
		return fmt.Errorf("gtp_echo_interval must be at least 60 seconds (TS 29.281 V19.2.0 clause 7.2.1)")
	}
	if err := c.ValidatePFCP(); err != nil {
		return err
	}
	v := validator.New()
	v.RegisterTagNameFunc(func(f reflect.StructField) string { return f.Tag.Get("mapstructure") })
	if err := v.Struct(c); err != nil {
		return err
	}
	if _, err := zerolog.ParseLevel(c.LoggingLevel); err != nil {
		return fmt.Errorf("logging_level: %w", err)
	}
	if err := c.ValidateAPIExposure(); err != nil {
		return err
	}
	// Bound eagerly allocated maps and pools before multiplying or enumerating them.
	for key, value := range map[string]uint32{"max_sessions": c.MaxSessions, "association_setup_timeout": c.AssociationSetupTimeout, "gtp_echo_interval": c.GtpEchoInterval} {
		if value == 0 || value > 1<<20 {
			return fmt.Errorf("%s must be between 1 and 1048576", key)
		}
	}

	for key, value := range map[string]uint32{"pdr_map_size": c.PdrMapSize, "far_map_size": c.FarMapSize, "qer_map_size": c.QerMapSize, "urr_map_size": c.UrrMapSize} {
		if value > 2<<20 {
			return fmt.Errorf("%s must not exceed 2097152", key)
		}
	}
	for key, value := range map[string]int{"trace_files": c.TraceMaxDumpFiles, "trace_max_size": c.TraceMaxDumpSize, "trace_max_packets": c.TraceMaxDumpPackets} {
		minimum := 1
		if key == "trace_files" {
			minimum = 0
		}
		if value < minimum || value > 1<<30 {
			return fmt.Errorf("%s must be between %d and 1073741824", key, minimum)
		}
	}
	if c.FeatureUEIP {
		ip, subnet, err := net.ParseCIDR(c.UEIPPool)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("ueip_pool must be an IPv4 CIDR")
		}
		ones, bits := subnet.Mask.Size()
		if bits != 32 || ones < 12 {
			return fmt.Errorf("ueip_pool must contain at most 1048576 addresses (/12 or narrower)")
		}
	}
	if c.FTEIDPool == 0 || c.FTEIDPool > 1<<20 {
		return fmt.Errorf("teid_pool must be between 1 and 1048576")
	}

	if !c.FeatureUEIP {
		c.UEIPPool = ""
	}

	if c.PdrMapSize == 0 {
		c.PdrMapSize = c.MaxSessions * 2
	}
	if c.FarMapSize == 0 {
		c.FarMapSize = c.MaxSessions * 2
	}
	if c.QerMapSize == 0 {
		c.QerMapSize = c.MaxSessions
	}
	if c.UrrMapSize == 0 {
		c.UrrMapSize = c.MaxSessions * 2
	}

	n3AdvertisedAddress5G := net.ParseIP(c.N3AdvertisedAddress5G)
	if n3AdvertisedAddress5G == nil {
		return fmt.Errorf("failed to parse N3 IP address for 5G: %s", c.N3AdvertisedAddress5G)
	}
	c.SetRuntimeN3AdvertisedAddress5G(n3AdvertisedAddress5G)

	return nil
}

// Unmarshal data from config file
func (c *UpfConfig) Unmarshal() error {
	configMu.Lock()
	defer configMu.Unlock()
	if err := commonConfigV.UnmarshalExact(c); err != nil {
		return err
	}
	c.n3AdvertisedExplicit = explicitAddress("n3_adv_address", "n3advaddr", c.N3AdvertisedAddress)
	c.n3Advertised5GExplicit = explicitAddress("n3_adv_address_5g", "n3advaddr5g", c.N3AdvertisedAddress5G)
	c.n9AdvertisedExplicit = explicitAddress("n9_adv_address", "n9advaddr", c.N9AdvertisedAddress)
	c.RefreshDerivedAdvertisedAddresses()
	return nil
}

func explicitAddress(key, flag, value string) bool {
	if value == "" {
		return false
	}
	f := pflag.Lookup(flag)
	return commonConfigV.InConfig(key) || (f != nil && f.Changed) || os.Getenv("UPF_"+strings.ToUpper(key)) != ""
}

func validateSdfFilter(fl validator.FieldLevel) bool {
	if fl.Field().Type() != reflect.TypeOf("") {
		return false
	}

	return SDFFilterRegex.MatchString(fl.Field().String())
}

func initValidator() {
	validate = validator.New()

	err := validate.RegisterValidation("sdfFilter", validateSdfFilter)
	if err != nil {
		log.Error().Msgf("error register sdfFilter validator: %v", err)
	}
}

func (pcr *PCCRulesConfig) Validate() error {
	if err := validate.Struct(pcr); err != nil {
		return err
	}

	return nil
}

// Unmarshal data from config file
func (pcr *PCCRulesConfig) Unmarshal() error {
	return pccConfigV.UnmarshalExact(pcr)
}

func (c *UpfConfig) UpdateFile(params map[string]interface{}) error {
	configMu.Lock()
	defer configMu.Unlock()
	path := commonConfigV.ConfigFileUsed()
	if path == "" {
		path = commonConfigPathName
	}
	saved := viper.New()
	saved.SetConfigFile(path)
	if err := saved.ReadInConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read selected config: %w", err)
	}
	for key, value := range params {
		saved.Set(key, value)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".eupf-config-*.yaml")
	if err != nil {
		return fmt.Errorf("prepare selected config: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config temporary file: %w", err)
	}
	if err := saved.WriteConfigAs(name); err != nil {
		return fmt.Errorf("write selected config: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("commit selected config: %w", err)
	}

	return nil
}

// ValidateAPIExposure permits unauthenticated management only on loopback.
func (c *UpfConfig) ValidateAPIExposure() error {
	if (c.ApiTLSCertFile == "") != (c.ApiTLSKeyFile == "") {
		return fmt.Errorf("api_tls_cert_file and api_tls_key_file must be configured together")
	}
	host, _, err := net.SplitHostPort(c.ApiAddress)
	if err != nil {
		return fmt.Errorf("api_address: %w", err)
	}
	ip := net.ParseIP(host)
	if c.ApiToken == "" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("api_token is required when api_address binds outside loopback")
	}
	if c.ApiToken != "" && !apiTokenRegex.MatchString(c.ApiToken) {
		return fmt.Errorf("api_token must use HTTP token68 characters")
	}
	for _, origin := range c.ApiAllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(origin, "*") || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return fmt.Errorf("api_allowed_origins requires explicit http or https origins")
		}
	}
	return nil
}
