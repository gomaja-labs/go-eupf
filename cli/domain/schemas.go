package domain

import (
	"time"
)

type TraceRecord struct {
	Imsi      string    `json:"imsi"`
	Msisdn    string    `json:"msisdn"`
	Timestamp time.Time `json:"timestamp"`
	ConnAddr  string    `json:"connAddr"`
}

type BackupRecord struct {
	Name      string    `json:"name"`
	Timestamp time.Time `json:"timestamp"`
}

type UpfConfig struct {
	PfcpPeerAllowList       []string       `json:"pfcp_peer_allow_list" yaml:"pfcp_peer_allow_list"`
	PfcpRequestTimeout      uint32         `json:"pfcp_request_timeout" yaml:"pfcp_request_timeout"`
	PfcpRequestRetries      uint32         `json:"pfcp_request_retries" yaml:"pfcp_request_retries"`
	PfcpResponseRetention   uint32         `json:"pfcp_response_retention" yaml:"pfcp_response_retention"`
	PfcpMaxTransactions     uint32         `json:"pfcp_max_transactions" yaml:"pfcp_max_transactions"`
	PfcpMaxAssociations     uint32         `json:"pfcp_max_associations" yaml:"pfcp_max_associations"`
	HeartbeatFailureGrace   uint32         `json:"heartbeat_failure_grace" yaml:"heartbeat_failure_grace"`
	InterfaceName           []string       `json:"interface_name" yaml:"interface_name"`
	XDPAttachMode           string         `json:"xdp_attach_mode" yaml:"xdp_attach_mode"`
	ApiAllowedOrigins       []string       `json:"api_allowed_origins" yaml:"api_allowed_origins"`
	ApiTLSCertFile          string         `json:"api_tls_cert_file" yaml:"api_tls_cert_file"`
	ApiTLSKeyFile           string         `json:"api_tls_key_file" yaml:"api_tls_key_file"`
	ApiAddress              string         `json:"api_address" yaml:"api_address"`
	PfcpAddress             string         `json:"pfcp_address" yaml:"pfcp_address"`
	PfcpNodeId              string         `json:"pfcp_node_id" yaml:"pfcp_node_id"`
	PfcpRemoteNode          []string       `json:"pfcp_node" yaml:"pfcp_remote_node"`
	SxaRemoteNode           []string       `json:"sxa_node" yaml:"sxa_remote_node"`
	SxbRemoteNode           []string       `json:"sxb_node" yaml:"sxb_remote_node"`
	SxaLocalAddress         string         `json:"sxa_address" yaml:"sxa_address"`
	SxbLocalAddress         string         `json:"sxb_address" yaml:"sxb_address"`
	SxaLocalNodeId          string         `json:"sxa_node_id" yaml:"sxa_node_id"`
	SxbLocalNodeId          string         `json:"sxb_node_id" yaml:"sxb_node_id"`
	AssociationSetupTimeout uint32         `json:"association_setup_timeout" yaml:"association_setup_timeout"`
	MetricsAddress          string         `json:"metrics_address" yaml:"metrics_address"`
	N3Address               string         `json:"n3_address" yaml:"n3_address"`
	N9Address               string         `json:"n9_address" yaml:"n9_address"`
	N3AdvertisedAddress     string         `json:"n3_adv_address" yaml:"n3_adv_address"`
	N3AdvertisedAddress5G   string         `json:"n3_adv_address_5g" yaml:"n3_adv_address_5g"`
	N9AdvertisedAddress     string         `json:"n9_adv_address" yaml:"n9_adv_address"`
	S1UAddress              string         `json:"s1u_address" yaml:"s1u_address"`
	S5S8Address             string         `json:"s5s8_address" yaml:"s5s8_address"`
	PAAddress               string         `json:"pa_address" yaml:"pa_address"`
	GtpPeer                 []string       `json:"gtp_peer" yaml:"gtp_peer"`
	GtpEchoInterval         uint32         `json:"gtp_echo_interval" yaml:"gtp_echo_interval"`
	QerMapSize              uint32         `json:"qer_map_size" yaml:"qer_map_size"`
	FarMapSize              uint32         `json:"far_map_size" yaml:"far_map_size"`
	UrrMapSize              uint32         `json:"urr_map_size" yaml:"urr_map_size"`
	PdrMapSize              uint32         `json:"pdr_map_size" yaml:"pdr_map_size"`
	MaxSessions             uint32         `json:"max_sessions" yaml:"max_sessions"`
	HeartbeatRetries        uint32         `json:"heartbeat_retries" yaml:"heartbeat_retries"`
	HeartbeatInterval       uint32         `json:"heartbeat_interval" yaml:"heartbeat_interval"`
	HeartbeatTimeout        uint32         `json:"heartbeat_timeout" yaml:"heartbeat_timeout"`
	LoggingLevel            string         `json:"logging_level" yaml:"logging_level"`
	LoggingCaller           bool           `json:"logging_caller" yaml:"logging_caller"`
	UEIPPool                string         `json:"ueip_pool" yaml:"ueip_pool"`
	FTEIDPool               uint32         `json:"teid_pool" yaml:"teid_pool"`
	FeatureUEIP             bool           `json:"feature_ueip" yaml:"feature_ueip"`
	FeatureFTUP             bool           `json:"feature_ftup" yaml:"feature_ftup"`
	Qci2DscpMapping         map[string]int `json:"qci_dscp_mapping" yaml:"qci_dscp_mapping"`
	AllowedApns             string         `json:"allowed_apns" yaml:"allowed_apns"`
	DeniedApns              string         `json:"denied_apns" yaml:"denied_apns"`
	PfcpProfile             string         `json:"pfcp_profile" yaml:"pfcp_profile"`
	TraceAssociation        bool           `json:"trace_association" yaml:"trace_association"`
	TraceHeartbeat          bool           `json:"trace_heartbeat" yaml:"trace_heartbeat"`
	TraceIn                 bool           `json:"trace_in" yaml:"trace_in"`
	TraceOut                bool           `json:"trace_out" yaml:"trace_out"`
	TraceBlocked            bool           `json:"trace_blocked" yaml:"trace_blocked"`
	TraceMaxDumpFiles       int            `json:"trace_files" yaml:"trace_files"`
	TraceMaxDumpSize        int            `json:"trace_max_size" yaml:"trace_max_size"`
	TraceMaxDumpPackets     int            `json:"trace_max_packets" yaml:"trace_max_packets"`
	IP6RaSupport            bool           `json:"ip6_ra_support" yaml:"ip6_ra_support"`
	Ip6RaPrefix             string         `json:"ip6_ra_prefix" yaml:"ip6_ra_prefix"`
}

type PfcpSession struct {
	LocalSEID   uint64
	RemoteSEID  uint64
	IMSI        string
	MSISDN      string
	PDRs        map[string]SPDRInfo
	FARs        map[string]SFarInfo
	QERs        map[string]SQerInfo
	URRs        map[string]SUrrInfo
	URRSequence uint32
	Traced      bool
}

type SPDRInfo struct {
	PdrID           uint32
	PdrInfo         PdrInfo
	Teid            uint32
	Ipv4            string
	Ipv6            string
	NetworkInstance string
	Allocated       bool
	PCCInfo         *PCCInfo
}

type PCCInfo struct {
	PCCName      string
	Notify       bool
	RawSDFFilter string
	SDFFilter    SdfFilter
	FAR          FarInfo
	QER          QerInfo
}

type SFarInfo struct {
	FarInfo  FarInfo
	GlobalId uint32
}

type SQerInfo struct {
	QerInfo  QerInfo
	GlobalId uint32
}

type SUrrInfo struct {
	UrrInfo         UrrInfo
	GlobalId        uint32
	ReportSeqNumber uint32
}

type PdrInfo struct {
	OuterHeaderRemoval uint8
	FarId              uint32
	QerId              uint32
	Urr1Id             uint32
	Urr2Id             uint32
	SdfFilter          []SdfFilter
	TraceFlag          bool
	NotifyFlag         bool
}

type SdfFilter struct {
	Protocol     uint8
	SrcAddress   IpWMask
	SrcPortRange PortRange
	DstAddress   IpWMask
	DstPortRange PortRange
}

type IpWMask struct {
	Type uint8
	Ip   string
	Mask string
}

type PortRange struct {
	LowerBound uint16
	UpperBound uint16
}

type FarInfo struct {
	Action                uint8  `json:"action"`
	OuterHeaderCreation   uint8  `json:"outer_header_creation"`
	Teid                  uint32 `json:"teid"`
	RemoteIP              string `json:"remote_ip"`
	Trigger               uint8  `json:"trigger"`
	TransportLevelMarking uint16 `json:"transport_level_marking"`
}

type QerInfo struct {
	GateStatusUL uint8
	GateStatusDL uint8
	Qfi          uint8
	Dscp         uint8
	MaxBitrateUL uint64
	MaxBitrateDL uint64
}

type UrrInfo struct {
	UplinkVolume    uint64
	DownlinkVolume  uint64
	VolumeThreshold uint64
	TimeThreshold   float64
}
