package rest

type LoggingLevelConfig struct {
	LoggingLevel string `json:"logging_level" validate:"required"`
}

type LoggingCallerConfig struct {
	LoggingCaller bool `json:"logging_caller" validate:"required"`
}

type DataPlaneEbpfConfig struct {
	InterfaceName []string `json:"interface_name" validate:"required"`
	XDPAttachMode string   `json:"xdp_attach_mode" validate:"required"`
}

type DataPlaneAddressesConfig struct {
	N3Address string `json:"n3_address" validate:"required"`
	N9Address string `json:"n9_address" validate:"required"`
}

type PFCPN4Config struct {
	PFCPAddress    string   `json:"pfcp_address" validate:"required"`
	PFCPNodeID     string   `json:"pfcp_node_id" validate:"required"`
	PFCPRemoteNode []string `json:"pfcp_remote_node" validate:"required"`
}

type PFCPSxaConfig struct {
	SXAAddress    string   `json:"sxa_address" validate:"required"`
	SXANodeID     string   `json:"sxa_node_id" validate:"required"`
	SXARemoteNode []string `json:"sxa_remote_node" validate:"required"`
}

type PFCPSxbConfig struct {
	SXBAddress    string   `json:"sxb_address" validate:"required"`
	SXBNodeID     string   `json:"sxb_node_id" validate:"required"`
	SXBRemoteNode []string `json:"sxb_remote_node" validate:"required"`
}

type PFCPTimersConfig struct {
	AssociationSetupTimeout uint32 `json:"association_setup_timeout" validate:"required"`
	HeartbeatTimeout        uint32 `json:"heartbeat_timeout" validate:"required"`
}

type GTPPathConfig struct {
	GtpPeer         []string `json:"gtp_peer" validate:"required"`
	GtpEchoInterval uint32   `json:"gtp_echo_interval" validate:"required"`
}
