// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package rest

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/mitchellh/mapstructure"
)

// DisplayConfig godoc
//
//	@Summary		Display configuration
//	@Description	Display configuration
//	@Tags			Configuration
//	@Produce		json
//	@Success		200	{object}	config.UpfConfig
//	@Router			/config [get]
func (h *ApiHandler) displayConfig(c *gin.Context) {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	c.IndentedJSON(http.StatusOK, *h.Cfg)
}

// EditLoggingLevelConfig godoc
//
//	@Summary Update logging level
//	@Description Update the log level (debug, info, warn, error, etc.)
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body LoggingLevelConfig true "Logging level config"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Router /config/logging_level [post]
func (h *ApiHandler) editLoggingLevelConfig(c *gin.Context) {
	var config LoggingLevelConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := core.UpdateLogLevel(config.LoggingLevel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditLoggingCallerConfig godoc
//
//	@Summary Update logging caller info
//	@Description Enable or disable function caller information in logs
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body LoggingCallerConfig true "Logging caller configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Router /config/logging_caller [post]
func (h *ApiHandler) editLoggingCallerConfig(c *gin.Context) {
	var config LoggingCallerConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	core.UpdateLogCaller(config.LoggingCaller)

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditDataPlaneConfig godoc
//
//	@Summary Update dataplane eBPF interfaces
//	@Description Bind network interfaces for eBPF dataplane processing
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body DataPlaneEbpfConfig true "Dataplane eBPF configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/dataplane_ebpf [post]
func (h *ApiHandler) editDataPlaneConfig(c *gin.Context) {
	var config DataPlaneEbpfConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.cfgMu.RLock()
	currentMode := h.Cfg.XDPAttachMode
	h.cfgMu.RUnlock()
	if h.Links != nil && len(*h.Links) > 0 && currentMode != config.XDPAttachMode {
		c.JSON(http.StatusConflict, gin.H{"error": "remove active interfaces before changing xdp_attach_mode"})
		return
	}
	err := core.BindDataPlaneInterfaces(h.BpfObjects, h.Links, config.InterfaceName, config.XDPAttachMode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditDataPlaneAddressesConfig godoc
//
//	@Summary Update dataplane N3 and N9 addresses
//	@Description Update IP addresses for N3 and N9 interfaces
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body DataPlaneAddressesConfig true "Dataplane addresses configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/dataplane_addresses [post]
func (h *ApiHandler) editDataPlaneAddressesConfig(c *gin.Context) {
	var config DataPlaneAddressesConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	n3Addr := net.ParseIP(config.N3Address)
	if n3Addr == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "n3_address is not a valid IP"})

		return
	}

	n9Addr := net.ParseIP(config.N9Address)
	if n9Addr == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "n9_address is not a valid IP"})

		return
	}

	if h.BpfObjects == nil || h.GtpPathManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "dataplane unavailable"})
		return
	}
	var dataplane ebpf.IpEntrypointDataplaneConfig
	if err := h.BpfObjects.GlobalConfig.Get(&dataplane); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	dataplane.N3Ipv4Address = binary.LittleEndian.Uint32(n3Addr.To4())
	dataplane.N9Ipv4Address = binary.LittleEndian.Uint32(n9Addr.To4())
	if err := h.BpfObjects.GlobalConfig.Set(dataplane); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	err := core.UpdateDataPlaneAddresses(h.GetPFCPSrv(), h.GtpPathManager, n3Addr, n9Addr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditPFCPN4Config godoc
//
//	@Summary Update N4 PFCP connection settings
//	@Description Update local and remote node information for PFCP N4 connection
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body PFCPN4Config true "PFCP N4 connection configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/pfcp_n4 [post]
func (h *ApiHandler) editPFCPN4Config(c *gin.Context) {
	var config PFCPN4Config
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pfcpSrv := h.GetPFCPSrv()

	if _, exists := pfcpSrv[core.N4PFCPKeyName]; exists {
		err := core.UpdatePFCPConnectionsAndPersist(
			pfcpSrv,
			core.N4PFCPKeyName,
			config.PFCPAddress,
			config.PFCPNodeID,
			config.PFCPRemoteNode,
			func() error { return h.updateConfigFile(config) },
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PFCP connection for N4 not found"})

		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditPFCPSxaConfig godoc
//
//	@Summary Update Sxa PFCP connection settings
//	@Description Update local and remote node information for PFCP Sxa connection
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body PFCPSxaConfig true "PFCP Sxa connection configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/pfcp_sxa [post]
func (h *ApiHandler) editPFCPSxaConfig(c *gin.Context) {
	var config PFCPSxaConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pfcpSrv := h.GetPFCPSrv()

	if _, exists := pfcpSrv[core.SxaPFCPKeyName]; exists {
		err := core.UpdatePFCPConnectionsAndPersist(
			pfcpSrv,
			core.SxaPFCPKeyName,
			config.SXAAddress,
			config.SXANodeID,
			config.SXARemoteNode,
			func() error { return h.updateConfigFile(config) },
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PFCP connection for Sxa not found"})

		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditPFCPSxbConfig godoc
//
//	@Summary Update Sxb PFCP connection settings
//	@Description Update local and remote node information for PFCP Sxb connection
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body PFCPSxbConfig true "PFCP Sxb connection configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/pfcp_sxb [post]
func (h *ApiHandler) editPFCPSxbConfig(c *gin.Context) {
	var config PFCPSxbConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pfcpSrv := h.GetPFCPSrv()

	if _, exists := pfcpSrv[core.SxbPFCPKeyName]; exists {
		err := core.UpdatePFCPConnectionsAndPersist(
			pfcpSrv,
			core.SxbPFCPKeyName,
			config.SXBAddress,
			config.SXBNodeID,
			config.SXBRemoteNode,
			func() error { return h.updateConfigFile(config) },
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PFCP connection for Sxb not found"})

		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditPFCPTimersConfig godoc
//
//	@Summary Update PFCP timers settings
//	@Description Update heartbeat and association setup timeout values
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body PFCPTimersConfig true "PFCP timers configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/pfcp_timers [post]
func (h *ApiHandler) editPFCPTimersConfig(c *gin.Context) {
	var config PFCPTimersConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pfcpSrv := h.GetPFCPSrv()

	core.UpdateAssociationSetupTimeout(pfcpSrv, config.AssociationSetupTimeout)
	core.UpdateHeartbeatTimeout(pfcpSrv, config.HeartbeatTimeout)

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// EditGTPPathConfig godoc
//
//	@Summary Update GTP path configuration
//	@Description Update GTP peers and echo interval
//	@Tags Configuration
//	@Accept json
//	@Produce json
//	@Param config body GTPPathConfig true "GTP path configuration"
//	@Success 200 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /config/gtp_path [post]
func (h *ApiHandler) editGTPPathConfig(c *gin.Context) {
	var config GTPPathConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "gtp_echo_interval must be at least 60 seconds (TS 29.281 V19.2.0 clause 7.2.1): " + err.Error()})
		return
	}
	if _, _, err := h.validatedEdit(config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	core.UpdateGTPManager(h.GtpPathManager, config.GtpPeer, config.GtpEchoInterval)

	if err := h.updateConfigFile(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime edit applied but persistence failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// validatedEdit applies only submitted keys to a separate configuration, then
// runs the same validator as startup before any runtime or persistence change.
func (h *ApiHandler) validatedEdit(data any) (*config.UpfConfig, map[string]interface{}, error) {
	h.cfgMu.RLock()
	next := *h.Cfg
	h.cfgMu.RUnlock()
	cfgs := make(map[string]interface{})
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil, nil, fmt.Errorf("input must be a struct")
	}
	for i := 0; i < val.NumField(); i++ {
		key := val.Type().Field(i).Tag.Get("json")
		if key != "" && key != "-" {
			cfgs[key] = val.Field(i).Interface()
		}
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &next, WeaklyTypedInput: true})
	if err != nil {
		return nil, nil, fmt.Errorf("create config decoder: %w", err)
	}
	if err := decoder.Decode(cfgs); err != nil {
		return nil, nil, fmt.Errorf("decode configuration edit: %w", err)
	}
	if err := next.Validate(); err != nil {
		return nil, nil, err
	}
	return &next, cfgs, nil
}

func (h *ApiHandler) updateConfigFile(data interface{}) error {
	next, keys, err := h.validatedEdit(data)
	if err != nil {
		return err
	}
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	if err := next.UpdateFile(keys); err != nil {
		return err
	}
	*h.Cfg = *next
	return nil
}
