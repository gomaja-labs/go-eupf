package rest

import (
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

type PdrMapElement struct {
	SessionID uint64         `json:"session_id"`
	Rules     []ebpf.PdrInfo `json:"rules"`
}

// getUplinkPdrValue godoc
// @Summary Get the ordered PDR list for a TEID
// @Tags PDR
// @Produce json
// @Param id path int true "Local TEID"
// @Success 200 {object} PdrMapElement
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /uplink_pdr_map/{id} [get]
func (h *ApiHandler) getUplinkPdrValue(c *gin.Context) {
	unlock := h.BpfObjects.LockRuleSnapshot()
	defer unlock()
	key, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid TEID"})
		return
	}
	var value ebpf.IpEntrypointPdrInfo
	if err := h.BpfObjects.PdrMapTeidIp4.Lookup(uint32(key), &value); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no PDR list found"})
		return
	}
	c.JSON(http.StatusOK, PdrMapElement{SessionID: value.SessionId, Rules: ebpf.DecodePDRBucket(value)})
}

// setUplinkPdrValue godoc
// @Summary Reject direct PDR writes; use PFCP
// @Tags PDR
// @Accept json
// @Produce json
// @Param id path int true "Local TEID"
// @Param pdr body ebpf.PdrInfo true "PDR identity, PDI and rule bindings"
// @Failure 405 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
func (h *ApiHandler) setUplinkPdrValue(c *gin.Context) {
	c.Header("Allow", "GET")
	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "forwarding rules are managed through PFCP"})
}

// getDownlinkPdrValue godoc
// @Summary Get the ordered PDR list for a UE address
// @Tags PDR
// @Produce json
// @Param id path string true "UE IP address"
// @Success 200 {object} PdrMapElement
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /downlink_pdr_map/{id} [get]
func (h *ApiHandler) getDownlinkPdrValue(c *gin.Context) {
	unlock := h.BpfObjects.LockRuleSnapshot()
	defer unlock()
	ip := net.ParseIP(c.Param("id"))
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid UE address"})
		return
	}
	value, err := h.BpfObjects.LookupDownlinkPDR(ip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no PDR list found"})
		return
	}
	c.JSON(http.StatusOK, PdrMapElement{SessionID: value.SessionId, Rules: ebpf.DecodePDRBucket(value)})
}

// setDownlinkPdrValue godoc
// @Summary Reject direct PDR writes; use PFCP
// @Tags PDR
// @Accept json
// @Produce json
// @Param id path string true "UE IP address"
// @Param pdr body ebpf.PdrInfo true "PDR identity, PDI and rule bindings"
// @Failure 405 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
func (h *ApiHandler) setDownlinkPdrValue(c *gin.Context) {
	c.Header("Allow", "GET")
	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "forwarding rules are managed through PFCP"})
}
