// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package rest

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/rs/zerolog/log"
)

// ListQerMapContent godoc
//
//	@Summary		List QER map content
//	@Description	List QER map content
//	@Tags			QER
//	@Produce		json
//	@Success		200	{object}	[]ebpf.QerMapElement
//	@Router			/qer_map [get]
func (h *ApiHandler) listQerMapContent(c *gin.Context) {
	unlock := h.BpfObjects.LockRuleSnapshot()
	defer unlock()
	if elements, err := ebpf.ListQerMapContents(h.BpfObjects.QerMap); err != nil {
		log.Info().Msgf("Error reading map: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	} else {
		c.IndentedJSON(http.StatusOK, elements)
	}
}

// GetQerValue godoc
//
//	@Summary		List QER map content
//	@Description	List QER map content
//	@Tags			QER
//	@Produce		json
//	@Param			id	path		int	true	"Qer ID"
//	@Success		200	{object}	[]ebpf.QerMapElement
//	@Router			/qer_map/{id} [get]
func (h *ApiHandler) getQerValue(c *gin.Context) {
	unlock := h.BpfObjects.LockRuleSnapshot()
	defer unlock()
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		log.Info().Msgf("Error converting id to uint32: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var value ebpf.IpEntrypointQerInfo

	if err = h.BpfObjects.QerMap.Lookup(uint32(id), &value); err != nil {
		log.Printf("Error reading map: %s", err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, ebpf.QerMapElement{
		Id:           uint32(id),
		GateStatusUL: value.UlGateStatus,
		GateStatusDL: value.DlGateStatus,
		Qfi:          value.Qfi,
		MaxBitrateUL: value.UlMaximumBitrate,
		MaxBitrateDL: value.DlMaximumBitrate,
	})
}

// SetQerValue godoc
//
//	@Summary Reject direct QER writes; use PFCP
//	@Description Create or update QER map element
//	@Tags QER
//	@Accept json
//	@Produce json
//	@Param id path int true "QER ID"
//	@Param qer body ebpf.QerMapElement true "QER element data"
//	@Failure 405 {object} map[string]string
//	@Failure 400 {object} map[string]string
//	@Failure 500 {object} map[string]string
func (h *ApiHandler) setQerValue(c *gin.Context) {
	c.Header("Allow", "GET")
	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "forwarding rules are managed through PFCP"})
}
