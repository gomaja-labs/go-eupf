// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package rest

import (
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

type NodeAssociationDescription struct {
	ID   string
	Addr string
}

// ListPfcpAssociations godoc
//
//	@Summary		List PFCP associations
//	@Description	List PFCP associations
//	@Tags			PFCP
//	@Produce		json
//	@Success		200	{array}	NodeAssociationDescription
//	@Router			/pfcp_associations [get]
func (h *ApiHandler) listPfcpAssociations(c *gin.Context) {

	nodeAssociationsList := []NodeAssociationDescription{}

	for _, c := range h.GetPFCPSrv() {
		for _, v := range c.AssociationSnapshots() {
			nodeAssociationsList = append(nodeAssociationsList, NodeAssociationDescription{
				ID:   v.ID,
				Addr: v.Addr})
		}
	}
	c.IndentedJSON(http.StatusOK, nodeAssociationsList)
}

// ListPfcpAssociationsFull godoc
//
//	@Summary		List PFCP associations
//	@Description	List PFCP associations
//	@Tags			PFCP
//	@Produce		json
//	@Success		200	{object}	map[string]core.NodeAssociation
//	@Router			/pfcp_associations/full [get]
func (h *ApiHandler) listPfcpAssociationsFull(c *gin.Context) {

	associations := map[string]*core.NodeAssociation{}
	for _, c := range h.GetPFCPSrv() {
		maps.Copy(associations, c.AssociationSnapshots())
	}

	c.IndentedJSON(http.StatusOK, associations)
}

// pfcpAssociationRelease requests release of every association.
// @Summary Release PFCP associations
// @Tags PFCP
// @Success 204 "No Content"
// @Router /pfcp_associations/release [post]
func (h *ApiHandler) pfcpAssociationRelease(c *gin.Context) {
	select {
	case h.associationReleaseChan <- struct{}{}:
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "association release unavailable or already pending"})
		return
	}

	c.Status(http.StatusNoContent)
}
