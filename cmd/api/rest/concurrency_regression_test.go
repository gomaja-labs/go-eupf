package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

func TestAssociationAPIDuringAssociationDeletion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "192.0.2.1", "192.0.2.1", nil, nil, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := range 128 {
		addr := fmt.Sprintf("192.0.2.1:%d", 10000+i)
		conn.NodeAssociations[addr] = core.NewNodeAssociation(addr, addr)
	}
	h := &ApiHandler{pfcpSrv: map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}}
	r := gin.New()
	r.GET("/associations", h.listPfcpAssociations)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Go(func() {
		<-start
		for range 256 {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/associations", nil))
		}
	})
	wg.Go(func() {
		<-start
		for i := range 128 {
			conn.DeleteAssociation(fmt.Sprintf("192.0.2.1:%d", 10000+i))
		}
	})
	close(start)
	wg.Wait()
}
