// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type Server struct {
	httpServer *http.Server
}

func New(addr string, handler http.Handler) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  1 * time.Second,
		},
	}
}

func (s *Server) Run() error {
	log.Info().Msgf("running on %s", s.httpServer.Addr)
	l, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	return s.serve(l)
}

func (s *Server) Stop(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		closeErr := s.httpServer.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warn().Err(err).Msg("HTTP shutdown deadline reached; remaining connections force-closed")
			return closeErr
		}
		return errors.Join(err, closeErr)
	}
	return nil
}

func (s *Server) serve(l net.Listener) error {
	if s.httpServer.TLSConfig != nil {
		l = tls.NewListener(l, s.httpServer.TLSConfig)
	}
	return serverResult(s.httpServer.Serve(l))
}
func serverResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// NewTLS prepares the certificate before a listener is opened. RFC 6750 section
// 5.3 requires bearer token confidentiality; RFC 8996 sections 4 and 5 prohibits TLS 1.0/1.1.
func NewTLS(addr string, handler http.Handler, certFile, keyFile string) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("api_tls_cert_file/api_tls_key_file: %w", err)
	}
	s := New(addr, handler)
	s.httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	return s, nil
}
