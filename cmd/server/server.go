// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package server

import (
	"context"
	"errors"
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
		return errors.Join(err, s.httpServer.Close())
	}
	return nil
}

func (s *Server) serve(l net.Listener) error {
	return serverResult(s.httpServer.Serve(l))
}
func serverResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
