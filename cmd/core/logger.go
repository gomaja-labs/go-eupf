// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var baseLogger zerolog.Logger
var logCaller atomic.Bool

type callerHook struct{}

func (callerHook) Run(event *zerolog.Event, _ zerolog.Level, _ string) {
	if logCaller.Load() {
		event.Caller(3)
	}
}

func InitLogger() {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006/01/02 15:04:05"}
	baseLogger = zerolog.New(output).With().Timestamp().Logger().Hook(callerHook{})
	log.Logger = baseLogger
}

func SetLoggerLevel(loggingLevel string) error {
	if loggingLevel == "" {
		return fmt.Errorf("logging level can't be empty")
	}
	if loglvl, err := zerolog.ParseLevel(loggingLevel); err == nil {
		zerolog.SetGlobalLevel(loglvl)
	} else {
		return fmt.Errorf("can't parse logging level: '%s'", loggingLevel)
	}
	return nil
}

func SetLoggerCaller(enableCaller bool) { logCaller.Store(enableCaller) }
