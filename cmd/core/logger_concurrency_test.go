package core

import (
	"io"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestLoggerCallerDuringLogging(t *testing.T) {
	oldBase, oldLogger := baseLogger, log.Logger
	defer func() { baseLogger, log.Logger = oldBase, oldLogger }()
	baseLogger = zerolog.New(io.Discard)
	log.Logger = baseLogger
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for i := range 512 {
			SetLoggerCaller(i%2 == 0)
		}
	})
	wg.Go(func() {
		<-start
		for range 512 {
			log.Info().Msg("configuration update")
		}
	})
	close(start)
	wg.Wait()
}
