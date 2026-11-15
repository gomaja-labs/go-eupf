//go:build linux

package core

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type canceledBufferSender struct{ bufferSenderFunc }

func (canceledBufferSender) initialize(ctx context.Context) error { return ctx.Err() }

func TestPacketBufferPreparationCancellationIsDebug(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output).Level(zerolog.DebugLevel)
	defer func() { log.Logger = previous }()
	buffering := &PacketBuffering{
		plane: ebpf.NewBpfObjects(), sender: canceledBufferSender{},
		prepareDone: make(chan struct{}), prepareStop: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	<-buffering.Start(ctx)
	if strings.Contains(output.String(), `"level":"error"`) || !strings.Contains(output.String(), `"level":"debug"`) {
		t.Fatalf("cancellation logged as initialization failure: %s", output.String())
	}
}
