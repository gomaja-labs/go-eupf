package core

import (
	"bytes"
	"encoding/json"

	"testing"

	"github.com/rs/zerolog"
)

func TestSessionLoggerKeepsBothIdentifiers(t *testing.T) {
	var output bytes.Buffer
	logger := sessionLogger(zerolog.New(&output).With().Str("endpoint", "N4").Logger(), &Session{LocalSEID: 11, RemoteSEID: 12})
	logger.Error().Msg("synthetic failure")
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["LocalSEID"] != float64(11) || fields["RemoteSEID"] != float64(12) || fields["endpoint"] != "N4" {
		t.Fatalf("session context lost: %v", fields)
	}
}
