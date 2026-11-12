package core

import (
	"bytes"
	"encoding/json"
	"github.com/rs/zerolog"
	"strings"
	"testing"
)

func TestCallerHookTracksRuntimeOption(t *testing.T) {
	previous := logCaller.Load()
	defer logCaller.Store(previous)
	oldLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	defer zerolog.SetGlobalLevel(oldLevel)
	for _, enabled := range []bool{false, true, false} {
		var output bytes.Buffer
		logger := zerolog.New(&output).Hook(callerHook{})
		SetLoggerCaller(enabled)
		logger.Info().Msg("toggle caller")
		var value map[string]any
		if err := json.Unmarshal(output.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		caller, found := value[zerolog.CallerFieldName]
		if found != enabled {
			t.Errorf("caller present=%v enabled=%v", found, enabled)
		}
		if enabled && !strings.Contains(caller.(string), "logger_hook_test.go") {
			t.Errorf("wrong caller=%v", caller)
		}
	}
}
