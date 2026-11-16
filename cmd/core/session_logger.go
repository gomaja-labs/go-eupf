package core

import "github.com/rs/zerolog"

// Keep identifiers on emitted events without constructing a context buffer on
// every successful request whose informational logs are disabled.
type sessionLogContext struct{ local, remote uint64 }

func (context sessionLogContext) Run(event *zerolog.Event, _ zerolog.Level, _ string) {
	event.Uint64("LocalSEID", context.local).Uint64("RemoteSEID", context.remote)
}
func sessionLogger(base zerolog.Logger, session *Session) zerolog.Logger {
	return base.Hook(sessionLogContext{session.LocalSEID, session.RemoteSEID})
}
