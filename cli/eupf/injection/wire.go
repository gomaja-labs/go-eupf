//go:build wireinject
// +build wireinject

package injection

import (
	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/eupf/delivery"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/file"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
	"github.com/gomaja-labs/go-eupf/cli/eupf/usecase"
	"github.com/google/wire"
)

func InitEupfCLI(baseURL string, cfg *config.Config) *delivery.CLI {
	wire.Build(
		http.NewEupfHttpRepository,
		file.NewFileRepository,
		usecase.NewEupf,
		delivery.NewCLI,
	)

	return &delivery.CLI{}
}
