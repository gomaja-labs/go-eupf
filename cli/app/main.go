package main

import (
	"fmt"
	"os"

	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/eupf/delivery"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/file"
	"github.com/gomaja-labs/go-eupf/cli/eupf/repository/http"
	"github.com/gomaja-labs/go-eupf/cli/eupf/usecase"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func InitLogger() {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006/01/02 15:04:05"}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()
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

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading config")
	}

	InitLogger()

	err = SetLoggerLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("Error setting log level")
	}

	repo, err := http.NewEupfHttpRepository(cfg.EupfAddr, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Initialize API client")
	}
	root := delivery.NewCLI(usecase.NewEupf(
		repo,
		file.NewFileRepository(cfg),
		cfg,
	))
	err = root.Execute()
	if err != nil {
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
