package delivery

import (
	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/spf13/cobra"
)

type CLI struct {
	Root    *cobra.Command
	usecase domain.EupfUseCase
}

func NewCLI(usecase domain.EupfUseCase) *CLI {
	root := &cobra.Command{
		Use:   "eupf",
		Short: "eUPF CLI tool",
	}

	root.PersistentFlags().AddFlagSet(config.GlobalFlags())
	cli := &CLI{
		Root:    root,
		usecase: usecase,
	}

	root.AddCommand(cli.newConfigSetCmd())
	root.AddCommand(cli.newConfigShowCmd())
	root.AddCommand(cli.newSessionCmd())
	root.AddCommand(cli.newCliConfigCmd())
	root.AddCommand(cli.newTraceCmd())
	root.AddCommand(cli.newBackupCmd())

	return cli
}

func (cli *CLI) Execute() error {
	return cli.Root.Execute()
}
