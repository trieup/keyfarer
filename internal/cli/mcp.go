package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/internal/mcp"
)

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve secrets to AI agents over MCP (stdio)",
		Long: "Starts the Model Context Protocol server that lets AI coding agents use\n" +
			"this repository's secrets without secret values entering the model context.\n" +
			"Registered automatically in .cursor/mcp.json and .mcp.json by `keyfarer init`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			return mcp.Serve(cmd.Context(), wd)
		},
	}
}
