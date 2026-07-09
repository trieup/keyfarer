// Package cli is the human runtime layer: thin cobra commands over the
// core/secrets service. No business logic lives here.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/secrets"
	"github.com/trieup/keyfarer/internal/version"
)

// New builds the root command with every subcommand attached.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "keyfarer",
		Short: "Repo secret vault for solo developers",
		Long: "Keyfarer encrypts your project's secrets (API keys, .p8 keys, .env values)\n" +
			"into a single keyfarer.vault file that is safe to commit. Restore everything\n" +
			"on a new machine with your vault key. AI agents access secrets through the\n" +
			"built-in MCP server without values ever entering the model context.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newAddCmd(),
		newSealCmd(),
		newRestoreCmd(),
		newStatusCmd(),
		newRunCmd(),
		newGuardCmd(),
		newKeyCmd(),
		newMCPCmd(),
	)
	return root
}

// Main is the process entry point.
func Main() {
	if err := New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "keyfarer:", err)
		os.Exit(1)
	}
}

// openProject loads the project for a command, with interactive prompting.
func openProject(cmd *cobra.Command) (*secrets.Project, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return secrets.Open(wd, true)
}
