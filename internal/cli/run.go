package cli

import (
	"os"

	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with vault secrets injected as env vars",
		Long: "Decrypts the vault in memory and executes the command with every managed\n" +
			"key/value secret in its environment. No plaintext touches disk.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			code, err := p.Run(cmd.Context(), args, os.Stdout, os.Stderr, os.Stdin)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}
