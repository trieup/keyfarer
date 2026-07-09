package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	var noFiles bool
	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with vault secrets injected",
		Long: "Decrypts the vault in memory and executes the command with every managed\n" +
			"key/value secret in its environment. Sealed secret files (.env, JSON, .p8)\n" +
			"are written to their repo paths only for the lifetime of the command, then\n" +
			"removed, so plaintext never lingers on disk. Pass --no-files to inject env\n" +
			"secrets only and leave file secrets in the vault.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			// Keep the parent alive through Ctrl+C so run-scoped secret files are
			// always cleaned up. The child shares our process group and receives
			// the signal directly, so it still terminates.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			defer signal.Stop(sigCh)
			go func() {
				for range sigCh {
				}
			}()

			code, err := p.Run(cmd.Context(), args, os.Stdout, os.Stderr, os.Stdin, !noFiles)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noFiles, "no-files", false, "inject env secrets only; do not materialize file secrets for the run")
	return cmd
}
