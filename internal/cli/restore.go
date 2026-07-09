package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/instrument"
)

func newRestoreCmd() *cobra.Command {
	var withFiles bool
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore secrets on this machine from the committed vault",
		Long: "Decrypts the vault, refreshes local state, and reinstalls the pre-commit\n" +
			"guard hook and agent instrumentation (hooks do not survive git clone).\n\n" +
			"On a new machine you will be prompted to paste your vault key once;\n" +
			"it is then cached locally. Secrets stay encrypted; pass --files to also\n" +
			"write every secret file to disk.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			written, err := p.Restore(withFiles)
			if err != nil {
				return err
			}

			// Close the fresh-clone gap: hooks and ignores are local-only.
			if _, err := gitx.EnsureIgnored(p.Root, []string{config.Dir + "/"}); err != nil {
				return err
			}
			if err := gitx.InstallPreCommitHook(p.Root); err != nil {
				return err
			}
			if _, err := instrument.WriteAll(p.Root); err != nil {
				return err
			}

			for _, f := range written {
				fmt.Println("restored", f)
			}
			if len(written) == 0 {
				fmt.Println("vault verified; secrets stay encrypted")
				fmt.Println("materialize a file when needed: keyfarer restore --files, or via the MCP materialize tool")
			}
			fmt.Println("reinstalled guard hook and agent instrumentation")
			return nil
		},
	}
	cmd.Flags().BoolVar(&withFiles, "files", false, "also write secret files to disk")
	return cmd
}
