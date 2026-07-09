package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/instrument"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up keyfarer in this repository",
		Long: "Creates keyfarer.toml, protects .keyfarer/ via .gitignore, installs the\n" +
			"pre-commit guard hook, and writes AI agent instrumentation (AGENTS.md\n" +
			"section, Cursor rule, MCP registration).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			root, err := gitx.RepoRoot(wd)
			if err != nil {
				return err
			}

			if _, err := config.Load(root); errors.Is(err, config.ErrNotInitialized) {
				cfg := config.Default()
				if err := cfg.Save(root); err != nil {
					return err
				}
				fmt.Println("created", config.FileName)
			} else if err != nil {
				return err
			} else {
				fmt.Println(config.FileName, "already present")
			}

			if err := os.MkdirAll(filepath.Join(root, config.SecretsDir), 0o700); err != nil {
				return err
			}
			added, err := gitx.EnsureIgnored(root, []string{config.Dir + "/"})
			if err != nil {
				return err
			}
			if len(added) > 0 {
				fmt.Println("added to .gitignore:", added)
			}
			if err := gitx.InstallPreCommitHook(root); err != nil {
				return err
			}
			fmt.Println("installed pre-commit guard hook")

			changed, err := instrument.WriteAll(root)
			if err != nil {
				return err
			}
			for _, f := range changed {
				fmt.Println("wrote agent instrumentation:", f)
			}

			fmt.Println("\nNext: add your first secret with")
			fmt.Println("  keyfarer add path/to/secret.p8")
			fmt.Println("  keyfarer add --env OPENAI_API_KEY")
			return nil
		},
	}
	return cmd
}
