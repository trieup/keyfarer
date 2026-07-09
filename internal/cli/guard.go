package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/guard"
	"github.com/trieup/keyfarer/core/secrets"
)

func newGuardCmd() *cobra.Command {
	var staged bool
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Verify no plaintext secret can reach git",
		Long: "Checks gitignore coverage for every managed secret and, with --staged,\n" +
			"scans the git index for managed secret paths, byte-identical copies, and\n" +
			"pasted secret values (hash comparison; no vault key needed).\n\n" +
			"This is the pre-commit hook entry point. Exit code 1 blocks the commit.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			vs := guard.CheckSetup(p.Root, p.Config)
			if staged {
				st, err := secrets.LoadState(p.Root)
				if err != nil {
					return err
				}
				stagedVs, err := guard.CheckStaged(p.Root, p.Config, st)
				if err != nil {
					return err
				}
				vs = append(vs, stagedVs...)
			}
			for _, v := range vs {
				stream := os.Stdout
				kind := "warning"
				if v.Blocking {
					stream = os.Stderr
					kind = "BLOCKED"
				}
				_, _ = fmt.Fprintf(stream, "keyfarer guard [%s] %s: %s\n", kind, v.Code, v.Message)
			}
			if guard.Blocking(vs) {
				os.Exit(1)
			}
			if len(vs) == 0 {
				fmt.Println("guard: OK")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&staged, "staged", false, "also scan staged content (used by the pre-commit hook)")
	return cmd
}
