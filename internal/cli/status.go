package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/secrets"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show drift between disk, vault, and registry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			rep, err := p.Status()
			if err != nil {
				return err
			}
			if !rep.VaultFound {
				fmt.Println("no vault yet; add a secret with `keyfarer add`")
			}
			if !rep.StateFound && rep.VaultFound {
				fmt.Println("no local state (fresh clone?); run `keyfarer restore` for full drift detection")
			}
			if len(rep.Entries) == 0 {
				fmt.Println("no managed secrets")
				return nil
			}
			for _, e := range rep.Entries {
				fmt.Printf("%-13s %-4s %s\n", label(e.Status), e.Kind, e.Name)
			}
			if rep.Dirty() {
				fmt.Println("\naction needed: run `keyfarer seal` to update the vault, then commit it")
			}
			return nil
		},
	}
}

func label(s secrets.EntryStatus) string {
	switch s {
	case secrets.StatusClean:
		return "clean"
	case secrets.StatusEncrypted:
		return "encrypted"
	case secrets.StatusDrifted:
		return "DRIFTED"
	case secrets.StatusUnsealed, secrets.StatusUnsealedEnv:
		return "UNSEALED"
	case secrets.StatusMissing:
		return "MISSING"
	case secrets.StatusSealedEnv:
		return "sealed"
	}
	return string(s)
}
