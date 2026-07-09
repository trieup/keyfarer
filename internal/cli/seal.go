package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trieup/keyfarer/core/config"
)

func newSealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "seal",
		Short: "Re-encrypt all managed secrets into the vault",
		Long: "Re-reads every managed plaintext source on disk and rewrites the encrypted\n" +
			"vault. Run this after editing a secret file, then commit the vault.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			if err := p.Seal(); err != nil {
				return err
			}
			fmt.Println("sealed", config.VaultFileName)
			fmt.Println("commit it to back up your secrets")
			return nil
		},
	}
}
