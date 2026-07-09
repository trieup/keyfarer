package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage the vault decryption key for this repository",
	}
	cmd.AddCommand(newKeyShowCmd(), newKeyForgetCmd())
	return cmd
}

func newKeyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the cached vault key (for setting up another machine)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			k, err := p.ShowKey()
			if err != nil {
				return err
			}
			fmt.Println(k)
			return nil
		},
	}
}

func newKeyForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget",
		Short: "Remove the cached vault key from local storage",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}
			if err := p.ForgetKey(); err != nil {
				return err
			}
			fmt.Println("removed cached vault key for this repository")
			return nil
		},
	}
}
