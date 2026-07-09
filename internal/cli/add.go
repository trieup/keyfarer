package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/keys"
)

func newAddCmd() *cobra.Command {
	var envEntry string
	var keep bool
	cmd := &cobra.Command{
		Use:   "add [file]",
		Short: "Encrypt a secret into the vault",
		Long: "Adds a secret file (any type: .p8, .pem, .env, JSON) or a key/value secret\n" +
			"to the encrypted vault and registers it in keyfarer.toml.\n\n" +
			"By default the plaintext file is deleted after sealing; agents access it\n" +
			"through the MCP server. Pass --keep to keep the plaintext\n" +
			"(it stays gitignored and drift-tracked).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := openProject(cmd)
			if err != nil {
				return err
			}

			if envEntry != "" {
				if len(args) > 0 {
					return fmt.Errorf("pass either a file or --env, not both")
				}
				key, value, hasValue := strings.Cut(envEntry, "=")
				if !hasValue {
					value, err = promptSecretValue(key)
					if err != nil {
						return err
					}
				}
				createdKey, err := p.AddEnv(key, value)
				if err != nil {
					return err
				}
				printCreatedKey(createdKey)
				fmt.Println("sealed env secret", key, "into", config.VaultFileName)
				fmt.Println("use it via: keyfarer run -- <cmd>   (injected as $" + key + ")")
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("pass a file path or --env KEY[=VALUE]")
			}
			removePlaintext := !keep
			rel, createdKey, err := p.AddFile(args[0], removePlaintext)
			if err != nil {
				return err
			}
			printCreatedKey(createdKey)
			fmt.Println("sealed", rel, "into", config.VaultFileName)
			if removePlaintext {
				fmt.Println("removed plaintext; bring it back on demand with: keyfarer restore --files")
			}
			fmt.Println("commit", config.VaultFileName, "and", config.FileName, "to back up this secret")
			return nil
		},
	}
	cmd.Flags().StringVar(&envEntry, "env", "", "add a key/value secret: KEY=VALUE, or KEY to be prompted")
	cmd.Flags().BoolVar(&keep, "keep", false, "keep the plaintext file on disk after sealing")
	return cmd
}

func printCreatedKey(createdKey string) {
	if createdKey == "" {
		return
	}
	fmt.Println()
	fmt.Println("Save this vault key in your password manager. You need it on every new machine.")
	fmt.Println("It is also cached locally (OS credential store or", keysEnvHint()+").")
	fmt.Println()
	fmt.Println(createdKey)
	fmt.Println()
}

func keysEnvHint() string {
	path, err := keys.KeyFilePath()
	if err != nil {
		return "your keyfarer key file"
	}
	return path
}

func promptSecretValue(key string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no value given and stdin is not a terminal; use --env %s=VALUE", key)
	}
	fmt.Fprintf(os.Stderr, "Value for %s (hidden): ", key)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
