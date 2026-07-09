// Package mcp is the agent runtime layer: an MCP server over stdio exposing
// keyfarer's secrets to AI coding agents. Tool design keeps secret values out
// of the model context (docs/design-docs/ai-access-model.md); the tool
// descriptions below are the primary instruction surface for agents.
package mcp

import (
	"context"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/trieup/keyfarer/core/secrets"
	"github.com/trieup/keyfarer/internal/version"
)

// project opens the keyfarer project non-interactively: an MCP server has no
// terminal, so the vault key must come from the credential store, key file, or env var.
func project(dir string) (*secrets.Project, error) {
	p, err := secrets.Open(dir, false)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func keyHint(err error) error {
	return fmt.Errorf("%w. Ask the user to run `keyfarer restore` once in a terminal to unlock this repo's vault (the key is then cached locally)", err)
}

// NewServer builds the MCP server rooted at dir (the repo or any dir inside).
func NewServer(dir string) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{
		Name:    "keyfarer",
		Title:   "Keyfarer secret vault",
		Version: version.Version,
	}, nil)

	sdk.AddTool(s, &sdk.Tool{
		Name: "list_secrets",
		Description: "List every secret managed by Keyfarer in this repository: names, " +
			"kinds (file or env), and whether they are sealed. Returns metadata only, " +
			"never secret values. Use this first to discover what is available.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, listOut, error) {
		p, err := project(dir)
		if err != nil {
			return nil, listOut{}, err
		}
		infos, err := p.List()
		if err != nil {
			return nil, listOut{}, err
		}
		return nil, listOut{Secrets: infos}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "run_with_secrets",
		Description: "PREFERRED way to use secrets: run a command with every managed " +
			"secret available. Key/value secrets are injected as environment variables, " +
			"and sealed secret files (.env, service account JSON, .p8) are written to " +
			"their repo paths only for the duration of the command, then removed. So a " +
			"command that reads ./.env or GOOGLE_APPLICATION_CREDENTIALS=./sa.json just " +
			"works, and no plaintext lingers on disk. You receive only the command " +
			"output. Example: argv [\"npm\",\"start\"] runs with $OPENAI_API_KEY etc. " +
			"available. Never echo secret values or cat secret files; as a backstop, any " +
			"known secret value or file content is redacted to [REDACTED] in the output.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in runIn) (*sdk.CallToolResult, runOut, error) {
		if len(in.Argv) == 0 {
			return nil, runOut{}, fmt.Errorf("argv must not be empty")
		}
		p, err := project(dir)
		if err != nil {
			return nil, runOut{}, err
		}
		out, code, err := p.RunCapture(ctx, in.Argv)
		if err != nil {
			return nil, runOut{}, keyHint(err)
		}
		return nil, runOut{Output: out, ExitCode: code}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "materialize",
		Description: "Decrypt ONE managed secret file to its recorded path inside the " +
			"repository and leave it there. Prefer run_with_secrets, which materializes " +
			"file secrets automatically just for the duration of a command; use " +
			"materialize only for a long-lived need outside a single command (for " +
			"example a tool you keep running yourself). Returns only the absolute path, " +
			"never the content. Do NOT read the materialized file yourself; pass the " +
			"path to the tool that needs it.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in materializeIn) (*sdk.CallToolResult, materializeOut, error) {
		p, err := project(dir)
		if err != nil {
			return nil, materializeOut{}, err
		}
		path, err := p.Materialize(in.Path)
		if err != nil {
			return nil, materializeOut{}, keyHint(err)
		}
		return nil, materializeOut{AbsolutePath: path}, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name: "get_secret",
		Description: "LAST RESORT: return the raw value of one key/value secret. The " +
			"value will enter the conversation context, so prefer run_with_secrets or " +
			"materialize whenever possible. Never write the returned value into code, " +
			"files, commit messages, or logs; the pre-commit guard will block commits " +
			"containing it.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in getIn) (*sdk.CallToolResult, getOut, error) {
		p, err := project(dir)
		if err != nil {
			return nil, getOut{}, err
		}
		val, err := p.GetEnvValue(in.Key)
		if err != nil {
			return nil, getOut{}, keyHint(err)
		}
		return nil, getOut{Value: val}, nil
	})

	return s
}

// Serve runs the server over stdio until the client disconnects.
func Serve(ctx context.Context, dir string) error {
	return NewServer(dir).Run(ctx, &sdk.StdioTransport{})
}

type listOut struct {
	Secrets []secrets.SecretInfo `json:"secrets" jsonschema:"metadata for every managed secret; never contains values"`
}

type runIn struct {
	Argv []string `json:"argv" jsonschema:"command and arguments to execute, e.g. [\"npm\",\"start\"]"`
}

type runOut struct {
	Output   string `json:"output" jsonschema:"combined stdout and stderr of the command"`
	ExitCode int    `json:"exit_code" jsonschema:"process exit code"`
}

type materializeIn struct {
	Path string `json:"path" jsonschema:"repo-relative path of the managed secret file, as returned by list_secrets"`
}

type materializeOut struct {
	AbsolutePath string `json:"absolute_path" jsonschema:"absolute path of the decrypted file on disk"`
}

type getIn struct {
	Key string `json:"key" jsonschema:"name of the key/value secret, as returned by list_secrets"`
}

type getOut struct {
	Value string `json:"value" jsonschema:"the raw secret value; handle with care"`
}
