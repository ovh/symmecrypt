package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/ovh/symmecrypt/seal"
)

const sealUsage = `Usage: symmecrypt seal <subcommand> [flags]

Subcommands:
  new   generate a new shamir seal and its shards
`

func cmdSeal(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErrorf(sealUsage, "missing subcommand")
	}
	switch args[0] {
	case "new":
		return cmdSealNew(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, sealUsage)
		return nil
	default:
		return usageErrorf(sealUsage, "unknown subcommand 'seal %s'", args[0])
	}
}

func cmdSealNew(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("seal new", flag.ContinueOnError)
	min := fs.Uint("min", 0, "number of shards required to unseal (required)")
	total := fs.Uint("total", 0, "total number of shards (required)")
	usage := usageOf(fs, "Usage: symmecrypt seal new --min N --total N\n\nGenerate a new shamir seal. The seal config JSON is printed on stdout\n(redirect it to a file); the shards are printed on stderr, one per line.\n")

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}
	if *min == 0 || *total == 0 {
		return usageErrorf(usage, "--min and --total are required")
	}
	if *min > *total {
		return usageErrorf(usage, "--min (%d) cannot be greater than --total (%d)", *min, *total)
	}

	s, shards, err := seal.NewRandom(*min, *total)
	if err != nil {
		return err
	}

	cfg := struct {
		Min   uint   `json:"min"`
		Total uint   `json:"total"`
		Nonce string `json:"nonce"`
	}{Min: s.Min, Total: s.Total, Nonce: s.Nonce}
	j, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(j))

	fmt.Fprintf(stderr, "# seal shards (%d/%d needed to unseal) - shown ONCE, distribute them now:\n", *min, *total)
	for _, shard := range shards {
		fmt.Fprintln(stderr, shard)
	}
	return nil
}
