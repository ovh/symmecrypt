package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ovh/symmecrypt/keyloader"
)

const keyUsage = `Usage: symmecrypt key <subcommand> [flags]

Subcommands:
  new       generate a new random encryption key config
  rotate    add a new revision to an existing key (key rollover)
  inspect   show key config metadata (never prints key material)
  seal      seal key config(s) with a shamir seal
  unseal    unseal key config(s)

Key configs are read from --key-file, --config (configstore file) or stdin.
`

// usageOf renders a command synopsis followed by its flag defaults.
func usageOf(fs *flag.FlagSet, synopsis string) string {
	var b strings.Builder
	b.WriteString(synopsis)
	b.WriteString("\nFlags:\n")
	fs.SetOutput(&b)
	fs.PrintDefaults()
	return b.String()
}

// parseFlags parses args, mapping flag errors to the CLI error conventions:
// -h/--help prints the usage on stdout, misuse becomes a usageError (exit 2).
func parseFlags(fs *flag.FlagSet, usage string, args []string, stdout io.Writer) error {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return flag.ErrHelp
		}
		return usageErrorf(usage, "%v", err)
	}
	if fs.NArg() > 0 {
		return usageErrorf(usage, "unexpected argument '%s'", fs.Arg(0))
	}
	return nil
}

func validateCipher(name string) error {
	for _, c := range ciphers {
		if c == name {
			return nil
		}
	}
	return fmt.Errorf("unknown cipher '%s' (available: %s)", name, joinCiphers())
}

func cmdKey(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErrorf(keyUsage, "missing subcommand")
	}
	switch args[0] {
	case "new":
		return cmdKeyNew(args[1:], stdout)
	case "rotate":
		return cmdKeyRotate(args[1:], stdin, stdout)
	case "inspect":
		return cmdKeyInspect(args[1:], stdin, stdout)
	case "seal":
		return cmdKeySealUnseal(true, args[1:], stdin, stdout)
	case "unseal":
		return cmdKeySealUnseal(false, args[1:], stdin, stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, keyUsage)
		return nil
	default:
		return usageErrorf(keyUsage, "unknown subcommand 'key %s'", args[0])
	}
}

func cmdKeyNew(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("key new", flag.ContinueOnError)
	cipher := fs.String("cipher", keyloader.DefaultCipher, "cipher of the key")
	identifier := fs.String("identifier", "default", "key identifier")
	useBase64 := fs.Bool("base64", false, "output as a base64 item ready for "+encryptionKeyEnv)
	usage := usageOf(fs, "Usage: symmecrypt key new [flags]\n\nGenerate a new random encryption key config (JSON on stdout).\n")

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}
	if err := validateCipher(*cipher); err != nil {
		return usageErrorf(usage, "%v", err)
	}

	cfg, err := keyloader.GenerateKey(*cipher, *identifier, false, time.Now())
	if err != nil {
		return err
	}
	return writeKeyConfigs(stdout, []*keyloader.KeyConfig{cfg}, *useBase64)
}

func cmdKeyRotate(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	identifier := fs.String("identifier", "", "identifier of the key to rotate (required if several identifiers are present)")
	cipher := fs.String("cipher", "", "cipher of the new revision (default: cipher of the latest revision)")
	keyFile := fs.String("key-file", "", "read key configs from this file instead of stdin")
	configFile := fs.String("config", "", "read key configs from this configstore file instead of stdin")
	useBase64 := fs.Bool("base64", false, "output all configs as one comma-separated base64 line")
	sealFile := fs.String("seal-file", "", "seal config file (required if the latest revision is sealed)")
	var shards, shardFiles stringsFlag
	fs.Var(&shards, "shard", "seal shard (repeatable)")
	fs.Var(&shardFiles, "shard-file", "file containing seal shards, one per line (repeatable)")
	usage := usageOf(fs, "Usage: symmecrypt key rotate [flags]\n\nEmit the existing key config(s) plus a new revision (same identifier,\nstrictly newer timestamp). The new revision comes first.\n")

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}
	if *cipher != "" {
		if err := validateCipher(*cipher); err != nil {
			return usageErrorf(usage, "%v", err)
		}
	}

	cfgs, err := loadKeyConfigs(*keyFile, *configFile, true, stdin)
	if err != nil {
		return err
	}
	selected, err := selectIdentifier(cfgs, *identifier)
	if err != nil {
		return err
	}

	latest := selected[0]
	for _, cfg := range selected[1:] {
		if cfg.Timestamp > latest.Timestamp {
			latest = cfg
		}
	}

	newCipher := *cipher
	if newCipher == "" {
		newCipher = latest.Cipher
	}
	newTimestamp := time.Now().Unix()
	if newTimestamp <= latest.Timestamp {
		newTimestamp = latest.Timestamp + 1
	}

	newCfg, err := keyloader.GenerateKey(newCipher, latest.Identifier, false, time.Unix(newTimestamp, 0))
	if err != nil {
		return err
	}

	// A sealed key must be rotated to another sealed revision, otherwise the
	// keyring downgrade detection of keyloader.NewKey rejects the whole set.
	if latest.Sealed {
		if *sealFile == "" {
			return errors.New("latest revision is sealed: provide --seal-file and shards to seal the new revision")
		}
		s, err := loadSeal(*sealFile, shards, shardFiles)
		if err != nil {
			return err
		}
		newCfg, err = keyloader.SealKey(newCfg, s)
		if err != nil {
			return err
		}
	}

	out := append([]*keyloader.KeyConfig{newCfg}, cfgs...)
	return writeKeyConfigs(stdout, out, *useBase64)
}

func cmdKeyInspect(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("key inspect", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "read key configs from this file instead of stdin")
	configFile := fs.String("config", "", "read key configs from this configstore file instead of stdin")
	usage := usageOf(fs, "Usage: symmecrypt key inspect [flags]\n\nPrint key config metadata. The key material is never printed.\n")

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}

	cfgs, err := loadKeyConfigs(*keyFile, *configFile, true, stdin)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IDENTIFIER\tCIPHER\tTIMESTAMP\tSEALED")
	for _, cfg := range cfgs {
		ts := "-"
		if cfg.Timestamp != 0 {
			ts = time.Unix(cfg.Timestamp, 0).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%t\n", cfg.Identifier, cfg.Cipher, ts, cfg.Sealed)
	}
	return w.Flush()
}

func cmdKeySealUnseal(sealing bool, args []string, stdin io.Reader, stdout io.Writer) error {
	name, verb := "key seal", "Seal"
	if !sealing {
		name, verb = "key unseal", "Unseal"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	sealFile := fs.String("seal-file", "", "seal config file (required)")
	var shards, shardFiles stringsFlag
	fs.Var(&shards, "shard", "seal shard (repeatable)")
	fs.Var(&shardFiles, "shard-file", "file containing seal shards, one per line (repeatable)")
	keyFile := fs.String("key-file", "", "read key configs from this file instead of stdin")
	configFile := fs.String("config", "", "read key configs from this configstore file instead of stdin")
	useBase64 := fs.Bool("base64", false, "output all configs as one comma-separated base64 line")
	usage := usageOf(fs, fmt.Sprintf("Usage: symmecrypt %s [flags]\n\n%s key config(s) with a shamir seal.\n", name, verb))

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}
	if *sealFile == "" {
		return usageErrorf(usage, "--seal-file is required")
	}

	s, err := loadSeal(*sealFile, shards, shardFiles)
	if err != nil {
		return err
	}
	cfgs, err := loadKeyConfigs(*keyFile, *configFile, true, stdin)
	if err != nil {
		return err
	}

	out := make([]*keyloader.KeyConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		var res *keyloader.KeyConfig
		if sealing {
			res, err = keyloader.SealKey(cfg, s)
		} else {
			res, err = keyloader.UnsealKey(cfg, s)
		}
		if err != nil {
			return fmt.Errorf("unable to %s key '%s': %w", strings.ToLower(verb), cfg.Identifier, err)
		}
		out = append(out, res)
	}
	return writeKeyConfigs(stdout, out, *useBase64)
}
