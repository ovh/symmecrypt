package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/seal"
)

// stringsFlag is a repeatable string flag.
type stringsFlag []string

func (s *stringsFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseKeyConfigs parses key configurations from raw data. It accepts either
// JSON key configs (one object per line) or a comma/newline-separated list of
// base64-encoded JSON key configs (the ENCRYPTION_KEY_BASE64 format).
func parseKeyConfigs(data []byte) ([]*keyloader.KeyConfig, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty key configuration")
	}

	var items []string
	if data[0] == '{' {
		items = strings.Split(string(data), "\n")
	} else {
		items = strings.FieldsFunc(string(data), func(r rune) bool { return r == ',' || r == '\n' })
	}

	var cfgs []*keyloader.KeyConfig
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		raw := []byte(item)
		if raw[0] != '{' {
			var err error
			raw, err = base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 key config: %w", err)
			}
		}
		cfg := &keyloader.KeyConfig{}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("invalid key config JSON: %w", err)
		}
		cfgs = append(cfgs, cfg)
	}
	if len(cfgs) == 0 {
		return nil, errors.New("empty key configuration")
	}
	return cfgs, nil
}

// keyConfigsFromStore loads key configurations from a configstore file
// (the documented `- key: encryption-key` / `value: '{...}'` format).
func keyConfigsFromStore(path string) ([]*keyloader.KeyConfig, error) {
	store := configstore.NewStore()
	store.File(path)

	items, err := keyloader.ConfigFilter.Store(store).GetItemList()
	if err != nil {
		return nil, fmt.Errorf("unable to read configstore file '%s': %w", path, err)
	}

	var cfgs []*keyloader.KeyConfig
	for _, item := range items.Items {
		i, err := item.Unmarshaled()
		if err != nil {
			return nil, fmt.Errorf("invalid key config in '%s': %w", path, err)
		}
		cfgs = append(cfgs, i.(*keyloader.KeyConfig))
	}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("no '%s' item found in configstore file '%s'", keyloader.EncryptionKeyConfigName, path)
	}
	return cfgs, nil
}

// loadKeyConfigs loads key configurations following the source precedence rules:
// --key-file and --config are mutually exclusive; without them, filter commands
// (stdinFallback=true) read stdin, while encrypt/decrypt read ENCRYPTION_KEY_BASE64.
func loadKeyConfigs(keyFile, configFile string, stdinFallback bool, stdin io.Reader) ([]*keyloader.KeyConfig, error) {
	if keyFile != "" && configFile != "" {
		return nil, errors.New("--key-file and --config are mutually exclusive")
	}

	switch {
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		return parseKeyConfigs(data)

	case configFile != "":
		return keyConfigsFromStore(configFile)

	case stdinFallback:
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		return parseKeyConfigs(data)

	default:
		env := os.Getenv(encryptionKeyEnv)
		if env == "" {
			return nil, fmt.Errorf("no encryption key: provide --key-file, --config or set %s", encryptionKeyEnv)
		}
		return parseKeyConfigs([]byte(env))
	}
}

// writeKeyConfigs writes key configurations as JSON lines, or as a single
// comma-separated line of base64-encoded items (ENCRYPTION_KEY_BASE64 format).
func writeKeyConfigs(w io.Writer, cfgs []*keyloader.KeyConfig, useBase64 bool) error {
	var items []string
	for _, cfg := range cfgs {
		j, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if useBase64 {
			items = append(items, base64.StdEncoding.EncodeToString(j))
		} else {
			items = append(items, string(j))
		}
	}
	sep := "\n"
	if useBase64 {
		sep = ","
	}
	_, err := fmt.Fprintln(w, strings.Join(items, sep))
	return err
}

// selectIdentifier keeps only the configs matching the given identifier.
// With an empty identifier, all configs must share the same one.
func selectIdentifier(cfgs []*keyloader.KeyConfig, identifier string) ([]*keyloader.KeyConfig, error) {
	byID := map[string][]*keyloader.KeyConfig{}
	var ids []string
	for _, cfg := range cfgs {
		if _, ok := byID[cfg.Identifier]; !ok {
			ids = append(ids, cfg.Identifier)
		}
		byID[cfg.Identifier] = append(byID[cfg.Identifier], cfg)
	}

	if identifier != "" {
		selected, ok := byID[identifier]
		if !ok {
			return nil, fmt.Errorf("encryption key '%s' not found", identifier)
		}
		return selected, nil
	}

	if len(ids) > 1 {
		return nil, fmt.Errorf("several encryption keys found (%s): select one with --key", strings.Join(ids, ", "))
	}
	return cfgs, nil
}

// loadSeal builds a *seal.Seal from a seal config file and unseals it with the
// shards provided directly (--shard) and/or read from files (--shard-file, one
// shard per line).
func loadSeal(sealFile string, shards, shardFiles []string) (*seal.Seal, error) {
	sealJSON, err := os.ReadFile(sealFile)
	if err != nil {
		return nil, err
	}

	// seal.Seal cannot be constructed as a literal from outside the package
	// (unexported shards map): go through a throwaway configstore instance.
	store := configstore.NewStore()
	store.InMemory("cli").Add(configstore.NewItem(seal.ConfigName, strings.TrimSpace(string(sealJSON)), 1))
	s, err := seal.NewSealFromStore(store)
	if err != nil {
		return nil, fmt.Errorf("invalid seal config '%s': %w", sealFile, err)
	}
	if s == nil {
		return nil, fmt.Errorf("invalid seal config '%s'", sealFile)
	}

	allShards := append([]string{}, shards...)
	for _, f := range shardFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			// skip blanks and comments so 'seal new 2>shards.txt' output is usable as-is
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				allShards = append(allShards, line)
			}
		}
	}

	for _, shard := range allShards {
		unsealed, err := s.AddShard(shard)
		if err != nil {
			return nil, fmt.Errorf("invalid seal shard: %w", err)
		}
		if unsealed {
			return s, nil
		}
	}
	return nil, fmt.Errorf("insufficient seal shards: %d provided, %d required", len(allShards), s.Min)
}

// unsealConfigs returns copies of the configs, unsealed with the given seal.
// The seal is required only if at least one config is sealed.
func unsealConfigs(cfgs []*keyloader.KeyConfig, sealFile string, shards, shardFiles []string) ([]*keyloader.KeyConfig, error) {
	sealed := false
	for _, cfg := range cfgs {
		if cfg.Sealed {
			sealed = true
			break
		}
	}
	if !sealed {
		return cfgs, nil
	}
	if sealFile == "" {
		return nil, errors.New("sealed key config: provide --seal-file and shards (--shard/--shard-file)")
	}
	s, err := loadSeal(sealFile, shards, shardFiles)
	if err != nil {
		return nil, err
	}

	out := make([]*keyloader.KeyConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		u, err := keyloader.UnsealKey(cfg, s)
		if err != nil {
			return nil, fmt.Errorf("unable to unseal key '%s': %w", cfg.Identifier, err)
		}
		out = append(out, u)
	}
	return out, nil
}

// openInput returns the payload source: stdin for "-", the file otherwise.
func openInput(path string, stdin io.Reader) (io.ReadCloser, error) {
	if path == "" || path == "-" {
		return io.NopCloser(stdin), nil
	}
	return os.Open(path)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// openOutput returns the payload destination: stdout for "-", the file otherwise.
func openOutput(path string, stdout io.Writer) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopWriteCloser{stdout}, nil
	}
	return os.Create(path)
}
