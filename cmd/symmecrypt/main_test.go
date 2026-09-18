package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ovh/symmecrypt/keyloader"
)

// runCLI runs the CLI in-process and returns stdout, stderr and the error.
func runCLI(stdin []byte, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := run(args, bytes.NewReader(stdin), &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestKeyNewEncryptDecryptRoundtrip(t *testing.T) {
	keyOut, _, err := runCLI(nil, "key", "new", "--cipher", "aes-gcm", "--identifier", "test")
	require.NoError(t, err)
	require.Contains(t, keyOut, `"cipher":"aes-gcm"`)

	keyFile := filepath.Join(t.TempDir(), "key.json")
	require.NoError(t, os.WriteFile(keyFile, []byte(keyOut), 0600))

	encrypted, _, err := runCLI([]byte("foobar"), "encrypt", "--key-file", keyFile, "--extra", "aa", "--extra", "bb")
	require.NoError(t, err)

	decrypted, _, err := runCLI([]byte(encrypted), "decrypt", "--key-file", keyFile, "--extra", "aa", "--extra", "bb")
	require.NoError(t, err)
	require.Equal(t, "foobar", decrypted)

	// wrong extra data must fail authentication
	_, _, err = runCLI([]byte(encrypted), "decrypt", "--key-file", keyFile, "--extra", "wrong")
	require.Error(t, err)
}

func TestEncryptDecryptEnvBase64(t *testing.T) {
	keyOut, _, err := runCLI(nil, "key", "new", "--base64")
	require.NoError(t, err)
	t.Setenv(encryptionKeyEnv, strings.TrimSpace(keyOut))

	encrypted, _, err := runCLI([]byte("hello"), "encrypt", "--base64")
	require.NoError(t, err)

	decrypted, _, err := runCLI([]byte(encrypted), "decrypt", "--base64")
	require.NoError(t, err)
	require.Equal(t, "hello", decrypted)
}

func TestConfigstoreRoundtrip(t *testing.T) {
	keyOut, _, err := runCLI(nil, "key", "new", "--identifier", "storage")
	require.NoError(t, err)

	configFile := filepath.Join(t.TempDir(), "config.yml")
	content := fmt.Sprintf("- key: %s\n  value: '%s'\n", keyloader.EncryptionKeyConfigName, strings.TrimSpace(keyOut))
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	encrypted, _, err := runCLI([]byte("via configstore"), "encrypt", "--config", configFile)
	require.NoError(t, err)

	decrypted, _, err := runCLI([]byte(encrypted), "decrypt", "--config", configFile, "--key", "storage")
	require.NoError(t, err)
	require.Equal(t, "via configstore", decrypted)
}

func TestStreamRoundtrip(t *testing.T) {
	keyOut, _, err := runCLI(nil, "key", "new")
	require.NoError(t, err)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.json")
	require.NoError(t, os.WriteFile(keyFile, []byte(keyOut), 0600))

	// more than 2 chunks (256KiB each)
	clear := make([]byte, 600*1024)
	_, err = rand.Read(clear)
	require.NoError(t, err)
	inFile := filepath.Join(dir, "clear.bin")
	encFile := filepath.Join(dir, "enc.bin")
	decFile := filepath.Join(dir, "dec.bin")
	require.NoError(t, os.WriteFile(inFile, clear, 0600))

	_, _, err = runCLI(nil, "encrypt", "--stream", "--key-file", keyFile, "--in", inFile, "--out", encFile)
	require.NoError(t, err)

	_, _, err = runCLI(nil, "decrypt", "--stream", "--key-file", keyFile, "--in", encFile, "--out", decFile)
	require.NoError(t, err)

	decrypted, err := os.ReadFile(decFile)
	require.NoError(t, err)
	require.True(t, bytes.Equal(clear, decrypted))

	// the stream format is not compatible with the plain format
	_, _, err = runCLI(nil, "decrypt", "--key-file", keyFile, "--in", encFile, "--out", filepath.Join(dir, "bogus.bin"))
	require.Error(t, err)
}

func TestSealCeremony(t *testing.T) {
	sealOut, sealShards, err := runCLI(nil, "seal", "new", "--min", "2", "--total", "3")
	require.NoError(t, err)
	dir := t.TempDir()
	sealFile := filepath.Join(dir, "seal.json")
	require.NoError(t, os.WriteFile(sealFile, []byte(sealOut), 0600))

	var shards []string
	for _, line := range strings.Split(sealShards, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			shards = append(shards, line)
		}
	}
	require.Len(t, shards, 3)

	keyOut, _, err := runCLI(nil, "key", "new", "--identifier", "sealed-test")
	require.NoError(t, err)
	origCfg := &keyloader.KeyConfig{}
	require.NoError(t, json.Unmarshal([]byte(keyOut), origCfg))

	// seal with 2 shards out of 3
	sealedOut, _, err := runCLI([]byte(keyOut), "key", "seal", "--seal-file", sealFile, "--shard", shards[0], "--shard", shards[2])
	require.NoError(t, err)
	sealedCfg := &keyloader.KeyConfig{}
	require.NoError(t, json.Unmarshal([]byte(sealedOut), sealedCfg))
	require.True(t, sealedCfg.Sealed)
	require.NotEqual(t, origCfg.Key, sealedCfg.Key)

	// inspect never prints key material
	inspectOut, _, err := runCLI([]byte(sealedOut), "key", "inspect")
	require.NoError(t, err)
	require.Contains(t, inspectOut, "sealed-test")
	require.Contains(t, inspectOut, "true")
	require.NotContains(t, inspectOut, sealedCfg.Key)
	require.NotContains(t, inspectOut, origCfg.Key)

	// unseal restores the original key material (all 3 shards: the unseal loop
	// must stop at the first success instead of erroring on extra shards)
	unsealedOut, _, err := runCLI([]byte(sealedOut), "key", "unseal", "--seal-file", sealFile,
		"--shard", shards[0], "--shard", shards[1], "--shard", shards[2])
	require.NoError(t, err)
	unsealedCfg := &keyloader.KeyConfig{}
	require.NoError(t, json.Unmarshal([]byte(unsealedOut), unsealedCfg))
	require.Equal(t, origCfg.Key, unsealedCfg.Key)

	// encrypt/decrypt directly with the sealed config and shards
	sealedKeyFile := filepath.Join(dir, "sealed.key")
	require.NoError(t, os.WriteFile(sealedKeyFile, []byte(sealedOut), 0600))
	encrypted, _, err := runCLI([]byte("secret"), "encrypt", "--key-file", sealedKeyFile,
		"--seal-file", sealFile, "--shard", shards[1], "--shard", shards[2])
	require.NoError(t, err)
	decrypted, _, err := runCLI([]byte(encrypted), "decrypt", "--key-file", sealedKeyFile,
		"--seal-file", sealFile, "--shard", shards[0], "--shard", shards[1])
	require.NoError(t, err)
	require.Equal(t, "secret", decrypted)

	// insufficient shards
	_, _, err = runCLI([]byte(keyOut), "key", "seal", "--seal-file", sealFile, "--shard", shards[0])
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient")
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"bogus"},
		{"key"},
		{"key", "bogus"},
		{"seal"},
		{"key", "new", "--cipher", "bogus"},
		{},
	} {
		_, _, err := runCLI(nil, args...)
		var uErr usageError
		require.Error(t, err, "args: %v", args)
		require.True(t, errors.As(err, &uErr), "expected usageError for args %v, got %T: %v", args, err, err)
	}
}
