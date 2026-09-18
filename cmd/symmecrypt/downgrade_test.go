package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/seal"
)

// These tests encode the keyring downgrade protection: keyloader.NewKey
// rejects a keyring where a non-sealed key outranks sealed keys (an attacker
// with write access to the key config source could append their own plain
// key with a newer timestamp and capture all new encryptions). Because the
// CLI unseals configs BEFORE calling NewKey, it must replicate that check on
// the original configs — otherwise the library never sees a sealed config.

func writeDowngradeFixtures(t *testing.T) (keyFile, sealFile, shard string) {
	t.Helper()
	s, shards, err := seal.NewRandom(1, 1)
	require.NoError(t, err)

	legit, err := keyloader.GenerateKey("aes-gcm", "prod", false, time.Now())
	require.NoError(t, err)
	sealedLegit, err := keyloader.SealKey(legit, s)
	require.NoError(t, err)

	// attacker-controlled key: not sealed, strictly newer timestamp
	attacker, err := keyloader.GenerateKey("aes-gcm", "prod", false, time.Now().Add(time.Hour))
	require.NoError(t, err)

	dir := t.TempDir()
	keyFile = filepath.Join(dir, "keyring.json")
	require.NoError(t, os.WriteFile(keyFile,
		[]byte(sealedLegit.String()+"\n"+attacker.String()+"\n"), 0600))

	sealJSON, err := json.Marshal(struct {
		Min   uint   `json:"min"`
		Total uint   `json:"total"`
		Nonce string `json:"nonce"`
	}{1, 1, s.Nonce})
	require.NoError(t, err)
	sealFile = filepath.Join(dir, "seal.json")
	require.NoError(t, os.WriteFile(sealFile, sealJSON, 0600))

	return keyFile, sealFile, shards[0]
}

func TestCryptRejectsSealedKeyDowngrade(t *testing.T) {
	keyFile, sealFile, shard := writeDowngradeFixtures(t)

	// the victim encrypts with their legitimate shards over the poisoned
	// keyring: the CLI must refuse instead of encrypting with the attacker key
	_, _, err := runCLI([]byte("secret"), "encrypt",
		"--key-file", keyFile, "--seal-file", sealFile, "--shard", shard)
	require.Error(t, err, "poisoned keyring accepted: new encryptions would use the attacker key")
	require.Contains(t, err.Error(), "downgrade")

	// decrypt goes through the same keyring construction: same rejection
	_, _, err = runCLI([]byte("whatever"), "decrypt",
		"--key-file", keyFile, "--seal-file", sealFile, "--shard", shard)
	require.Error(t, err)
	require.Contains(t, err.Error(), "downgrade")
}

// A sealed key with a newer timestamp than plain fallback keys is the
// legitimate rollover layout: it must keep working.
func TestCryptAcceptsSealedKeyOutrankingPlainKeys(t *testing.T) {
	s, shards, err := seal.NewRandom(1, 1)
	require.NoError(t, err)

	older, err := keyloader.GenerateKey("aes-gcm", "prod", false, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	newer, err := keyloader.GenerateKey("aes-gcm", "prod", false, time.Now())
	require.NoError(t, err)
	sealedNewer, err := keyloader.SealKey(newer, s)
	require.NoError(t, err)

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keyring.json")
	require.NoError(t, os.WriteFile(keyFile,
		[]byte(sealedNewer.String()+"\n"+older.String()+"\n"), 0600))
	sealJSON := fmt.Sprintf(`{"min":1,"total":1,"nonce":"%s"}`, s.Nonce)
	sealFile := filepath.Join(dir, "seal.json")
	require.NoError(t, os.WriteFile(sealFile, []byte(sealJSON), 0600))

	encrypted, _, err := runCLI([]byte("secret"), "encrypt",
		"--key-file", keyFile, "--seal-file", sealFile, "--shard", shards[0])
	require.NoError(t, err)

	decrypted, _, err := runCLI([]byte(encrypted), "decrypt",
		"--key-file", keyFile, "--seal-file", sealFile, "--shard", shards[0])
	require.NoError(t, err)
	require.Equal(t, "secret", decrypted)
}
