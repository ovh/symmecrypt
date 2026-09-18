package keyloader_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/seal"
)

// These tests encode the contract that a misconfigured sealed key must
// surface errors through the Key API instead of panicking in a background
// goroutine: a stale or foreign sealed key in the configuration must never
// be able to take down the whole process.

// mustSealedConfig returns a key config sealed with a throwaway seal that the
// process under test does NOT have.
func mustSealedConfig(t *testing.T, identifier string) *keyloader.KeyConfig {
	t.Helper()
	foreignSeal, _, err := seal.NewRandom(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := keyloader.GenerateKey("aes-gcm", identifier, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sealedCfg, err := keyloader.SealKey(cfg, foreignSeal)
	if err != nil {
		t.Fatal(err)
	}
	return sealedCfg
}

// Phase A: a sealed key config while NO seal is configured at all.
// Must run before phase B, which installs the global seal singleton.
func TestSealedKeyWithoutSealReturnsError(t *testing.T) {
	if seal.Exists() {
		t.Skip("global seal already configured by another test")
	}

	k, err := keyloader.NewKey(mustSealedConfig(t, "no-seal"))
	if err != nil {
		t.Fatal(err)
	}

	// Wait must return (not block forever), and the process must survive.
	done := make(chan struct{})
	go func() { k.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() blocked forever on an unusable sealed key")
	}

	if _, err := k.Encrypt([]byte("data")); err == nil {
		t.Fatal("expected an error encrypting with an unusable sealed key")
	}
}

// Phase B: a global seal is configured and unsealed, but the key was sealed
// with a DIFFERENT seal: unsealing it fails after WaitUnseal.
func TestSealedKeyWithWrongSealReturnsError(t *testing.T) {
	globalSeal, shards, err := seal.NewRandom(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	sealJSON, err := json.Marshal(struct {
		Min   uint   `json:"min"`
		Total uint   `json:"total"`
		Nonce string `json:"nonce"`
	}{1, 1, globalSeal.Nonce})
	if err != nil {
		t.Fatal(err)
	}

	store := configstore.NewStore()
	store.InMemory("test").Add(configstore.NewItem(seal.ConfigName, string(sealJSON), 1))
	if err := seal.InitFromStore(nil, store); err != nil {
		t.Fatal(err)
	}
	if unsealed, err := seal.Global().AddShard(shards[0]); err != nil || !unsealed {
		t.Fatalf("unable to unseal the global seal: unsealed=%t err=%v", unsealed, err)
	}

	k, err := keyloader.NewKey(mustSealedConfig(t, "wrong-seal"))
	if err != nil {
		t.Fatal(err)
	}
	k.Wait()

	_, err = k.Encrypt([]byte("data"))
	if err == nil {
		t.Fatal("expected an error encrypting with a key sealed by a foreign seal")
	}
	if !strings.Contains(err.Error(), "wrong-seal") {
		t.Fatalf("error should identify the key, got: %v", err)
	}
}
