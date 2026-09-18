package seal_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt/seal"
)

// sealedInstance rebuilds a sealed *Seal (shards not yet provided) matching
// the given generated seal, the way a process loads it from configuration.
func sealedInstance(t *testing.T, min, total uint, nonce string) *seal.Seal {
	t.Helper()
	cfg, err := json.Marshal(struct {
		Min   uint   `json:"min"`
		Total uint   `json:"total"`
		Nonce string `json:"nonce"`
	}{min, total, nonce})
	if err != nil {
		t.Fatal(err)
	}
	store := configstore.NewStore()
	store.InMemory("test").Add(configstore.NewItem(seal.ConfigName, string(cfg), 1))
	s, err := seal.NewSealFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("no seal loaded")
	}
	return s
}

// TestAddShardGarbageDoesNotBreakUnseal encodes the availability contract of
// the unseal ceremony: a malformed shard injected by anyone must not crash
// the process (sssa.Combine used to panic on mixed part counts) and must not
// prevent the legitimate shards from unsealing.
func TestAddShardGarbageDoesNotBreakUnseal(t *testing.T) {
	orig, shards, err := seal.NewRandom(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	// 88 base64 chars: passes sssa.IsValidShare but is not a real shard
	garbage := strings.Repeat("A", 88)
	if len(shards[0]) == len(garbage) {
		t.Fatal("test assumption broken: real shards must differ in length from the garbage shard")
	}

	s := sealedInstance(t, 3, 3, orig.Nonce)

	// the garbage shard may be stored or rejected; what matters is below
	_, _ = s.AddShard(garbage)

	unsealed := false
	for _, shard := range shards {
		ok, err := s.AddShard(shard)
		if err != nil {
			t.Fatalf("legitimate shard rejected: %v", err)
		}
		unsealed = unsealed || ok
	}
	if !unsealed {
		t.Fatal("seal not unsealed although all legitimate shards were provided")
	}
}

// TestAddShardRejectsEmptyShard: the empty string passes sssa.IsValidShare
// (len%88==0) but must never be stored nor count toward Min.
func TestAddShardRejectsEmptyShard(t *testing.T) {
	orig, _, err := seal.NewRandom(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	s := sealedInstance(t, 2, 2, orig.Nonce)
	if _, err := s.AddShard(""); err == nil {
		t.Fatal("expected an error adding an empty shard")
	}
}
