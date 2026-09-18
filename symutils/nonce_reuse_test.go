package symutils_test

import (
	"encoding/hex"
	"testing"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
)

const gcmNonceSize = 12

func nonceOfMarshaled(t *testing.T, s string) string {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < gcmNonceSize {
		t.Fatal("ciphertext too short")
	}
	return hex.EncodeToString(raw[:gcmNonceSize])
}

// TestSequenceKeyEncryptMarshalNoncesDiffer encodes the core AEAD safety
// requirement: two encryptions under the same sequence key must never reuse a
// nonce. Nonce reuse in AES-GCM leaks the XOR of plaintexts and allows
// forgeries, so this test failing means the cipher security is broken, not
// just a behavior change.
func TestSequenceKeyEncryptMarshalNoncesDiffer(t *testing.T) {
	f, err := symmecrypt.GetKeyFactory(aesgcm.CipherName)
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.NewRandomSequenceKey()
	if err != nil {
		t.Fatal(err)
	}

	c1, err := k.EncryptMarshal("payload one")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := k.EncryptMarshal("payload two")
	if err != nil {
		t.Fatal(err)
	}

	n1, n2 := nonceOfMarshaled(t, c1), nonceOfMarshaled(t, c2)
	if n1 == n2 {
		t.Fatalf("nonce reused across EncryptMarshal calls: %s", n1)
	}

	// mixing EncryptMarshal and Encrypt must not reuse a nonce either
	c3, err := k.Encrypt([]byte("payload three"))
	if err != nil {
		t.Fatal(err)
	}
	n3 := hex.EncodeToString(c3[:gcmNonceSize])
	if n3 == n1 || n3 == n2 {
		t.Fatalf("nonce reused between EncryptMarshal and Encrypt: %s", n3)
	}

	// the counter fix must not break decryption
	var out string
	if err := k.DecryptMarshal(c1, &out); err != nil {
		t.Fatal(err)
	}
	if out != "payload one" {
		t.Fatalf("unexpected plaintext %q", out)
	}
}
