package convergent_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aespmacsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/convergent"
	"github.com/ovh/symmecrypt/symutils"
	"github.com/stretchr/testify/require"
)

func TestKeyFromHash(t *testing.T) {
	// Create a new content that we want to encrypt
	clearContent := make([]byte, 10*1024*1024)
	rand.Read(clearContent) // nolint

	// Get the hash to know if the content is already known and encrypted
	h, err := convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	baseSecretValue := symutils.MustRandomString(8)
	k := convergent.KeyFromHash(h, baseSecretValue, 32)

	kDec, err := hex.DecodeString(k)
	require.NoError(t, err)
	require.Len(t, kDec, 32) // Checks that the key has the required len
}

func TestConvergentEncryption(t *testing.T) {
	ciphers := []string{
		aesgcm.CipherName,
		aespmacsiv.CipherName,
		chacha20poly1305.CipherName,
		xchacha20poly1305.CipherName,
		hmac.CipherName,
	}
	for _, s := range ciphers {
		t.Run(s, func(t *testing.T) {
			runTest(t, s)
		})
	}
}

func runTest(t *testing.T, cipherName string) {
	// Test initialization
	cfgs := []convergent.ConvergentEncryptionConfig{
		{
			Cipher:      cipherName,
			LocatorSalt: symutils.RandomSalt(),
			SecretValue: symutils.MustRandomString(10),
		},
		{
			Cipher:      cipherName,
			LocatorSalt: symutils.RandomSalt(),
			SecretValue: symutils.MustRandomString(10),
		},
	}
	mapHash := make(map[string]struct{})           // Index of all known content (DB simulation)
	mapEncryptedContent := make(map[string][]byte) // Index of locator (FS simulation)

	// Create a new content that we want to encrypt
	clearContent := make([]byte, 10*1024*1024)
	rand.Read(clearContent) // nolint

	// Get the hash to know if the content is already known and encrypted
	h, err := convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	hs := hex.EncodeToString(h.Sum(nil))

	_, has := mapHash[hs]
	require.False(t, has) // At this point the content is unkonwn

	// We will encrypt the stuff
	dest := new(bytes.Buffer)
	err = convergent.EncryptTo(bytes.NewReader(clearContent), dest, h, cfgs)
	require.NoError(t, err)

	// Calculate a new locator from the sha512
	l, err := convergent.NewLocator(h, cfgs...)
	require.NoError(t, err)

	// Store the encrypted content
	mapEncryptedContent[l] = dest.Bytes()
	mapHash[hs] = struct{}{}

	// Now simulated a new encryption from the same content, that should trigger deduplication
	// We start by getting the hash
	h, err = convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	_, has = mapHash[hs]
	require.True(t, has) // This is the point of deduplication

	// Since the hash is known we must be able to retrieve the encrypted content the the locator
	l, err = convergent.NewLocator(h, cfgs...)
	require.NoError(t, err)
	encryptedContent, has := mapEncryptedContent[l]
	require.True(t, has)

	// The deduplication has been proven.
	// For fun, let's decrypt it
	dest = new(bytes.Buffer)
	err = convergent.DecryptTo(bytes.NewReader(encryptedContent), dest, h, cfgs)
	require.NoError(t, err)

	// Ensure the content is correctly decrypted
	require.EqualValues(t, clearContent, dest.Bytes())
}
