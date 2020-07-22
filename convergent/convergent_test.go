package convergent_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/convergent"
	"github.com/ovh/symmecrypt/deterministic"
	"github.com/ovh/symmecrypt/symutils"
	"github.com/stretchr/testify/require"
)

func TestConvergentEncryption(t *testing.T) {
	// Test initialization
	locatorCfg := []deterministic.SaltConfig{
		{
			Value: symutils.RandomSalt(),
		},
	}
	keyCfg := []deterministic.KeyConfig{
		{
			Cipher: aesgcm.CipherName,
			Salt: []deterministic.SaltConfig{
				{
					Value: symutils.RandomSalt(),
				},
			},
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

	_, has := mapHash[h]
	require.False(t, has) // At this point the content is unkonwn

	// We will encrypt the stuff
	dest := new(bytes.Buffer)
	err = convergent.EncryptTo(bytes.NewReader(clearContent), dest, h, keyCfg)
	require.NoError(t, err)

	// Calculate a new locator from the sha512
	l, err := convergent.NewLocator(h, locatorCfg)
	require.NoError(t, err)

	// Store the encrypted content
	mapEncryptedContent[l] = dest.Bytes()
	mapHash[h] = struct{}{}

	// Now simulated a new encryption from the same content, that should trigger dedupliation
	// We start by getting the hash
	h, err = convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	_, has = mapHash[h]
	require.True(t, has) // This is the point of deduplication

	// Since the hash is known we must be able to retrieve the encrypted content the the locator
	l, err = convergent.NewLocator(h, locatorCfg)
	require.NoError(t, err)
	encryptedContent, has := mapEncryptedContent[l]
	require.True(t, has)

	// The deduplication has been proven.
	// For fun, let's decrypt it
	dest = new(bytes.Buffer)
	err = convergent.DecryptTo(bytes.NewReader(encryptedContent), dest, h, keyCfg)
	require.NoError(t, err)

	// Ensure the content is correctly descrypted
	require.EqualValues(t, clearContent, dest.Bytes())
}
