package convergent_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovh/configstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aespmacsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/convergent"
	"github.com/ovh/symmecrypt/symutils"
)

func TestKeyFromHash(t *testing.T) {
	// Create a new content that we want to encrypt
	clearContent := make([]byte, 10*1024*1024)
	rand.Read(clearContent) // nolint

	// Get the hash to know if the content is already known and encrypted
	h, err := convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	baseSecretValue := symutils.MustRandomString(8)
	k, err := convergent.KeyFromHash(h, baseSecretValue, 32)
	require.NoError(t, err)

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

	t.Logf("hash=%s", h)

	_, has := mapHash[h]
	require.False(t, has) // At this point the content is unkonwn

	k, err := convergent.NewKey(h, cfgs...)
	require.NoError(t, err)
	require.NotNil(t, k)

	// We will encrypt the stuff
	dest := new(bytes.Buffer)
	err = k.EncryptPipe(bytes.NewReader(clearContent), dest)
	require.NoError(t, err)

	// Calculate a new locator from the sha512
	l, err := k.Locator()
	require.NoError(t, err)

	// Store the encrypted content
	mapEncryptedContent[l] = dest.Bytes()
	mapHash[h] = struct{}{}

	// Now simulated a new encryption from the same content, that should trigger deduplication
	// We start by getting the hash
	h, err = convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	_, has = mapHash[h]
	require.True(t, has) // This is the point of deduplication

	// Since the hash is known we must be able to retrieve the encrypted content from the locator
	l, err = k.Locator()
	require.NoError(t, err)
	encryptedContent, has := mapEncryptedContent[l]
	require.True(t, has)

	// The deduplication has been proven.
	// For fun, let's decrypt it
	dest = new(bytes.Buffer)
	err = k.DecryptPipe(bytes.NewReader(encryptedContent), dest)
	require.NoError(t, err)

	// Ensure the content is correctly decrypted
	require.EqualValues(t, clearContent, dest.Bytes())
}

func TestSequentialEncryption(t *testing.T) {
	var content = "this is a very sensitive content"

	// The key will be Instantiate from the sha152 of the content
	hash, err := convergent.NewHash(strings.NewReader(content))
	require.NoError(t, err)

	// Prepare a keyloadConfig to be able to Instantiate the key properly
	cfg := convergent.ConvergentEncryptionConfig{
		Cipher: aesgcm.CipherName,
	}

	// Instantiate a Sequence key from the sha512
	ck, err := convergent.NewKey(hash, cfg)
	require.NoError(t, err)
	k, err := ck.NewSequenceKey()
	require.NoError(t, err)
	require.NotNil(t, k)

	encryptedBuffer, err := k.Encrypt([]byte(content))
	require.NoError(t, err)

	// Due to the nonce, the same plain text with the same key won't be encrypted the same way
	encryptedBuffer2, err := k.Encrypt([]byte(content))
	require.NoError(t, err)
	require.NotEqual(t, encryptedBuffer, encryptedBuffer2)

	// But if we reinitialize the key, it will encrypt the plain text in a deterministic way
	k, err = convergent.NewKey(hash, cfg)
	require.NoError(t, err)
	require.NotNil(t, k)
	encryptedBuffer3, err := k.Encrypt([]byte(content))
	require.NoError(t, err)
	require.Equal(t, encryptedBuffer, encryptedBuffer3)

	// Checks that all decrypted contents
	decContent, err := k.Decrypt(encryptedBuffer)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	decContent, err = k.Decrypt(encryptedBuffer2)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	decContent, err = k.Decrypt(encryptedBuffer3)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	t.Run("key reinitialization from config", func(t *testing.T) {
		// Dump the key configuration to string
		cfgBtes, err := json.Marshal(cfg)
		require.NoError(t, err)
		t.Logf("deterministic key config is : %s", string(cfgBtes))

		var cfg2 convergent.ConvergentEncryptionConfig

		t.Log(string(cfgBtes))

		// Marshal it as a KeyConfig
		err = json.Unmarshal(cfgBtes, &cfg2)
		require.NoError(t, err)

		// Reload the key from its configuration
		k, err = convergent.NewKey(hash, cfg2)
		require.NoError(t, err)
		// check encrypt/decrypt
		encryptedBufferBis, err := k.Encrypt([]byte(content))
		require.NoError(t, err)
		decContent, err = k.Decrypt(encryptedBufferBis)
		require.NoError(t, err)
		require.Equal(t, content, string(decContent))
		// Check the deterministic nonce
		require.Equal(t, encryptedBuffer, encryptedBufferBis)
	})

	t.Run("with multiple config", func(t *testing.T) {
		cfg1 := convergent.ConvergentEncryptionConfig{
			Cipher:    aesgcm.CipherName,
			Timestamp: time.Now().Unix(),
		}

		k, err := convergent.NewKey(hash, cfg1)
		require.NoError(t, err)

		encryptedBuffer1, err := k.Encrypt([]byte(content))
		require.NoError(t, err)

		cfg1.Timestamp = time.Now().Add(-1 * time.Minute).Unix()
		cfg2 := convergent.ConvergentEncryptionConfig{
			Cipher:      aesgcm.CipherName,
			Timestamp:   time.Now().Unix(),
			SecretValue: "secret value",
		}

		k, err = convergent.NewKey(hash, cfg1, cfg2)
		require.NoError(t, err)

		encryptedBuffer2, err := k.Encrypt([]byte(content))
		require.NoError(t, err)

		// With the salt, the encyption should be equals to the encryption without salt
		require.NotEqual(t, encryptedBuffer1, encryptedBuffer2)

		k, err = convergent.NewKey(hash, cfg1, cfg2)
		require.NoError(t, err)

		decryptedContent, err := k.Decrypt(encryptedBuffer1)
		require.NoError(t, err)

		require.Equal(t, []byte(content), decryptedContent)
	})
}

func ProviderTest() (configstore.ItemList, error) {
	ret := configstore.ItemList{
		Items: []configstore.Item{
			configstore.NewItem(
				convergent.EncryptionKeyConfigName,
				`{"identifier":"test", "timestamp":1522325806,"cipher":"aes-gcm"}`,
				1,
			),
		},
	}
	return ret, nil
}

func TestLoadKeyFromStore(t *testing.T) {
	configstore.RegisterProvider("test", ProviderTest)
	k, err := convergent.LoadKey("38cd3c98c2d50fae7e3aba2f346cea9a8ff2e382145fc373fa79424ee3b9cdaa2c19c67332d1ff2132c8c9296acb74615100af4cc32eb97084095a33e4cd854b", "test")
	require.NoError(t, err)
	require.NotNil(t, k)
}

func TestDecryptFromHTTP(t *testing.T) {
	// Key config
	cfgs := []convergent.ConvergentEncryptionConfig{
		{
			Cipher:      aesgcm.CipherName,
			LocatorSalt: symutils.RandomSalt(),
			SecretValue: symutils.MustRandomString(10),
		},
	}

	// Encrypt a random content
	clearContent := make([]byte, 10*1024)
	rand.Read(clearContent) // nolint

	h, err := convergent.NewHash(bytes.NewReader(clearContent))
	require.NoError(t, err)

	k, err := convergent.NewKey(h, cfgs...)
	require.NoError(t, err)
	require.NotNil(t, k)

	dest := new(bytes.Buffer)
	err = k.EncryptPipe(bytes.NewReader(clearContent), dest)
	require.NoError(t, err)
	encryptedContent := dest.String()

	// Serve the encrypted content
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		io.WriteString(w, encryptedContent) //nolint
	}))
	defer ts.Close()

	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			res, err := http.Get(ts.URL)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)
			res.Body.Close()

			dest := new(bytes.Buffer)
			err = k.DecryptPipe(bytes.NewReader(body), dest)
			require.NoError(t, err)

			// Ensure the content is correctly decrypted
			assert.EqualValues(t, clearContent, dest.Bytes())
			wg.Done()
		}()
	}

	wg.Wait()
}
