// Package convergent handles convergent encryption, also known as content hash keying, it is a cryptosystem that produces identical ciphertext
// from identical plaintext files. This has applications in cloud computing to remove duplicate files from storage without the provider having access to the encryption keys.
// The combination of deduplication and convergent encryption was described in a backup system patent filed by Stac Electronics in 1995.
// Convergent encryption is open to a "confirmation of a file attack" in which an attacker can effectively confirm whether a target possesses
// a certain file by encrypting an unencrypted, or plain-text, version and then simply comparing the output with files possessed by the target.

package convergent

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/stream"
	"golang.org/x/crypto/pbkdf2"
)

type Key interface {
	symmecrypt.Key
	EncryptPipe(io.Reader, io.Writer, ...[]byte) error
	DecryptPipe(io.Reader, io.Writer, ...[]byte) error
	Locator() (string, error)
	NewSequenceKey() (symmecrypt.Key, error)
}

type key struct {
	Hash   string                       `json:"hash"`
	Config []ConvergentEncryptionConfig `json:"encryption_config"`
}

type ConvergentEncryptionConfig struct {
	Identifier  string `json:"identifier,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
	Cipher      string `json:"cipher"`
	LocatorSalt string `json:"localtor_salt,omitempty"`
	SecretValue string `json:"secret_value,omitempty"`
}

const ChunkSize = 256 * 1024

func (c key) EncryptPipe(r io.Reader, w io.Writer, extra ...[]byte) error {
	k, err := c.NewSequenceKey()
	if err != nil {
		return err
	}
	wc := stream.NewWriter(w, k, ChunkSize, extra...)
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func (c key) DecryptPipe(r io.Reader, w io.Writer, extra ...[]byte) error {
	k, err := c.NewSequenceKey()
	if err != nil {
		return err
	}
	rc := stream.NewReader(r, k, ChunkSize, extra...)
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}

func (c key) Locator() (string, error) {
	l, err := locator(c.Hash, c.Config[0].LocatorSalt)
	if err != nil {
		return "", err
	}
	return l, nil
}

func (c key) Encrypt(s []byte, extra ...[]byte) ([]byte, error) {
	k, err := c.NewSequenceKey()
	if err != nil {
		return nil, err
	}
	return k.Encrypt(s, extra...)
}

func (c key) Decrypt(s []byte, extra ...[]byte) ([]byte, error) {
	k, err := c.NewSequenceKey()
	if err != nil {
		return nil, err
	}
	return k.Decrypt(s, extra...)
}

func (c key) EncryptMarshal(i interface{}, extra ...[]byte) (string, error) {
	k, err := c.NewSequenceKey()
	if err != nil {
		return "", err
	}
	return k.EncryptMarshal(i, extra...)
}

func (c key) DecryptMarshal(s string, i interface{}, extra ...[]byte) error {
	k, err := c.NewSequenceKey()
	if err != nil {
		return err
	}
	return k.DecryptMarshal(s, i, extra...)
}

func (c key) Wait() {
	k, _ := c.NewSequenceKey()
	if k != nil {
		k.Wait()
	}
}

func (c key) String() (string, error) {
	k, err := c.NewSequenceKey()
	if err != nil {
		return "", err
	}
	return k.String()
}

func (c key) NewSequenceKey() (symmecrypt.Key, error) {
	return newSequenceKey(c.Hash, c.Config...)
}

// NewKey returns a convergent.Key object configured from a hash and number of ConvergentEncryptionConfig objects.
// If several ConvergentEncryptionConfig are supplied, the returned Key will be composite.
// A composite key encrypts with the latest Key (based on timestamp) and decrypts with any of they keys.
//
// The key cipher name is expected to match a KeyFactory that got registered through RegisterCipher().
// Either use a built-in cipher, or make sure to register a proper factory for this cipher.
// This KeyFactory will be called, either directly or when the symmecrypt/seal global singleton gets unsealed, if applicable.
func NewKey(hash string, cfgs ...ConvergentEncryptionConfig) (Key, error) {
	hbtes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	for i := range cfgs {
		cfg := &cfgs[i]
		factory, err := symmecrypt.GetKeyFactory(cfg.Cipher)
		if err != nil {
			return nil, fmt.Errorf("unable to get key factory: %w", err)
		}
		if factory.KeyLen() > len(hbtes) {
			return nil, errors.New("invalid hash size")
		}
	}

	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Timestamp > cfgs[j].Timestamp })

	return &key{
		Hash:   hash,
		Config: cfgs,
	}, nil
}

func configFactory() interface{} {
	return &ConvergentEncryptionConfig{}
}

// Helper to manipulate the configuration encryption keys by identifier
func rekeyConfigByIdentifier(s *configstore.Item) string {
	i, err := s.Unmarshaled()
	if err == nil {
		return i.(*ConvergentEncryptionConfig).Identifier
	}
	return ""
}

// Helper to sort the configuration encryption keys by timestamp
func reorderTimestamp(s *configstore.Item) int64 {
	i, err := s.Unmarshaled()
	if err == nil {
		ret := i.(*ConvergentEncryptionConfig).Timestamp
		return ret
	}
	return s.Priority()
}

var (
	EncryptionKeyConfigName = "convergent-encryption-key-config"
	// ConfigFilter is the configstore manipulation filter used to retrieve the encryption keys
	ConfigFilter = configstore.Filter().Slice(EncryptionKeyConfigName).Unmarshal(configFactory).Rekey(rekeyConfigByIdentifier).Reorder(reorderTimestamp)
)

// LoadKeyFromStore instantiates a new encryption key for a given identifier from a specific store instance.
// It retrieves all the necessary data from configstore then calls NewKey().
//
// If several keys are found for the identifier, they are sorted by timestamp, and a composite key is returned.
// The most recent key will be used for encryption, and decryption will be done by any of them.
// There needs to be _only one_ key with the highest priority for the identifier.
//
// If the key configuration specifies it is sealed, the key returned will be wrapped by an unseal mechanism.
// When the symmecrypt/seal global singleton gets unsealed, the key will become usable instantly. It will return errors in the meantime.
//
// The key cipher name is expected to match a KeyFactory that got registered through RegisterCipher().
// Either use a built-in cipher, or make sure to register a proper factory for this cipher.
// This KeyFactory will be called, either directly or when the symmecrypt/seal global singleton gets unsealed, if applicable.
func LoadKeyFromStore(hash, identifier string, store *configstore.Store) (Key, error) {
	items, err := ConfigFilter.Slice(identifier).Store(store).GetItemList()
	if err != nil {
		return nil, err
	}

	switch configstore.Filter().Squash().Apply(items).Len() {
	case 0:
		return nil, fmt.Errorf("encryption key '%s' not found", identifier)
	case 1: // OK, single key with highest prio
	default:
		return nil, fmt.Errorf("ambiguous config: several encryption keys conflicting for '%s'", identifier)
	}

	var cfgs []ConvergentEncryptionConfig
	for _, item := range items.Items {
		i, err := item.Unmarshaled()
		if err != nil {
			return nil, err
		}
		cfg := i.(*ConvergentEncryptionConfig)
		cfgs = append(cfgs, *cfg)
	}

	key, err := NewKey(hash, cfgs...)
	if err != nil {
		return nil, fmt.Errorf("encryption key '%s': %v", identifier, err)
	}

	return key, nil
}

// LoadKey instantiates a new encryption key for a given identifier from the default store in configstore.
// It retrieves all the necessary data from configstore then calls NewKey().
//
// If several keys are found for the identifier, they are sorted by timestamp, and a composite key is returned.
// The most recent key will be used for encryption, and decryption will be done by any of them.
// There needs to be _only one_ key with the highest priority for the identifier.
//
// If the key configuration specifies it is sealed, the key returned will be wrapped by an unseal mechanism.
// When the symmecrypt/seal global singleton gets unsealed, the key will become usable instantly. It will return errors in the meantime.
//
// The key cipher name is expected to match a KeyFactory that got registered through RegisterCipher().
// Either use a built-in cipher, or make sure to register a proper factory for this cipher.
// This KeyFactory will be called, either directly or when the symmecrypt/seal global singleton gets unsealed, if applicable.
func LoadKey(hash, identifier string) (Key, error) {
	return LoadKeyFromStore(hash, identifier, configstore.DefaultStore)
}

func newSequenceKey(h string, cfgs ...ConvergentEncryptionConfig) (symmecrypt.Key, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("missing key config")
	}

	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Timestamp > cfgs[j].Timestamp })

	var comp symmecrypt.CompositeKey
	for i := range cfgs {
		cfg := &cfgs[i]
		var ref symmecrypt.Key
		factory, err := symmecrypt.GetKeyFactory(cfg.Cipher)
		if err != nil {
			return nil, fmt.Errorf("unable to get key factory: %w", err)
		}

		key, err := KeyFromHash(h, cfg.SecretValue, factory.KeyLen())
		if err != nil {
			return nil, fmt.Errorf("unable to create new key: %w", err)
		}

		ref, err = factory.NewSequenceKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to create new key: %w", err)
		}
		comp = append(comp, ref)
	}

	// if only a single key config was provided, decapsulate the composite key
	if len(comp) == 1 {
		return comp[0], nil
	}

	return comp, nil
}

// NewHash reads the provided io.Reader and returns the sha512 hash
func NewHash(r io.Reader) (string, error) {
	hash := sha512.New()
	if _, err := io.Copy(hash, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func KeyFromHash(s string, secretValue string, keylen int) (string, error) {
	h := sha512.New()
	sbtes, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	_, _ = h.Write(sbtes)
	_, _ = h.Write([]byte(secretValue))
	k := h.Sum(nil)[:keylen]
	return hex.EncodeToString(k), nil
}

// Locator returns the result of PBKDF2. PBKDF2 is a key derivation function
// https://en.wikipedia.org/wiki/PBKDF2
func locator(s string, salt string) (string, error) {
	if len(salt) < 8 {
		return "", errors.New("at least 8 Bytes are recommanded for the salt")
	}
	return hex.EncodeToString(pbkdf2.Key([]byte(s), []byte(salt), 4096, 32, sha1.New)), nil
}
