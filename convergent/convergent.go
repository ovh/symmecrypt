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
	"hash"
	"io"
	"sort"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/stream"
	"golang.org/x/crypto/pbkdf2"
)

type ConvergentEncryptionConfig struct {
	Identifier  string `json:"identifier,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
	Cipher      string `json:"cipher"`
	LocatorSalt string `json:"localtor_salt"`
	SecretValue string `json:"secret_value"`
}

func LoadKeyFromConfig() (symmecrypt.Key, error) {
	return nil, nil
}

func NewKey(h hash.Hash, cfgs ...ConvergentEncryptionConfig) (symmecrypt.Key, error) {
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

		var key = KeyFromHash(h, cfg.SecretValue, factory.KeyLen())

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
func NewHash(r io.Reader) (hash.Hash, error) {
	hash := sha512.New()
	if _, err := io.Copy(hash, r); err != nil {
		return nil, err
	}
	return hash, nil
}

func KeyFromHash(h hash.Hash, secretValue string, keylen int) string {
	k := h.Sum([]byte(secretValue))[:keylen]
	return hex.EncodeToString(k)
}

// Locator returns the result of PBKDF2. PBKDF2 is a key derivation function
// https://en.wikipedia.org/wiki/PBKDF2
func Locator(s string, salt string) (string, error) {
	if len(salt) < 8 {
		return "", errors.New("at least 8 Bytes are recommanded for the salt")
	}
	return hex.EncodeToString(pbkdf2.Key([]byte(s), []byte(salt), 4096, 32, sha1.New)), nil
}

// MustLocator returns the result of PBKDF2. PBKDF2 is a key derivation function
// If the salt doesnt respect the PBKDF2 RFC, it will panic
func MustLocator(s string, salt string) string {
	l, err := Locator(s, salt)
	if err != nil {
		panic(err)
	}
	return l
}

func NewLocator(h hash.Hash, cfgs ...ConvergentEncryptionConfig) (string, error) {
	if len(cfgs) == 0 {
		return "", errors.New("locator salt configuration must be provided")
	}

	// sort by timestamp: latest (bigger timestamp) first
	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Timestamp > cfgs[j].Timestamp })
	sha512_256 := h.Sum(nil)
	s := hex.EncodeToString(sha512_256)
	l, err := Locator(s, cfgs[0].LocatorSalt)
	if err != nil {
		return "", err
	}
	return l, nil
}

const ChunkSize = 256 * 1024

func EncryptTo(r io.Reader, w io.Writer, h hash.Hash, cfgs []ConvergentEncryptionConfig, extra ...[]byte) error {
	k, err := NewKey(h, cfgs...)
	if err != nil {
		return err
	}
	wc := stream.NewWriter(w, k, ChunkSize, extra...)
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func DecryptTo(r io.Reader, w io.Writer, h hash.Hash, cfgs []ConvergentEncryptionConfig, extra ...[]byte) error {
	k, err := NewKey(h, cfgs...)
	if err != nil {
		return err
	}
	rc := stream.NewReader(r, k, ChunkSize, extra...)
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}
