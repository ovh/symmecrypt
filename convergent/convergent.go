// Package convergent handles convergent encryption, also known as content hash keying, is a cryptosystem that produces identical ciphertext
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
	"io"
	"sort"

	"github.com/ovh/symmecrypt/deterministic"
	"github.com/ovh/symmecrypt/stream"
	"golang.org/x/crypto/pbkdf2"
)

func NewHash(r io.Reader) (string, error) {
	hash := sha512.New512_256()
	if _, err := io.Copy(hash, r); err != nil {
		return "", nil
	}
	sha512 := hex.EncodeToString(hash.Sum(nil))
	return sha512, nil
}

// Locator returns the result of PBKDF2. PBKDF2 is a key derivation function
// https://en.wikipedia.org/wiki/PBKDF2
func locator(s string, salt string) (string, error) {
	if len(salt) < 8 {
		return "", errors.New("at least 8 Bytes are recommanded for the salt")
	}
	return hex.EncodeToString(pbkdf2.Key([]byte(s), []byte(salt), 4096, 32, sha1.New)), nil
}

// MustLocator returns the result of PBKDF2. PBKDF2 is a key derivation function
// If the salt doesnt respect the PBKDF2 RFC, it will panic
func MustLocator(s string, salt string) string {
	l, err := locator(s, salt)
	if err != nil {
		panic(err)
	}
	return l
}

func NewLocator(s string, cfgs []deterministic.SaltConfig) (string, error) {
	if len(cfgs) == 0 {
		return "", errors.New("locator salt configuration must be provided")
	}

	// sort by timestamp: latest (bigger timestamp) first
	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Timestamp > cfgs[j].Timestamp })
	l, err := locator(s, cfgs[0].Value)
	if err != nil {
		return "", err
	}
	return l, nil
}

const ChunkSize = 256 * 1024

func EncryptTo(r io.Reader, w io.Writer, sha512 string, cfgs []deterministic.KeyConfig, extra ...[]byte) error {
	k, err := deterministic.NewKey(sha512, cfgs...)
	if err != nil {
		return err
	}
	wc := stream.NewWriter(w, k, ChunkSize, extra...)
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func DecryptTo(r io.Reader, w io.Writer, sha512 string, cfgs []deterministic.KeyConfig, extra ...[]byte) error {
	k, err := deterministic.NewKey(sha512, cfgs...)
	if err != nil {
		return err
	}
	rc := stream.NewReader(r, k, ChunkSize, extra...)
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}
