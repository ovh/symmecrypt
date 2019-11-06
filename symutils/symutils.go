package symutils

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/ovh/symmecrypt"
)

/*
** MISC
 */

// RawKey accepts either a raw byte array of len keyLen, or a hex-encoded representation of len keyLen*2.
// It always returns an array of raw bytes of len keyLen.
func RawKey(b []byte, keyLen int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty encryption key")
	}
	if len(b) == hex.EncodedLen(keyLen) {
		// Hex representation? decode it
		b2 := make([]byte, hex.DecodedLen(len(b)))
		_, err := hex.Decode(b2, b)
		if err != nil {
			return nil, fmt.Errorf("encryption key is too long, but is not a valid hex encoded string: %s", err)
		}
		b = b2
	} else if len(b) == base64.StdEncoding.EncodedLen(keyLen) {
		// base64 representation? decode it!
		b2 := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
		n, err := base64.StdEncoding.Decode(b2, b)
		if err != nil {
			return nil, fmt.Errorf("encryption key is too long, but is not a valid base64 encoded string: %s", err)
		}
		b = b2[:n] // n may be smaller than DecodedLen(len(b)) because of base64 padding
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("encryption key: incorrect length: expected %d, got %d", keyLen, len(b))
	}
	return b, nil
}

// Random returns a random array of raw bytes of len keyLen.
func Random(keyLen int) ([]byte, error) {
	b := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

/*
** AEAD
 */

type factoryAEAD struct {
	cipherFactory func([]byte) (cipher.AEAD, error)
	keyLen        int
	mutex         bool
}

// NewFactoryAEAD returns a symmecrypt.KeyFactory that can be registered to symmecrypt.RegisterCipher.
// It accepts a key length and a function that returns a cipher.AEAD.
// This allows very easy symmecrypt implementations of any cipher that respects the AEAD interface.
func NewFactoryAEAD(keyLen int, cipherFactory func([]byte) (cipher.AEAD, error)) symmecrypt.KeyFactory {
	return &factoryAEAD{keyLen: keyLen, cipherFactory: cipherFactory}
}

func NewFactoryAEADMutex(keyLen int, cipherFactory func([]byte) (cipher.AEAD, error)) symmecrypt.KeyFactory {
	return &factoryAEAD{keyLen: keyLen, cipherFactory: cipherFactory, mutex: true}
}

func (f *factoryAEAD) NewKey(s string) (symmecrypt.Key, error) {
	k, err := NewKeyAEAD([]byte(s), f.keyLen, f.cipherFactory)
	if err != nil {
		return nil, err
	}
	if f.mutex {
		k = &KeyMutex{Key: k}
	}
	return k, nil
}

func (f *factoryAEAD) NewRandomKey() (symmecrypt.Key, error) {
	k, err := NewRandomKeyAEAD(f.keyLen, f.cipherFactory)
	if err != nil {
		return nil, err
	}
	if f.mutex {
		k = &KeyMutex{Key: k}
	}
	return k, nil
}

func RandomSalt() []byte {
	var buff = make([]byte, 8)
	rand.Read(buff) // nolint
	return buff
}

func (f *factoryAEAD) NewSequentialKey(s string, salt ...byte) (symmecrypt.Key, error) {
	btes, err := RawKey([]byte(s), f.keyLen)
	if err != nil {
		return nil, err
	}
	k, err := f.NewKey(string(btes))
	if err != nil {
		return nil, err
	}
	km := &KeyMutex{
		Key: &KeySequential{
			k:    k.(*KeyAEAD),
			salt: salt,
		},
	}
	return km, nil
}

// KeyAEAD is a base implementation of a symmecrypt key that uses AEAD ciphers.
// It transforms any AEAD cipher factory into a full-fledged symmecrypt key implementation.
type KeyAEAD struct {
	key           []byte
	cipherFactory func([]byte) (cipher.AEAD, error)
}

// NewKeyAEAD needs the key representation (raw or hex), desired length, and an AEAD cipher factory.
func NewKeyAEAD(rawkey []byte, keyLen int, factory func([]byte) (cipher.AEAD, error)) (symmecrypt.Key, error) {
	raw, err := RawKey(rawkey, keyLen)
	if err != nil {
		return nil, err
	}
	return &KeyAEAD{key: raw, cipherFactory: factory}, nil
}

// NewRandomKeyAEAD needs the desired key length, and an AEAD cipher factory.
func NewRandomKeyAEAD(keyLen int, factory func([]byte) (cipher.AEAD, error)) (symmecrypt.Key, error) {
	b, err := Random(keyLen)
	if err != nil {
		return nil, err
	}
	return NewKeyAEAD(b, keyLen, factory)
}

// Encrypt arbitrary data. Extra data can be passed for MAC.
func (b KeyAEAD) Encrypt(text []byte, extra ...[]byte) ([]byte, error) {
	ciph, err := b.cipherFactory(b.key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, ciph.NonceSize(), ciph.NonceSize()+ciph.Overhead()+len(text)) // Extra capacity to append ciphertext without realloc
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	var extraData []byte
	for _, e := range extra {
		extraData = append(extraData, e...)
	}

	ciphertext := ciph.Seal(nil, nonce, text, extraData)

	return append(nonce, ciphertext...), nil
}

// Decrypt arbitrary data. Extra data can be passed for MAC.
func (b KeyAEAD) Decrypt(text []byte, extra ...[]byte) ([]byte, error) {
	ciph, err := b.cipherFactory(b.key)
	if err != nil {
		return nil, err
	}

	if len(text) < ciph.NonceSize() {
		return nil, errors.New("ciphered text too short")
	}

	nonce := text[:ciph.NonceSize()]
	ciphertext := text[ciph.NonceSize():]

	var extraData []byte
	for _, e := range extra {
		extraData = append(extraData, e...)
	}

	plaintext, err := ciph.Open(nil, nonce, ciphertext, extraData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptMarshal encrypts the marshaled representation of an arbitrary object. Extra data can be passed for MAC.
func (b KeyAEAD) EncryptMarshal(i interface{}, extra ...[]byte) (string, error) {
	serialized, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	ciphered, err := b.Encrypt(serialized, extra...)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciphered), nil
}

// DecryptMarshal decrypts the marshaled representation of an arbitrary object. Extra data can be passed for MAC.
func (b KeyAEAD) DecryptMarshal(s string, target interface{}, extra ...[]byte) error {
	data, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	unciphered, err := b.Decrypt(data, extra...)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(unciphered))
	dec.UseNumber()
	return dec.Decode(target)
}

// Wait is a noop for regular implementations: the key is always ready
func (b KeyAEAD) Wait() {
}

// String returns a hex encoded representation of the key
func (b KeyAEAD) String() (string, error) {
	return hex.EncodeToString(b.key), nil
}

// KeyMutex wraps a symmecrypt Key with a mutex to protect unsafe concurrent implementations
type KeyMutex struct {
	Key symmecrypt.Key
	mut sync.Mutex
}

func (k *KeyMutex) Encrypt(text []byte, extra ...[]byte) ([]byte, error) {
	k.mut.Lock()
	defer k.mut.Unlock()

	return k.Key.Encrypt(text, extra...)
}

func (k *KeyMutex) Decrypt(text []byte, extra ...[]byte) ([]byte, error) {
	k.mut.Lock()
	defer k.mut.Unlock()

	return k.Key.Decrypt(text, extra...)
}

func (k *KeyMutex) EncryptMarshal(i interface{}, extra ...[]byte) (string, error) {
	k.mut.Lock()
	defer k.mut.Unlock()

	return k.Key.EncryptMarshal(i, extra...)
}

func (k *KeyMutex) DecryptMarshal(s string, target interface{}, extra ...[]byte) error {
	k.mut.Lock()
	defer k.mut.Unlock()

	return k.Key.DecryptMarshal(s, target, extra...)
}

func (k *KeyMutex) Wait() {
	k.mut.Lock()
	defer k.mut.Unlock()

	k.Key.Wait()
}

func (k *KeyMutex) String() (string, error) {
	k.mut.Lock()
	defer k.mut.Unlock()

	return k.Key.String()
}

type KeySequential struct {
	k       *KeyAEAD
	counter uint32
	salt    []byte
}

func (k *KeySequential) incrementCounter() {
	k.counter++
}

func (k *KeySequential) Encrypt(t []byte, extras ...[]byte) ([]byte, error) {
	defer k.incrementCounter()

	ciph, err := k.k.cipherFactory(k.k.key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, ciph.NonceSize(), ciph.NonceSize()+ciph.Overhead()+len(k.salt)+len(t)) // Extra capacity to append ciphertext without realloc
	offset := copy(nonce, k.salt)
	binary.PutUvarint(nonce[offset:], uint64(k.counter))

	var extraData []byte
	for _, e := range extras {
		extraData = append(extraData, e...)
	}

	ciphertext := ciph.Seal(nil, nonce, t, extraData)

	return append(nonce, ciphertext...), nil
}

func (k *KeySequential) Decrypt(t []byte, extras ...[]byte) ([]byte, error) {
	return k.k.Decrypt(t, extras...)
}

func (k *KeySequential) EncryptMarshal(i interface{}, extras ...[]byte) (string, error) {
	serialized, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	ciphered, err := k.Encrypt(serialized, extras...)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciphered), nil
}

func (k *KeySequential) DecryptMarshal(s string, i interface{}, extras ...[]byte) error {
	return k.k.DecryptMarshal(s, i, extras...)
}

func (k *KeySequential) Wait() {
	k.k.Wait()
}

func (k *KeySequential) String() (string, error) {
	return k.k.String()
}

// Locator returns the result of PBKDF2. PBKDF2 is a key derivation function
// https://en.wikipedia.org/wiki/PBKDF2
func Locator(s string, salt ...byte) string {
	return hex.EncodeToString(pbkdf2.Key([]byte(s), salt, 4096, 32, sha1.New))
}
