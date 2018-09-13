package symmecrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Key is an abstraction of a symmetric encryption key
// - Encrypt / Decrypt provide low-level data encryption, with extra data for MAC
// - EncryptMarshal / DecryptMarshal build on top of that, working with a JSON representation of an object
// - Wait blocks until the Key is ready to be used (noop for the default implementation, useful for keys that need to be activated somehow)
type Key interface {
	Encrypt([]byte, ...[]byte) ([]byte, error)
	Decrypt([]byte, ...[]byte) ([]byte, error)
	EncryptMarshal(interface{}, ...[]byte) (string, error)
	DecryptMarshal(string, interface{}, ...[]byte) error
	Wait()
	String() (string, error)
}

// A KeyFactory instantiates a Key
type KeyFactory interface {
	NewKey(string) (Key, error)
	NewRandomKey() (Key, error)
}

// CompositeKey provides a keyring mechanism: encrypt with first, decrypt with _any_
type CompositeKey []Key

// ErrorKey is a helper implementation that always returns an error
type ErrorKey struct {
	Error error
}

/*
** KEY TYPES (factory)
 */

var (
	factories    = map[string]KeyFactory{}
	factoriesMut sync.Mutex
)

// RegisterCipher registers a custom cipher. Useful for backwards compatibility or very specific needs,
// otherwise the provided implementations are recommended.
func RegisterCipher(name string, f KeyFactory) {
	if f == nil {
		return
	}
	factoriesMut.Lock()
	defer factoriesMut.Unlock()
	_, ok := factories[name]
	if ok {
		panic(fmt.Sprintf("Danger! Conflicting encryption key factories: %s", name))
	}
	factories[name] = f
}

// NewKey instantiates a new key with a given cipher.
func NewKey(cipher string, key string) (Key, error) {
	f, err := GetKeyFactory(cipher)
	if err != nil {
		return nil, err
	}
	return f.NewKey(key)
}

// NewRandomKey instantiates a new random key with a given cipher.
func NewRandomKey(cipher string) (Key, error) {
	f, err := GetKeyFactory(cipher)
	if err != nil {
		return nil, err
	}
	return f.NewRandomKey()
}

// GetKeyFactory retrieves the factory function from a cipher name
func GetKeyFactory(name string) (KeyFactory, error) {
	if name == "" {
		return nil, errors.New("trying to instantiate an encryption key without specifying a cipher")
	}
	factoriesMut.Lock()
	defer factoriesMut.Unlock()
	f, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown cipher '%s'", name)
	}
	return f, nil
}

/*
** COMPOSITE ENCRYPTION KEY: keyring mechanism, always encrypt with first key, decrypt with _any_
 */

// Encrypt arbitrary data with the first key (highest priority)
func (c CompositeKey) Encrypt(text []byte, extra ...[]byte) ([]byte, error) {
	if len(c) == 0 {
		return nil, errors.New("empty composite encryption key")
	}
	return c[0].Encrypt(text, extra...)
}

// Decrypt arbitrary data with _any_ key
func (c CompositeKey) Decrypt(text []byte, extra ...[]byte) ([]byte, error) {
	for _, k := range c {
		b, err := k.Decrypt(text, extra...)
		if err == nil {
			return b, nil
		}
	}
	return nil, errors.New("failed to decrypt with all keys")
}

// EncryptMarshal encrypts an object with the first key (highest priority)
func (c CompositeKey) EncryptMarshal(i interface{}, extra ...[]byte) (string, error) {
	if len(c) == 0 {
		return "", errors.New("empty composite encryption key")
	}
	return c[0].EncryptMarshal(i, extra...)
}

// DecryptMarshal decrypts an object with _any_ key
func (c CompositeKey) DecryptMarshal(s string, target interface{}, extra ...[]byte) error {
	var firstErr error
	for _, k := range c {
		err := k.DecryptMarshal(s, target, extra...)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	// none worked, return the first error for cleaner propagation
	if firstErr != nil {
		return firstErr
	}
	return errors.New("failed to decrypt marshal with all keys")
}

// Wait for _all_ the keys to be ready
func (c CompositeKey) Wait() {
	for _, k := range c {
		k.Wait()
	}
}

// String is not implemented for composite keys
func (c CompositeKey) String() (string, error) {
	return "", errors.New("String operation unsupported for composite key")
}

/*
** ERROR KEY: respects Key interface, always returns error (helper)
 */

// Encrypt returns the predefined error
func (e ErrorKey) Encrypt(t []byte, extra ...[]byte) ([]byte, error) {
	return nil, e.Error
}

// Decrypt returns the predefined error
func (e ErrorKey) Decrypt(t []byte, extra ...[]byte) ([]byte, error) {
	return nil, e.Error
}

// EncryptMarshal returns the predefined error
func (e ErrorKey) EncryptMarshal(i interface{}, extra ...[]byte) (string, error) {
	return "", e.Error
}

// DecryptMarshal returns the predefined error
func (e ErrorKey) DecryptMarshal(s string, i interface{}, extra ...[]byte) error {
	return e.Error
}

// Wait is a no-op
func (e ErrorKey) Wait() {
}

// String returns the predefined error
func (e ErrorKey) String() (string, error) {
	return "", e.Error
}

type Writer struct {
	k             Key
	w             io.Writer
	currentSecret []byte
	extras        [][]byte
}

func NewWriter(w io.Writer, k Key, extra ...[]byte) *Writer {
	return &Writer{
		k:      k,
		w:      w,
		extras: extra,
	}
}

func (sw *Writer) Flush() error {
	// Encrypt the internal buffer
	encData, err := sw.k.Encrypt(sw.currentSecret, sw.extras...)
	if err != nil {
		return err
	}
	n, err := sw.w.Write(encData)
	switch {
	case n != len(encData):
		return fmt.Errorf("something went wrong during write to internal buffer")
	case err != nil:
		return err
	}
	// Dereference the clear data
	sw.currentSecret = nil

	return nil
}

func (sw *Writer) Write(b []byte) (int, error) {
	// copy clear data in the internal buffer
	// it will be encrypted on flush
	destSlice := make([]byte, len(b)+len(sw.currentSecret))
	if len(sw.currentSecret) > 0 {
		copy(destSlice, sw.currentSecret)
	}
	copy(destSlice[len(sw.currentSecret):], b)
	sw.currentSecret = destSlice
	return len(b), nil
}

func (sw *Writer) Close() error {
	return sw.Flush()
}

type Reader struct {
	decBuffer io.Reader
}

func NewReader(r io.Reader, k Key, extra ...[]byte) (*Reader, error) {
	reader := &Reader{}

	// Read all the encrypted data in the internal buffer
	var buffer bytes.Buffer
	_, err := io.Copy(&buffer, r)
	if err != nil {
		return nil, err
	}

	// Decrypt allbuffer
	decData, err := k.Decrypt(buffer.Bytes(), extra...)
	if err != nil {
		return nil, err
	}

	// Instanciate a bytes reader
	reader.decBuffer = bytes.NewReader(decData)

	return reader, nil
}

func (sr *Reader) Read(b []byte) (int, error) {
	// Do you try to read after OEF ?
	if sr.decBuffer == nil {
		return 0, io.ErrClosedPipe
	}

	n, err := sr.decBuffer.Read(b)

	// If the buffer has reached EOF, dereferences it
	if n == 0 || err != nil {
		sr.decBuffer = nil
	}

	return n, err
}
