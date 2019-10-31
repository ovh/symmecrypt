package symmecrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
)

var LogErrorFunc = log.Println

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
	NewConvergentKey(string) (Key, error)
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

type writer struct {
	k             Key
	w             io.Writer
	currentSecret bytes.Buffer
	extras        [][]byte
}

// NewWriter instanciates an io.WriteCloser to help you encrypt while you write in a standard io.Writer.
// Internally it stores in an internal buffer the content you want to encrypt. This internal is flushed, encrypted
// and write to the targeted io.Writer on Close().
func NewWriter(w io.Writer, k Key, extra ...[]byte) io.WriteCloser {
	return &writer{
		k:      k,
		w:      w,
		extras: extra,
	}
}

// Close closes the writer. First it reads the internal buffer, then it encrypts its content.
// Finally the encrypted content is written to the destination writer.
// The error returned must be checked, you should not call Close on defer.
// If the destication writer is also a io.Write
func (sw *writer) Close() error {
	// Encrypt the internal buffer
	encData, err := sw.k.Encrypt(sw.currentSecret.Bytes(), sw.extras...)
	if err != nil {
		return err
	}
	// Write the encrypted bytes to the destination writer
	n, err := sw.w.Write(encData)
	switch {
	case n != len(encData):
		return errors.New("something went wrong during write to internal buffer")
	case err != nil:
		return err
	}
	// If the destication writer is a io.Closer: close it
	c, ok := sw.w.(io.Closer)
	if ok {
		return c.Close()
	}

	return nil
}

// Write appends the contents of b to the internal buffer.
// The returned value n is the length of p; err is always nil. If the
// buffer becomes too large, Write will panic with ErrTooLarge.
func (sw *writer) Write(b []byte) (int, error) {
	// copy clear data in the internal buffer
	// it will be encrypted on close
	return sw.currentSecret.Write(b)
}

type reader struct {
	io.Reader
}

func newReaderBuf(buf []byte, k Key, extra ...[]byte) (io.Reader, error) {
	decData, err := k.Decrypt(buf, extra...)
	if err != nil {
		return nil, err
	}
	// Instanciate a bytes reader
	reader := &reader{bytes.NewReader(decData)}
	return reader, nil
}

// NewReader returns a new Reader which is able to decrypt the source io.Reader.
// It returns an error if the source io.Reader is unreadable with the provided Key and extras.
func NewReader(r io.Reader, k Key, extra ...[]byte) (io.Reader, error) {
	// Read all the encrypted data in the internal buffer
	var buffer bytes.Buffer
	_, err := io.Copy(&buffer, r)
	if err != nil {
		return nil, err
	}
	// Decrypt all the buffer
	btes := buffer.Bytes()
	return newReaderBuf(btes, k, extra...)
}

var _ io.Writer = new(chunksWriter)

type chunksWriter struct {
	destination              io.Writer
	k                        Key
	extras                   [][]byte
	chunkSize                int
	currentChunkWriter       *bytes.Buffer
	currentChunkBytesWritten int
}

func (w *chunksWriter) encryptCurrentChunk() (int, error) {
	currentChunk := w.currentChunkWriter.Bytes()
	// first step: encrypt the chunks
	var encChunk bytes.Buffer
	encWriter := NewWriter(&encChunk, w.k, w.extras...).(*writer)
	n, err := encWriter.Write(currentChunk)
	if err != nil {
		return n, err
	}

	// call close to effectivelly encrypt all the things
	if err := encWriter.Close(); err != nil {
		return n, err
	}

	// get the encrypted content
	btes := encChunk.Bytes()

	// then write into the destination writer the len of the encrypted chunks
	headerBuf := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(headerBuf, int64(len(btes)))
	if _, err := w.destination.Write(headerBuf); err != nil {
		return n, err
	}

	// then write into the desitination writer the encrypted chunks
	_, err = w.destination.Write(btes)

	// finally reset the current chunk
	w.currentChunkBytesWritten = 0
	w.currentChunkWriter = nil

	return n, err
}

func (w *chunksWriter) Write(p []byte) (int, error) {
	if w.currentChunkWriter == nil {
		w.currentChunkWriter = new(bytes.Buffer)
		w.currentChunkBytesWritten = 0
	}

	if w.currentChunkBytesWritten == w.chunkSize {
		return w.encryptCurrentChunk()
	}

	if w.currentChunkBytesWritten+len(p) <= w.chunkSize {
		n, err := w.currentChunkWriter.Write(p)
		if err != nil {
			return int(n), err
		}
		w.currentChunkBytesWritten += int(n)
		return w.encryptCurrentChunk()
	}

	x := w.chunkSize - w.currentChunkBytesWritten
	p1 := p[:x]
	p2 := p[x:]

	x, err := w.Write(p1)
	if err != nil {
		return x, err
	}

	y, err := w.Write(p2)
	return x + y, err
}

func NewChunksWriter(w io.Writer, k Key, chunkSize int, extras ...[]byte) io.Writer {
	var cw = chunksWriter{
		chunkSize:   chunkSize,
		destination: w,
		k:           k,
		extras:      extras,
	}
	return &cw
}

var _ io.Reader = new(chunksReader)

type chunksReader struct {
	src                   io.Reader
	k                     Key
	extras                [][]byte
	chunkSize             int
	currentChunk          io.Reader
	currentChunkReadBytes int
}

func NewChunksReader(r io.Reader, k Key, chunkSize int, extras ...[]byte) io.Reader {
	var cr = chunksReader{
		src:       r,
		k:         k,
		extras:    extras,
		chunkSize: chunkSize,
	}
	return &cr
}

func (r *chunksReader) readNewChunk() error {
	// read the chunksize
	headerBtes := make([]byte, binary.MaxVarintLen64)
	if _, err := r.src.Read(headerBtes); err != nil { // READING THE CLEAR HEADER FROM THE ENCRYPTED SOURCE
		return err
	}

	n, err := binary.ReadVarint(bytes.NewReader(headerBtes)) // READ THE HEADER BUFFER
	if err != nil {
		return err
	}

	// read the chunk content
	btes := make([]byte, n)
	_, err = r.src.Read(btes)
	if err != nil && err != io.EOF {
		return err
	}

	kr, err := newReaderBuf(btes, r.k, r.extras...) // PREPARE THE CLEAR BUFFER OF THE CHUNK CONTENT
	if err != nil {
		return err
	}

	r.currentChunk = kr
	r.currentChunkReadBytes = 0
	return nil
}

func (r *chunksReader) Read(p []byte) (int, error) {
	if r.currentChunk == nil {
		if err := r.readNewChunk(); err != nil {
			return 0, err
		}
	}

	if len(p)+r.currentChunkReadBytes > r.chunkSize {
		// The first part of 'p' will store the current chunk
		p1 := p[:r.chunkSize-r.currentChunkReadBytes]
		// The last part of 'p' will store the next chunk
		p2 := p[r.chunkSize-r.currentChunkReadBytes:]

		n, err := r.currentChunk.Read(p1)
		r.currentChunkReadBytes += n
		if err != nil {
			return n, err
		}

		if err := r.readNewChunk(); err != nil {
			return n, err
		}

		m, err := r.Read(p2)
		r.currentChunkReadBytes += m
		return n + m, err
	}

	n, err := r.currentChunk.Read(p)
	r.currentChunkReadBytes += n
	return n, err
}
