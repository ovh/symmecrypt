package stream

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/ovh/symmecrypt"
	_ "github.com/ovh/symmecrypt/keyloader"
)

const ChunkSize = 256 * 1024

type Key interface {
	EncryptPipe(io.Reader, io.Writer, ...[]byte) error
	DecryptPipe(io.Reader, io.Writer, ...[]byte) error
}

func NewKey(k symmecrypt.Key) Key {
	return key{k}
}

type key struct {
	symmecrypt.Key
}

var _ Key = new(key)

func (k key) EncryptPipe(r io.Reader, w io.Writer, extra ...[]byte) error {
	wc := NewWriter(w, k, ChunkSize, extra...)
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func (k key) DecryptPipe(r io.Reader, w io.Writer, extra ...[]byte) error {
	rc := NewReader(r, k, ChunkSize, extra...)
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}

var _ io.WriteCloser = new(chunksWriter)

type chunksWriter struct {
	destination              io.Writer
	k                        symmecrypt.Key
	extras                   [][]byte
	chunkSize                int
	currentChunkWriter       *bytes.Buffer
	currentChunkBytesWritten int
}

func (w *chunksWriter) encryptCurrentChunk() error {
	if w.currentChunkWriter == nil && w.currentChunkBytesWritten == 0 {
		return nil
	}
	currentChunk := w.currentChunkWriter.Bytes()
	// first step: encrypt the chunks
	btes, err := w.k.Encrypt(currentChunk, w.extras...)
	if err != nil {
		return err
	}

	// then write into the destination writer the len of the encrypted chunks
	headerBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutUvarint(headerBuf, uint64(len(btes)))
	if _, err := w.destination.Write(headerBuf); err != nil {
		return err
	}

	// then write into the desitination writer the encrypted chunks
	_, err = w.destination.Write(btes)

	// finally reset the current chunk
	w.currentChunkBytesWritten = 0
	w.currentChunkWriter = nil

	return err
}

func (w *chunksWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return len(p), nil
	}
	if w.currentChunkWriter == nil {
		w.currentChunkWriter = new(bytes.Buffer)
		w.currentChunkBytesWritten = 0
	}

	if w.currentChunkBytesWritten == w.chunkSize {
		if err := w.encryptCurrentChunk(); err != nil {
			return 0, err
		}
	}

	if w.currentChunkBytesWritten+len(p) == w.chunkSize {
		n, err := w.currentChunkWriter.Write(p)
		if err != nil {
			return n, err
		}
		w.currentChunkBytesWritten += int(n)
		if err := w.encryptCurrentChunk(); err != nil {
			return n, err
		}
		return n, nil
	}

	x := w.chunkSize - w.currentChunkBytesWritten
	if len(p) < x {
		n, err := w.currentChunkWriter.Write(p)
		w.currentChunkBytesWritten += int(n)
		return n, err
	} else {
		p1 := p[:x]
		p2 := p[x:]

		x, err := w.Write(p1)
		if err != nil {
			return x, err
		}

		y, err := w.Write(p2)
		if err != nil {
			return y, err
		}
		return x + y, nil
	}
}

func (w *chunksWriter) Close() error {
	if err := w.encryptCurrentChunk(); err != nil {
		return err
	}
	closer, is := w.destination.(io.Closer)
	if !is {
		return nil
	}
	return closer.Close()
}

// NewWriter needs documentation and must be closed
func NewWriter(w io.Writer, k symmecrypt.Key, chunkSize int, extras ...[]byte) io.WriteCloser {
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
	k                     symmecrypt.Key
	uncappedK             symmecrypt.Key
	extras                [][]byte
	chunkSize             int
	currentChunk          io.Reader
	currentChunkReadBytes int
}

// NewReader needs doc
func NewReader(r io.Reader, k symmecrypt.Key, chunkSize int, extras ...[]byte) io.Reader {
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
	headerBtes := &bytes.Buffer{}
	if _, err := io.CopyN(headerBtes, r.src, binary.MaxVarintLen32); err != nil {
		return err
	}

	n, err := binary.ReadUvarint(bytes.NewReader(headerBtes.Bytes())) // READ THE HEADER BUFFER
	if err != nil {
		return err
	}

	// read the chunk content
	btsBuff := &bytes.Buffer{}
	if _, err := io.CopyN(btsBuff, r.src, int64(n)); err != nil && err != io.EOF{
		return err
	}
	btes := btsBuff.Bytes()

	var clearContent []byte

	if r.uncappedK == nil {
		var err error
		compositeKey, is := r.k.(symmecrypt.CompositeKey)
		if is {
			r.uncappedK, clearContent, err = compositeKey.DecryptUncap(btes, r.extras...)
		} else {
			clearContent, err = r.k.Decrypt(btes, r.extras...)
		}
		if err != nil {
			return err
		}
	} else {
		clearContent, err = r.uncappedK.Decrypt(btes, r.extras...)
		if err != nil {
			return err
		}
	}
	r.currentChunk = bytes.NewReader(clearContent)
	r.currentChunkReadBytes = 0
	return nil
}

func (r *chunksReader) Read(p []byte) (x int, e error) {
	if r.currentChunk == nil {
		if err := r.readNewChunk(); err != nil {
			return x, err
		}
	}

	if len(p)+r.currentChunkReadBytes > r.chunkSize {
		var pp = p
		for {
			// The first part of 'p' will store the current chunk
			z := r.chunkSize - r.currentChunkReadBytes
			if z > len(pp) {
				z = len(pp)
			}
			p1 := pp[:z]

			// Read the first part
			n, err := r.currentChunk.Read(p1)
			r.currentChunkReadBytes += n
			x += n

			if err != nil {
				return x, err
			}

			// The last part of 'p' will store the next chunk
			p2 := pp[n:]

			// Since the chunk is over, let's reset it
			if err := r.readNewChunk(); err != nil {
				return x, err
			}

			if len(p2) == 0 {
				return x, nil
			}

			if len(p2) < r.chunkSize {
				m, err := r.currentChunk.Read(p2)
				r.currentChunkReadBytes += m
				x += m

				if err != nil {
					return x, err
				}

				if m < len(p2) {
					pp = p2[m:]
					// In this case, we probably hit the end of a chunk
					if err := r.readNewChunk(); err != nil {
						return x, err
					}
					continue
				}
				return x, nil
			}

			pp = p2
		}
	}

	n, err := r.currentChunk.Read(p)
	r.currentChunkReadBytes += n
	x += n

	if err != nil {
		return x, err
	}

	if r.currentChunkReadBytes > r.chunkSize {
		return x, r.readNewChunk()
	}

	return x, err
}
