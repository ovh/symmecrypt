package stream

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/ovh/symmecrypt"
)

var _ io.WriteCloser = new(chunksWriter)

type chunksWriter struct {
	destination              io.Writer
	k                        symmecrypt.Key
	extras                   [][]byte
	chunkSize                int
	currentChunkWriter       *bytes.Buffer
	currentChunkBytesWritten int
}

func (w *chunksWriter) encryptCurrentChunk() (int, error) {
	if w.currentChunkWriter == nil && w.currentChunkBytesWritten == 0 {
		return 0, nil
	}
	currentChunk := w.currentChunkWriter.Bytes()
	// first step: encrypt the chunks
	var encChunk bytes.Buffer
	encWriter := symmecrypt.NewWriter(&encChunk, w.k, w.extras...)
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

	if w.currentChunkBytesWritten+len(p) == w.chunkSize {
		n, err := w.currentChunkWriter.Write(p)
		if err != nil {
			return int(n), err
		}
		w.currentChunkBytesWritten += int(n)
		return w.encryptCurrentChunk()
	}

	x := w.chunkSize - w.currentChunkBytesWritten
	if len(p) < x {
		n, err := w.currentChunkWriter.Write(p)
		w.currentChunkBytesWritten += int(n)
		return int(n), err
	} else {
		p1 := p[:x]
		p2 := p[x:]

		x, err := w.Write(p1)
		if err != nil {
			return x, err
		}

		y, err := w.Write(p2)
		return x + y, err
	}
}

func (w *chunksWriter) Close() error {
	_, err := w.encryptCurrentChunk()
	return err
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

	kr, err := symmecrypt.NewReaderFrom(btes, r.k, r.extras...) // PREPARE THE CLEAR BUFFER OF THE CHUNK CONTENT
	if err != nil {
		return err
	}

	r.currentChunk = kr
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
