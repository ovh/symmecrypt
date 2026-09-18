package stream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ovh/symmecrypt"
	_ "github.com/ovh/symmecrypt/keyloader"
)

const ChunkSize = 256 * 1024

// streamMagic identifies the authenticated stream format (v2). The writer
// always produces it; the reader also accepts the legacy format (bare chunk
// sequence without position binding) so that existing data remains readable.
// Detection is unambiguous: a legacy stream starts with a zero-padded 5-byte
// uvarint header, so a first byte of 'S' implies a zero second byte — it can
// never spell the magic. A v2 stream stripped of its magic cannot pass as
// legacy either: its chunks are authenticated with a position suffix that the
// legacy path does not provide.
var streamMagic = []byte{'S', 'M', 'C', '2'}

const (
	chunkFlagMore  byte = 0
	chunkFlagFinal byte = 1
)

// stream formats handled by the reader
const (
	formatUnknown = iota
	formatV2
	formatLegacy
)

// chunkAAD returns the extra data authenticating a chunk: the caller extras
// plus a fixed-size suffix binding the chunk position and the termination
// flag, so that reordered, replayed or truncated streams fail decryption.
func chunkAAD(extras [][]byte, index uint64, flag byte) [][]byte {
	suffix := make([]byte, 9)
	binary.BigEndian.PutUint64(suffix, index)
	suffix[8] = flag
	aad := make([][]byte, 0, len(extras)+1)
	aad = append(aad, extras...)
	return append(aad, suffix)
}

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

var buffers = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func getBuffer() (*bytes.Buffer, error) {
	if b, ok := buffers.Get().(*bytes.Buffer); ok {
		b.Reset()
		return b, nil
	}

	panic("buffers is not of type *bytes.Buffer")
}

func putBuffer(buf *bytes.Buffer) {
	buffers.Put(buf)
}

var _ io.WriteCloser = new(chunksWriter)

type chunksWriter struct {
	destination              io.Writer
	k                        symmecrypt.Key
	extras                   [][]byte
	chunkSize                int
	buf                      *bytes.Buffer
	currentChunkBytesWritten int
	chunkIndex               uint64
	wroteMagic               bool
	closed                   bool
}

func (w *chunksWriter) encryptCurrentChunk(last bool) error {
	if !last && w.buf == nil && w.currentChunkBytesWritten == 0 {
		return nil
	}
	if !w.wroteMagic {
		if _, err := w.destination.Write(streamMagic); err != nil {
			return err
		}
		w.wroteMagic = true
	}

	flag := chunkFlagMore
	if last {
		flag = chunkFlagFinal
	}

	// encrypt the chunk, binding its position and termination flag; the
	// final chunk may be empty, its authenticated flag is what allows the
	// reader to detect stream truncation
	var data []byte
	if w.buf != nil {
		data = w.buf.Bytes()
	}
	btes, err := w.k.Encrypt(data, chunkAAD(w.extras, w.chunkIndex, flag)...)
	if err != nil {
		return err
	}

	// write the chunk header: termination flag then encrypted length
	header := make([]byte, 1+binary.MaxVarintLen32)
	header[0] = flag
	binary.PutUvarint(header[1:], uint64(len(btes)))
	if _, err := w.destination.Write(header); err != nil {
		return err
	}

	// then write into the destination writer the encrypted chunk
	if _, err := w.destination.Write(btes); err != nil {
		return err
	}

	// finally reset the current chunk
	w.chunkIndex++
	w.currentChunkBytesWritten = 0
	if w.buf != nil {
		putBuffer(w.buf)
		w.buf = nil
	}

	return nil
}

func (w *chunksWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return len(p), nil
	}
	if w.buf == nil {
		chunkWriter, err := getBuffer()
		if err != nil {
			return 0, err
		}

		w.buf = chunkWriter
		w.currentChunkBytesWritten = 0
	}

	if w.currentChunkBytesWritten == w.chunkSize {
		if err := w.encryptCurrentChunk(false); err != nil {
			return 0, err
		}
	}

	if w.currentChunkBytesWritten+len(p) == w.chunkSize {
		n, err := w.buf.Write(p)
		if err != nil {
			return n, err
		}
		w.currentChunkBytesWritten += int(n)
		if err := w.encryptCurrentChunk(false); err != nil {
			return n, err
		}
		return n, nil
	}

	x := w.chunkSize - w.currentChunkBytesWritten
	if len(p) < x {
		n, err := w.buf.Write(p)
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
	if !w.closed {
		// always emit a final (possibly empty) chunk: its authenticated
		// termination flag is what lets the reader detect truncation
		if err := w.encryptCurrentChunk(true); err != nil {
			return err
		}
		w.closed = true
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
	chunkIndex            uint64
	format                int
	sawFinal              bool
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

// detectFormat sniffs the first bytes of the stream to pick the format.
func (r *chunksReader) detectFormat() {
	buf := make([]byte, len(streamMagic))
	// a read error is deliberately ignored here: the legacy path replays the
	// sniffed bytes and surfaces EOF/errors with the legacy semantics
	n, _ := io.ReadFull(r.src, buf)
	if n == len(streamMagic) && bytes.Equal(buf, streamMagic) {
		r.format = formatV2
		return
	}
	r.format = formatLegacy
	r.src = io.MultiReader(bytes.NewReader(buf[:n]), r.src)
}

// readLegacyChunk parses the pre-v2 format: a bare sequence of
// [5-byte uvarint length || ciphertext] chunks. Kept, tolerances included,
// so that data encrypted by previous symmecrypt versions remains readable.
// Legacy data carries no position binding: it stays exposed to the chunk
// reordering/truncation weaknesses the v2 format fixes.
func (r *chunksReader) readLegacyChunk() error {
	headerBtes, err := getBuffer()
	if err != nil {
		return err
	}
	defer putBuffer(headerBtes)

	// read the chunksize
	if _, err := io.CopyN(headerBtes, r.src, binary.MaxVarintLen32); err != nil {
		return err
	}

	n, err := binary.ReadUvarint(headerBtes)
	if err != nil {
		return err
	}

	// read the chunk content
	btsBuff, err := getBuffer()
	if err != nil {
		return err
	}
	defer putBuffer(btsBuff)

	if _, err := io.CopyN(btsBuff, r.src, int64(n)); err != nil && err != io.EOF {
		return err
	}

	var btes = btsBuff.Bytes()
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

func (r *chunksReader) readNewChunk() error {
	if r.format == formatUnknown {
		r.detectFormat()
	}
	if r.format == formatLegacy {
		return r.readLegacyChunk()
	}

	// once the authenticated final chunk has been consumed, the stream is
	// over: any trailing data is ignored
	if r.sawFinal {
		return io.EOF
	}

	// read the chunk termination flag; an EOF here means the stream was cut
	// before its authenticated final chunk
	var flagBuf [1]byte
	if _, err := io.ReadFull(r.src, flagBuf[:]); err != nil {
		return fmt.Errorf("symmecrypt/stream: truncated stream: %w", err)
	}
	flag := flagBuf[0]
	if flag != chunkFlagMore && flag != chunkFlagFinal {
		return errors.New("symmecrypt/stream: corrupted chunk header")
	}

	headerBtes, err := getBuffer()
	if err != nil {
		return err
	}
	defer putBuffer(headerBtes)

	// read the chunksize
	if _, err := io.CopyN(headerBtes, r.src, binary.MaxVarintLen32); err != nil {
		return fmt.Errorf("symmecrypt/stream: truncated stream: %w", err)
	}

	n, err := binary.ReadUvarint(headerBtes) // READ THE HEADER BUFFER
	if err != nil {
		return err
	}

	// read the chunk content
	btsBuff, err := getBuffer()
	if err != nil {
		return err
	}
	defer putBuffer(btsBuff)

	if _, err := io.CopyN(btsBuff, r.src, int64(n)); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("symmecrypt/stream: truncated stream: %w", err)
	}

	var btes = btsBuff.Bytes()
	var clearContent []byte
	aad := chunkAAD(r.extras, r.chunkIndex, flag)

	if r.uncappedK == nil {
		var err error
		compositeKey, is := r.k.(symmecrypt.CompositeKey)
		if is {
			r.uncappedK, clearContent, err = compositeKey.DecryptUncap(btes, aad...)
		} else {
			clearContent, err = r.k.Decrypt(btes, aad...)
		}
		if err != nil {
			return err
		}
	} else {
		clearContent, err = r.uncappedK.Decrypt(btes, aad...)
		if err != nil {
			return err
		}
	}
	r.chunkIndex++
	if flag == chunkFlagFinal {
		r.sawFinal = true
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

	if len(p)+r.currentChunkReadBytes >= r.chunkSize {
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
