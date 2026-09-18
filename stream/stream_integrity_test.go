package stream_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/stream"
)

// These tests encode the integrity contract of the stream format: a stored
// ciphertext altered by anyone (chunk reorder, replay, truncation at a chunk
// boundary) must FAIL to decrypt, not silently return a corrupted plaintext.
// AEAD per chunk is not enough: the position and the termination of each
// chunk must be authenticated too. Residual, imposed by legacy-format
// compatibility: a stream truncated to ZERO bytes reads as a legacy empty
// stream (see TestStreamLegacyEmptyStreamCompat).

const testChunkSize = 8

func testKey(t *testing.T) symmecrypt.Key {
	t.Helper()
	k, err := symmecrypt.NewRandomKey("aes-gcm")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func encryptStream(t *testing.T, k symmecrypt.Key, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := stream.NewWriter(&buf, k, testChunkSize)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decryptStream(k symmecrypt.Key, cipher []byte) ([]byte, error) {
	r := stream.NewReader(bytes.NewReader(cipher), k, testChunkSize)
	return io.ReadAll(r)
}

// splitChunks parses the wire format into whole chunk blocks (header included)
// so tests can tamper at chunk granularity. It intentionally knows the format:
// [4-byte magic] then a sequence of [1-byte flag || 5-byte uvarint length ||
// ciphertext]. Tampering reassembles the blocks after the magic.
func splitChunks(t *testing.T, cipher []byte) [][]byte {
	t.Helper()
	var blocks [][]byte
	pos := 4 // skip the format magic
	for pos < len(cipher) {
		if pos+6 > len(cipher) {
			t.Fatalf("malformed test stream at offset %d", pos)
		}
		n, err := binary.ReadUvarint(bytes.NewReader(cipher[pos+1 : pos+6]))
		if err != nil {
			t.Fatal(err)
		}
		end := pos + 6 + int(n)
		if end > len(cipher) {
			t.Fatalf("malformed test stream at offset %d", pos)
		}
		blocks = append(blocks, cipher[pos:end])
		pos = end
	}
	return blocks
}

func mustFailDecrypt(t *testing.T, k symmecrypt.Key, tampered []byte, attack string) {
	t.Helper()
	out, err := decryptStream(k, tampered)
	if err == nil {
		t.Fatalf("%s: tampered stream decrypted successfully (%d plaintext bytes) instead of failing", attack, len(out))
	}
}

func twoChunksStream(t *testing.T, k symmecrypt.Key) ([]byte, [][]byte) {
	t.Helper()
	data := append(bytes.Repeat([]byte("A"), testChunkSize), bytes.Repeat([]byte("B"), testChunkSize)...)
	cipher := encryptStream(t, k, data)
	blocks := splitChunks(t, cipher)
	if len(blocks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(blocks))
	}
	return cipher, blocks
}

// reassemble rebuilds a stream from tampered chunk blocks, keeping the
// original stream prefix (format magic).
func reassemble(cipher []byte, blocks ...[]byte) []byte {
	out := append([]byte{}, cipher[:4]...)
	for _, b := range blocks {
		out = append(out, b...)
	}
	return out
}

func TestStreamRoundTrip(t *testing.T) {
	k := testKey(t)
	cipher := encryptStream(t, k, []byte("hello"))
	out, err := decryptStream(k, cipher)
	if err != nil || string(out) != "hello" {
		t.Fatalf("roundtrip broken: %q %v", out, err)
	}
}

func TestStreamRejectsBoundaryTruncation(t *testing.T) {
	k := testKey(t)
	cipher, blocks := twoChunksStream(t, k)
	mustFailDecrypt(t, k, reassemble(cipher, blocks[0]), "boundary truncation")
	mustFailDecrypt(t, k, reassemble(cipher, blocks[:len(blocks)-1]...), "final chunk removal")
}

func TestStreamRejectsChunkReorder(t *testing.T) {
	k := testKey(t)
	cipher, blocks := twoChunksStream(t, k)
	swapped := append([][]byte{blocks[1], blocks[0]}, blocks[2:]...)
	mustFailDecrypt(t, k, reassemble(cipher, swapped...), "chunk reorder")
}

func TestStreamRejectsChunkReplay(t *testing.T) {
	k := testKey(t)
	cipher, blocks := twoChunksStream(t, k)
	replayed := append([][]byte{blocks[0], blocks[0]}, blocks[1:]...)
	mustFailDecrypt(t, k, reassemble(cipher, replayed...), "chunk replay")
}

func TestStreamEmptyPlaintextRoundTrip(t *testing.T) {
	k := testKey(t)
	out, err := decryptStream(k, encryptStream(t, k, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(out))
	}
}

// encryptLegacyStream reproduces the pre-v2 wire format (bare sequence of
// [5-byte uvarint length || AEAD(chunk, extras)]) to guarantee that data
// encrypted by previous symmecrypt versions remains readable.
func encryptLegacyStream(t *testing.T, k symmecrypt.Key, data []byte, extras ...[]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	for i := 0; i < len(data); i += testChunkSize {
		end := i + testChunkSize
		if end > len(data) {
			end = len(data)
		}
		ct, err := k.Encrypt(data[i:end], extras...)
		if err != nil {
			t.Fatal(err)
		}
		hdr := make([]byte, binary.MaxVarintLen32)
		binary.PutUvarint(hdr, uint64(len(ct)))
		out.Write(hdr)
		out.Write(ct)
	}
	return out.Bytes()
}

// TestStreamReadsLegacyFormat encodes the compatibility contract: streams
// produced by previous symmecrypt versions must remain readable.
func TestStreamReadsLegacyFormat(t *testing.T) {
	k := testKey(t)
	data := []byte("legacy data spanning multiple chunks plus a partial tail")
	extras := [][]byte{[]byte("ctx")}

	legacy := encryptLegacyStream(t, k, data, extras...)
	r := stream.NewReader(bytes.NewReader(legacy), k, testChunkSize, extras...)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("legacy stream mangled: %q", out)
	}
}

// TestStreamLegacyEmptyStreamCompat: previous versions encrypted empty input
// to zero bytes, so an empty input must keep reading as an empty stream.
// Documented residual: this makes a stream truncated to zero bytes
// indistinguishable from a legacy empty stream, so that specific tampering
// is not detectable while legacy support remains.
func TestStreamLegacyEmptyStreamCompat(t *testing.T) {
	k := testKey(t)
	out, err := decryptStream(k, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(out))
	}
}

// TestStreamRejectsMagicStripDowngrade: removing the v2 magic must not allow
// reading v2 chunks through the legacy code path (their AAD differs).
func TestStreamRejectsMagicStripDowngrade(t *testing.T) {
	k := testKey(t)
	cipher, _ := twoChunksStream(t, k)
	mustFailDecrypt(t, k, cipher[4:], "magic strip downgrade")
}
