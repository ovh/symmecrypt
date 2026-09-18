// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is derived from the AES-GCM-SIV implementation of the Tink
// project (github.com/tink-crypto/tink-go, internal/aead/aesgcmsiv.go), with
// modifications by OVH SAS: reworked to implement the standard library
// cipher.AEAD interface (the nonce is supplied by the caller instead of
// being generated internally).

package aesgcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// nonceSize is the acceptable IV size defined by RFC 8452.
	nonceSize = 12

	// blockSize is the block size that AES-GCM-SIV uses. This is the size
	// for the tag, the KDF etc. Note: this value is the same as AES block size.
	blockSize = 16

	// tagSize is the byte-length of the authentication tag produced by AES-GCM-SIV.
	tagSize = blockSize

	maxKeySize = 32

	// maxPlaintextSize is the plaintext limit defined by RFC 8452 (2^36 bytes).
	maxPlaintextSize = 1 << 36
)

// gcmSIV is an implementation of cipher.AEAD following RFC 8452.
type gcmSIV struct {
	block   cipher.Block
	keySize int
}

var _ cipher.AEAD = (*gcmSIV)(nil)

// newGCMSIV returns a gcmSIV instance.
// The key argument should be the AES key, either 16 or 32 bytes to select
// AES-128 or AES-256.
func newGCMSIV(key []byte) (*gcmSIV, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("aes-gcm-siv: invalid key size %d, expected 16 or 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm-siv: failed to create block cipher: %w", err)
	}
	return &gcmSIV{block: block, keySize: len(key)}, nil
}

func (g *gcmSIV) NonceSize() int {
	return nonceSize
}

func (g *gcmSIV) Overhead() int {
	return tagSize
}

// Seal encrypts and authenticates plaintext along with additionalData, and
// appends ciphertext||tag to dst. To reuse plaintext's storage for the output,
// use plaintext[:0] as dst; otherwise dst must not overlap plaintext.
func (g *gcmSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != nonceSize {
		panic("aes-gcm-siv: incorrect nonce length given to GCM-SIV")
	}
	if uint64(len(plaintext)) > maxPlaintextSize {
		panic("aes-gcm-siv: message too large for GCM-SIV")
	}

	var authKeyData [blockSize]byte
	var encKeyData [maxKeySize]byte
	authKey := authKeyData[:]
	encKey := encKeyData[:g.keySize]
	g.deriveKeys(nonce, authKey, encKey)

	pv := computePolyval(authKey, plaintext, additionalData)

	ret, out := sliceForAppend(dst, len(plaintext)+tagSize)
	tag := out[len(plaintext):]
	computeTag(pv[:], nonce, encKey, tag)
	aesCTR(encKey, tag, plaintext, out[:len(plaintext)])

	return ret
}

// Open authenticates ciphertext (as produced by Seal: ciphertext||tag) along
// with additionalData, then decrypts it and appends the plaintext to dst.
func (g *gcmSIV) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		panic("aes-gcm-siv: incorrect nonce length given to GCM-SIV")
	}
	if len(ciphertext) < tagSize {
		return nil, errors.New("aes-gcm-siv: ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-tagSize]

	var authKeyData [blockSize]byte
	var encKeyData [maxKeySize]byte
	authKey := authKeyData[:]
	encKey := encKeyData[:g.keySize]
	g.deriveKeys(nonce, authKey, encKey)

	ret, out := sliceForAppend(dst, len(ciphertext))
	aesCTR(encKey, tag, ciphertext, out)

	pv := computePolyval(authKey, out, additionalData)

	var expectedTag [tagSize]byte
	computeTag(pv[:], nonce, encKey, expectedTag[:])

	if subtle.ConstantTimeCompare(expectedTag[:], tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("aes-gcm-siv: message authentication failed")
	}

	return ret, nil
}

// deriveKeys implements the `derive_keys` function described by RFC 8452.
//
// It uses the key and nonce to derive the authentication key and the
// encryption key, which are written to authKey and encKey respectively.
// authKey must be of length blockSize and encKey of length g.keySize.
func (g *gcmSIV) deriveKeys(nonce, authKey, encKey []byte) {
	var nonceBlock [blockSize]byte
	copy(nonceBlock[blockSize-nonceSize:], nonce)

	const counterSize = 4 // blockSize - nonceSize

	var encBlock [blockSize]byte
	kdfAes := func(counter uint32, dst []byte) {
		binary.LittleEndian.PutUint32(nonceBlock[:counterSize], counter)
		g.block.Encrypt(encBlock[:], nonceBlock[:])
		copy(dst, encBlock[0:8])
	}

	kdfAes(0, authKey[0:8])
	kdfAes(1, authKey[8:16])
	kdfAes(2, encKey[0:8])
	kdfAes(3, encKey[8:16])
	if g.keySize == 32 {
		kdfAes(4, encKey[16:24])
		kdfAes(5, encKey[24:32])
	}
}

func computePolyval(authKey, pt, ad []byte) [blockSize]byte {
	var lengthBlock [blockSize]byte
	binary.LittleEndian.PutUint64(lengthBlock[:8], uint64(len(ad))*8)
	binary.LittleEndian.PutUint64(lengthBlock[8:], uint64(len(pt))*8)

	p, err := newPolyval(authKey)
	if err != nil {
		// unreachable: authKey is always blockSize bytes
		panic(fmt.Sprintf("aes-gcm-siv: failed to create polyval: %v", err))
	}

	p.update(ad)
	p.update(pt)
	p.update(lengthBlock[:])
	return p.finish()
}

func computeTag(pv, nonce, encKey, out []byte) {
	for i := range nonce {
		pv[i] ^= nonce[i]
	}
	pv[blockSize-1] &= 0x7f

	block, err := aes.NewCipher(encKey)
	if err != nil {
		// unreachable: encKey is always 16 or 32 bytes
		panic(fmt.Sprintf("aes-gcm-siv: failed to create block cipher: %v", err))
	}

	block.Encrypt(out, pv)
}

// aesCTR implements the AES-CTR operation of AES-GCM-SIV, writing the result
// to out.
//
// NOTE: This is from RFC 8452. The counter incrementation (32-bit little
// endian, wrapping) is different from standard AES-CTR. Arguments in and out
// must have the same length.
func aesCTR(key, tag, in, out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		// unreachable: key is always 16 or 32 bytes
		panic(fmt.Sprintf("aes-gcm-siv: failed to create block cipher: %v", err))
	}

	var counter [blockSize]byte
	copy(counter[:], tag)
	counter[blockSize-1] |= 0x80
	counterInc := binary.LittleEndian.Uint32(counter[0:4])

	outputIdx := 0
	var keystreamBlock [blockSize]byte
	for len(in) > 0 {
		block.Encrypt(keystreamBlock[:], counter[:])
		counterInc++
		binary.LittleEndian.PutUint32(counter[0:4], counterInc)
		n := xorBytes(out[outputIdx:], in, keystreamBlock[:])
		outputIdx += n
		in = in[n:]
	}
}

// xorBytes sets dst[i] = a[i] ^ b[i] for i < n where n = min(len(a), len(b)),
// and returns n. Local substitute for crypto/subtle.XORBytes (go >= 1.20).
func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. Same helper as in crypto/cipher.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
