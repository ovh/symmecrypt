package aesgcmsiv

import (
	"crypto/cipher"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/symutils"
)

const (
	// KeyLen is the number of raw bytes for a key: AES256
	KeyLen = 32

	// CipherName is the name of the cipher as registered on symmecrypt
	CipherName = "aes-gcm-siv"
)

func init() {
	symmecrypt.RegisterCipher(CipherName, symutils.NewFactoryAEAD(KeyLen, newAEAD))
}

func newAEAD(b []byte) (cipher.AEAD, error) {
	return newGCMSIV(b)
}
