package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aespmacsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/keyloader"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	DefaultCipher = aesgcm.CipherName
	ciphers       = []string{aesgcm.CipherName, chacha20poly1305.CipherName, aespmacsiv.CipherName, hmac.CipherName}

	app = kingpin.New("symmecrypt CLI tool", fmt.Sprintf("A command-line utility to generate symmecrypt encryption keys. Available ciphers: %s (default: %s)", strings.Join(ciphers, ", "), DefaultCipher))

	newEncryption           = app.Command("new", "Generate a new random encryption key")
	newEncryptionIdentifier = newEncryption.Arg("identifier", "identifier for the key").Required().String()
	newEncryptionCipher     = newEncryption.Arg("cipher", "cipher for the key").Default(DefaultCipher).Enum(ciphers...)

	encrypt       = app.Command("encrypt", "Encrypt data with selected key + cipher. Outputs hex.")
	encryptCipher = encrypt.Arg("cipher", "cipher to use").Default(DefaultCipher).Enum(ciphers...)

	decrypt       = app.Command("decrypt", "Decrypt data with selected key + cipher. Input is hex.")
	decryptCipher = decrypt.Arg("cipher", "cipher to use").Default(DefaultCipher).Enum(ciphers...)
)

func main() {

	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch cmd {
	case newEncryption.FullCommand():
		key, err := keyloader.GenerateKey(*newEncryptionCipher, *newEncryptionIdentifier, false, time.Now())
		if err != nil {
			panic(err)
		}
		j, err := json.Marshal(key)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(j))

	case encrypt.FullCommand():
		keyStr := readSecret("Encryption key: ")
		k, err := symmecrypt.NewKey(*encryptCipher, keyStr)
		if err != nil {
			panic(err)
		}
		dataStr := readSecret("Data to encrypt: ")
		b, err := k.Encrypt([]byte(dataStr))
		if err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(b))

	case decrypt.FullCommand():
		keyStr := readSecret("Encryption key: ")
		k, err := symmecrypt.NewKey(*decryptCipher, keyStr)
		if err != nil {
			panic(err)
		}
		dataStr := readSecret("hex data to decrypt: ")
		dataRaw, err := hex.DecodeString(dataStr)
		if err != nil {
			panic(err)
		}
		b, err := k.Decrypt([]byte(dataRaw))
		if err != nil {
			panic(err)
		}
		fmt.Println(string(b))
	}
}

func readSecret(msg string) string {
	sec, err := gopass.GetPasswdPrompt(msg, true, os.Stdin, os.Stderr)
	if len(sec) == 0 || err == gopass.ErrInterrupted {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return string(sec)
}
