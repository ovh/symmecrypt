package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aespmacsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/keyloader"
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

	quiet = app.Flag("quiet", "no prompts").Bool()
)

func main() {

	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch cmd {
	case newEncryption.FullCommand():
		key, err := keyloader.GenerateKey(*newEncryptionCipher, *newEncryptionIdentifier, false, time.Now())
		if err != nil {
			log.Fatalf("error: unable to generate key: %s", err)
		}
		j, err := json.Marshal(key)
		if err != nil {
			log.Fatalf("error: unable to generate key: %s", err)
		}
		fmt.Println(string(j))

	case encrypt.FullCommand():
		keyStr := readSecret("Encryption key: ")
		k, err := symmecrypt.NewKey(*encryptCipher, keyStr)
		if err != nil {
			log.Fatalf("error: failed to instantiate key: %s", err)
		}
		dataStr := readSecret("Data to encrypt: ")
		b, err := k.Encrypt([]byte(dataStr))
		if err != nil {
			log.Fatalf("error: failed to encrypt: %s", err)
		}
		fmt.Println(hex.EncodeToString(b))

	case decrypt.FullCommand():
		keyStr := readSecret("Encryption key: ")
		k, err := symmecrypt.NewKey(*decryptCipher, keyStr)
		if err != nil {
			log.Fatalf("error: failed to instantiate key: %s", err)
		}
		dataStr := readSecret("hex data to decrypt: ")
		dataRaw, err := hex.DecodeString(dataStr)
		if err != nil {
			log.Fatalf("error: failed to decode hex: %s", err)
		}
		b, err := k.Decrypt([]byte(dataRaw))
		if err != nil {
			log.Fatalf("error: failed to decrypt: %s", err)
		}
		fmt.Println(string(b))
	}
}

func readSecret(msg string) string {
	masked := true
	if *quiet {
		msg = ""
		masked = false
	}
	sec, err := gopass.GetPasswdPrompt(msg, masked, os.Stdin, os.Stderr)
	if len(sec) == 0 || err == gopass.ErrInterrupted {
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("error: failed to read input: %s", err)
	}
	return string(sec)
}
