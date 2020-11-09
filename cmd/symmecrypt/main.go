package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aespmacsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
)

const (
	EncryptionKeyBase64Env = "ENCRYPTION_KEY_BASE64"
)

var (
	DefaultCipher = aesgcm.CipherName
	ciphers       = []string{aesgcm.CipherName, chacha20poly1305.CipherName, xchacha20poly1305.CipherName, aespmacsiv.CipherName, hmac.CipherName}

	app = kingpin.New("symmecrypt", fmt.Sprintf(`A command-line utility tied to the symmecrypt library (https://github.com/ovh/symmecrypt). Generate new keys, and encrypt/decrypt arbitrary data.
	Available ciphers: %s (default: %s).
	For encrypt/decrypt, encryption keys are expected as a comma-separated list of base64-encoded keys in the environment variable ENCRYPTION_KEY_BASE64.
	Key identifiers can optionally be specified to choose which key to use, and in case several revisions of the same key identifier are present in the environment variable, normal fallback/priority rules are applied using timestamps, as specified in the documentation (https://github.com/ovh/symmecrypt).

Example:
	$ export ENCRYPTION_KEY_BASE64=$(symmecrypt new aes-gcm --base64)
	$ symmecrypt encrypt <<EOF >test.encrypted
	foo
	bar
	baz
	EOF
	$ cat -e test.encrypted
	^^JDM-1^EM-$M-^K1nX;^WM-^HC6^Xw^?^BM-.M-p^[M-%%=^M-^ZM-uM-%%M-2^H6M-sM-NM-FM-^H^RM-]g^_&$
	$ symmecrypt decrypt <test.encrypted
	foo
	bar
	baz
`, strings.Join(ciphers, ", "), DefaultCipher))

	useBase64     = app.Flag("base64", "Use base64 encoding for input/output.").Default("false").Bool()
	keyIdentifier = app.Flag("key", "Specify the identifier of the encryption key").String()

	newEncryption       = app.Command("new", "Generate a new random encryption key.")
	newEncryptionCipher = newEncryption.Arg("cipher", "Cipher for the key").Default(DefaultCipher).Enum(ciphers...)

	encrypt      = app.Command("encrypt", "Encrypt arbitrary data from STDIN. The output will be the encrypted data.")
	encryptExtra = encrypt.Flag("extra", "Extra metadata for MAC (decryption will fail unless the same extra data is passed when decrypting).").Strings()

	decrypt      = app.Command("decrypt", "Decrypt data from STDIN. The output will be the plain data.")
	decryptExtra = decrypt.Flag("extra", "Extra metadata for MAC (decryption will fail unless the same extra data that was used when encrypting is passed).").Strings()
)

func readKey() error {
	keyEnv := os.Getenv(EncryptionKeyBase64Env)
	if keyEnv == "" {
		return fmt.Errorf("No encryption key found in env '%s'", EncryptionKeyBase64Env)
	}
	keys := strings.Split(keyEnv, ",")
	keyList := []configstore.Item{}
	for _, encodedKey := range keys {
		plain, err := base64.StdEncoding.DecodeString(encodedKey)
		if err != nil {
			return fmt.Errorf("Invalid base64 encryption key: %w", err)
		}
		keyList = append(keyList, configstore.NewItem("encryption-key", string(plain), 1))
	}
	configstore.RegisterProvider("env", func() (configstore.ItemList, error) {
		return configstore.ItemList{
			Items: keyList,
		}, nil
	})
	return nil
}

func main() {

	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch cmd {
	case newEncryption.FullCommand():
		if *keyIdentifier == "" {
			*keyIdentifier = "default"
		}
		key, err := keyloader.GenerateKey(*newEncryptionCipher, *keyIdentifier, false, time.Now())
		if err != nil {
			log.Fatalf("error: unable to generate key: %v", err)
		}
		j, err := json.Marshal(key)
		if err != nil {
			log.Fatalf("error: unable to generate key: %v", err)
		}
		newKey := string(j)
		if *useBase64 {
			newKey = base64.StdEncoding.EncodeToString([]byte(newKey))
		}
		fmt.Println(newKey)

	case encrypt.FullCommand():
		err := readKey()
		if err != nil {
			log.Fatal(err)
		}
		var k symmecrypt.Key
		if *keyIdentifier != "" {
			k, err = keyloader.LoadKey(*keyIdentifier)
		} else {
			k, err = keyloader.LoadSingleKey()
		}
		if err != nil {
			log.Fatalf("error: failed to instantiate key: %v", err)
		}
		dataStr := readSecret()
		extra := [][]byte{}
		for _, ext := range *encryptExtra {
			extra = append(extra, []byte(ext))
		}
		b, err := k.Encrypt([]byte(dataStr), extra...)
		if err != nil {
			log.Fatalf("error: failed to encrypt: %v", err)
		}
		outputStr := string(b)
		if *useBase64 {
			outputStr = base64.StdEncoding.EncodeToString(b)
		}
		fmt.Print(outputStr)

	case decrypt.FullCommand():
		err := readKey()
		if err != nil {
			log.Fatal(err)
		}
		var k symmecrypt.Key
		if *keyIdentifier != "" {
			k, err = keyloader.LoadKey(*keyIdentifier)
		} else {
			k, err = keyloader.LoadSingleKey()
		}
		if err != nil {
			log.Fatalf("error: failed to instantiate key: %v", err)
		}
		dataStr := readSecret()
		if *useBase64 {
			dataRaw, err := base64.StdEncoding.DecodeString(dataStr)
			if err != nil {
				log.Fatalf("error: failed to decode base64: %v", err)
			}
			dataStr = string(dataRaw)
		}
		extra := [][]byte{}
		for _, ext := range *decryptExtra {
			extra = append(extra, []byte(ext))
		}
		b, err := k.Decrypt([]byte(dataStr), extra...)
		if err != nil {
			log.Fatalf("error: failed to decrypt: %v", err)
		}
		fmt.Print(string(b))
	}
}

func readSecret() string {
	b, err := ioutil.ReadAll(os.Stdin)
	if len(b) == 0 {
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("error: failed to read input: %v", err)
	}
	return string(b)
}
