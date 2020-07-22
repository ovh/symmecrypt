package hmac

import (
	"fmt"
	"testing"

	"github.com/ovh/symmecrypt"
)

func TestEncrypt(t *testing.T) {
	
	text := []byte("foobar")

	k, err := symmecrypt.NewRandomKey(CipherName)
	if err != nil {
		t.Fatal(err)
	}

	extra := []byte("baz")

	encr, err := k.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	encrExtra, err := k.Encrypt(text, extra)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(encr), len(encr))

	decr, err := k.Decrypt(encr)
	if err != nil {
		t.Fatal(err)
	}

	decrExtra, err := k.Decrypt(encrExtra, extra)
	if err != nil {
		t.Fatal(err)
	}

	if string(decr) != string(text) {
		t.Fatalf("text mismatch: %s", string(decr))
	}

	if string(decrExtra) != string(text) {
		t.Fatalf("text mismatch: %s", string(decr))
	}

	encr[3] = 'g'

	_, err = k.Decrypt(encr)
	if err == nil {
		t.Fatal("Altered data passed mac check")
	}

	_, err = k.Decrypt(encrExtra)
	if err == nil {
		t.Fatal("decrypt success with missing extra data")
	}

	extra[2] = 'h'

	_, err = k.Decrypt(encrExtra, extra)
	if err == nil {
		t.Fatal("Altered extra data passed mac check")
	}
}
