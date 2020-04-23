package symmecrypt_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/pelletier/go-toml"
	yaml "gopkg.in/yaml.v2"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/keyloader"
)

func ProviderTest() (configstore.ItemList, error) {
	ret := configstore.ItemList{
		Items: []configstore.Item{
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"test","sealed":false,"timestamp":1522325806,"cipher":"aes-gcm"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"7db2b4b695e11563edca94b0f9c7ad16919fc11eac414c1b1706cbaa3c3e61a4b884301ae4e8fbedcc4f000b9c52904f13ea9456379d373524dea7fef79b39f7","identifier":"test-composite","sealed":false,"timestamp":1522325758,"cipher":"aes-pmac-siv"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"QXdDW4N/jmJzpMu7i1zu4YF1opTn7H+eOk9CLFGBSFg=","identifier":"test-composite","sealed":false,"timestamp":1522325802,"cipher":"xchacha20-poly1305"}`,
				1,
			),
		},
	}
	return ret, nil
}

// Bad config: conflicting timestamps
func ProviderTestKOTimestamp() (configstore.ItemList, error) {
	ret := configstore.ItemList{
		Items: []configstore.Item{
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"test","sealed":false,"timestamp":1,"cipher":"aes-gcm"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"QXdDW4N/jmJzpMu7i1zu4YF1opTn7H+eOk9CLFGBSFg=","identifier":"test","sealed":false,"timestamp":1,"cipher":"xchacha20-poly1305"}`,
				1,
			),
		},
	}
	return ret, nil
}

// Bad config: latest key non sealed
func ProviderTestKOSeal() (configstore.ItemList, error) {
	ret := configstore.ItemList{
		Items: []configstore.Item{
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"test","sealed":false,"timestamp":2,"cipher":"aes-gcm"}`,
				1,
			),
			configstore.NewItem(
				keyloader.EncryptionKeyConfigName,
				`{"key":"QXdDW4N/jmJzpMu7i1zu4YF1opTn7H+eOk9CLFGBSFg=","identifier":"test","sealed":true,"timestamp":1,"cipher":"xchacha20-poly1305"}`,
				1,
			),
		},
	}
	return ret, nil
}

var KOTests = map[string]func() (configstore.ItemList, error){
	"timestamp": ProviderTestKOTimestamp,
	"seal":      ProviderTestKOSeal,
}

func TestMain(m *testing.M) {

	configstore.RegisterProvider("test", ProviderTest)

	os.Exit(m.Run())
}

func TestEncryptDecrypt(t *testing.T) {
	text := []byte("eoeodecrytp")

	extra := []byte("aa")
	extra2 := []byte("bb")

	k, err := keyloader.LoadKey("test")
	if err != nil {
		t.Fatal(err)
	}

	encr, err := k.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	encrExtra, err := k.Encrypt(text, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}

	decr, err := k.Decrypt(encr)
	if err != nil {
		t.Fatal(err)
	}

	decrExtra, err := k.Decrypt(encrExtra, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = k.Decrypt(encrExtra)
	if err == nil {
		t.Fatal("successfully decrypted cipher+extra without using extra -> ERROR")
	}

	_, err = k.Decrypt(encrExtra, []byte("cc"), []byte("dd"))
	if err == nil {
		t.Fatal("successfully decrypted cipher+extra using wrong extra -> ERROR")
	}

	_, err = k.Decrypt(encr, extra, extra2)
	if err == nil {
		t.Fatal("succerssfully decrypted cipher while using extra data -> ERROR")
	}

	if string(decr) != string(text) {
		t.Errorf("not equal when decrypt text encrypted,  %s != %s", text, decr)
	}

	if string(decrExtra) != string(text) {
		t.Errorf("not equal when decrypt text encrypted [extra data],  %s != %s", text, decrExtra)
	}
}

type testObfuscate struct {
	Name            string
	Amount          int
	InterfaceNumber interface{}
}

func TestEncryptDecryptMarshal(t *testing.T) {

	k, err := keyloader.LoadKey("test")
	if err != nil {
		t.Fatal(err)
	}

	origin := &testObfuscate{
		Name:            "test",
		Amount:          10,
		InterfaceNumber: 2345678954,
	}

	extra := []byte("aa")
	extra2 := []byte("bb")

	r, err := k.EncryptMarshal(origin)
	if err != nil {
		t.Fatal(err)
	}

	rExtra, err := k.EncryptMarshal(origin, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}

	target := &testObfuscate{}
	targetExtra := &testObfuscate{}

	err = k.DecryptMarshal(r, target)
	if err != nil {
		t.Fatal(err)
	}

	err = k.DecryptMarshal(rExtra, targetExtra, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}

	err = k.DecryptMarshal(rExtra, targetExtra)
	if err == nil {
		t.Fatal("succerssfully decrypted cipher without using extra data -> ERROR")
	}

	if target.Name != origin.Name || target.Amount != origin.Amount || fmt.Sprint(origin.InterfaceNumber) != fmt.Sprint(target.InterfaceNumber) {
		t.Errorf("Not same deobfuscated result %s, %d, %v", target.Name, target.Amount, target.InterfaceNumber)
	}
	if targetExtra.Name != origin.Name || targetExtra.Amount != origin.Amount || fmt.Sprint(origin.InterfaceNumber) != fmt.Sprint(targetExtra.InterfaceNumber) {
		t.Errorf("Not same deobfuscated result %s, %d, %v", targetExtra.Name, targetExtra.Amount, targetExtra.InterfaceNumber)
	}
}

func TestCompositeKey(t *testing.T) {

	kC, err := keyloader.LoadKey("test-composite")
	if err != nil {
		t.Fatal(err)
	}

	var k, k2 symmecrypt.Key

	comp, ok := kC.(symmecrypt.CompositeKey)
	if !ok {
		t.Fatal("Expected a composite key instance")
	}

	if len(comp) < 2 {
		t.Fatalf("composite len should be 2, got %d", len(comp))
	}

	k = comp[0]
	k2 = comp[1]

	text := []byte("eoeodecrytp")

	encr, err := kC.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	decr, err := kC.Decrypt(encr)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != string(decr) {
		t.Errorf("not equal when decrypt text encrypted,  %s != %s", text, decr)
	}

	decr1, err := k.Decrypt(encr)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != string(decr1) {
		t.Errorf("not equal when decrypt text encrypted,  %s != %s", text, decr1)
	}

	_, err = k2.Decrypt(encr)
	if err == nil {
		t.Fatal("successfully decrypted composite encrypt result with low-priority key -> ERROR")
	}

	encr2, err := k2.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	decr2, err := kC.Decrypt(encr2)
	if err != nil {
		t.Fatal(err)
	}

	if string(text) != string(decr2) {
		t.Errorf("not equal when decrypt text encrypted,  %s != %s", text, decr2)
	}

	extra := []byte("aa")
	extra2 := []byte("bb")

	encr3, err := k.Encrypt(text, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}

	decr3, err := kC.Decrypt(encr3, extra, extra2)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != string(decr3) {
		t.Errorf("not equal when decrypt text encrypted,  %s != %s", text, decr3)
	}

	_, err = kC.Decrypt(encr3)
	if err == nil {
		t.Fatal("successfully decrypted cipher+extra without using extra -> ERROR")
	}
}

// TestWriterWithEncoders is about testing symmecrypt directly coupled with json, yaml and toml encoder/decoder
func TestWriterWithEncoders(t *testing.T) {
	// Load a global key
	k, err := keyloader.LoadKey("test")
	if err != nil {
		t.Fatal(err)
	}

	// Define common interfaces to json, yaml, toml encoders and decoders
	type encoder interface {
		Encode(v interface{}) error
	}
	type decoder interface {
		Decode(v interface{}) error
	}

	// Define testscases
	var testcases = []struct {
		data    interface{}
		k       symmecrypt.Key
		extras  [][]byte
		encoder func(io.Writer) encoder
		decoder func(io.Reader) decoder
	}{
		{
			data: struct {
				A string
				B int
				C bool
			}{A: "A", B: 1, C: true},
			k:      k,
			extras: [][]byte{[]byte("aa"), []byte("bb")},
			encoder: func(w io.Writer) encoder {
				return yaml.NewEncoder(w)
			},
			decoder: func(r io.Reader) decoder {
				return yaml.NewDecoder(r)
			},
		}, {
			data: struct {
				A string
				B int
				C bool
			}{A: "A", B: 1, C: true},
			k:      k,
			extras: [][]byte{[]byte("aa"), []byte("bb")},
			encoder: func(w io.Writer) encoder {
				return json.NewEncoder(w)
			},
			decoder: func(r io.Reader) decoder {
				return json.NewDecoder(r)
			},
		}, {
			data: struct {
				A string
				B int
				C bool
			}{A: "AA", B: 11, C: false},
			k:      k,
			extras: [][]byte{[]byte("aa"), []byte("bb")},
			encoder: func(w io.Writer) encoder {
				return toml.NewEncoder(w)
			},
			decoder: func(r io.Reader) decoder {
				return toml.NewDecoder(r)
			},
		},
	}

	// Run the testcases
	for _, tt := range testcases {
		var writeBuf bytes.Buffer
		// Instanciate a writer and an encoder
		w := symmecrypt.NewWriter(&writeBuf, tt.k, tt.extras...)
		enc := tt.encoder(w)
		// Encode
		if err := enc.Encode(tt.data); err != nil {
			t.Fatal(err)
		}
		// Close (flush)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		// Instanciate a reader and an decoder
		r, err := symmecrypt.NewReader(&writeBuf, k, tt.extras...)
		if err != nil {
			t.Fatal(err)
		}
		dec := tt.decoder(r)

		var actual struct {
			A string
			B int
			C bool
		}

		// Decode
		if err := dec.Decode(&actual); err != nil {
			t.Fatal(err)
		}

		// Check
		if !reflect.DeepEqual(tt.data, actual) {
			t.Fatalf("expected: %+v but got %+v", tt.data, actual)
		}
	}
}

func TestKeyloaderKO(t *testing.T) {

	for testName, provider := range KOTests {
		st := configstore.NewStore()

		st.RegisterProvider("test", provider)

		_, err := keyloader.LoadKeyFromStore("test", st)
		if err == nil {
			t.Fatalf("nil error with KO config (%s)", testName)
		}
	}
}

func ExampleNewWriter() {
	k, err := keyloader.LoadKey("test")
	if err != nil {
		panic(err)
	}

	w := symmecrypt.NewWriter(os.Stdout, k)

	_, err = w.Write([]byte("secret content"))
	if err != nil {
		panic(err)
	}

	err = w.Close()
	if err != nil {
		panic(err)
	}
}

func ExampleNewReader() {
	k, err := keyloader.LoadKey("test")
	if err != nil {
		panic(err)
	}

	encryptedContent, err := k.Encrypt([]byte("secret content"))
	if err != nil {
		panic(err)
	}

	src := bytes.NewReader(encryptedContent)
	reader, err := symmecrypt.NewReader(src, k)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(os.Stdout, reader)
	if err != nil {
		panic(err)
	}
}
