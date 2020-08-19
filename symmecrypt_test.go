package symmecrypt_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ovh/configstore"
	toml "github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/convergent"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/stream"
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
				`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"test","sealed":false,"timestamp":10,"cipher":"aes-gcm"}`,
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
		// Instantiate a writer and an encoder
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
		// Instantiate a reader and an decoder
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

func TestSequentialEncryption(t *testing.T) {
	var content = "this is a very sensitive content"

	// The key will be Instantiate from the sha152 of the content
	hash, err := convergent.NewHash(strings.NewReader(content))
	require.NoError(t, err)

	// Prepare a keyloadConfig to be able to Instantiate the key properly
	cfg := convergent.ConvergentEncryptionConfig{
		Cipher: aesgcm.CipherName,
	}

	// Instantiate a Sequence key from the sha512
	k, err := convergent.NewKey(hash, cfg)
	require.NoError(t, err)
	require.NotNil(t, k)

	encryptedBuffer, err := k.Encrypt([]byte(content))
	require.NoError(t, err)

	// Due to the nonce, the same plain text with the same key won't be encrypted the same way
	encryptedBuffer2, err := k.Encrypt([]byte(content))
	require.NoError(t, err)
	assert.NotEqual(t, encryptedBuffer, encryptedBuffer2)

	// But if we reinitialize the key, it will encrypt the plain text in a deterministic way
	k, err = convergent.NewKey(hash, cfg)
	require.NoError(t, err)
	require.NotNil(t, k)
	encryptedBuffer3, err := k.Encrypt([]byte(content))
	require.NoError(t, err)
	require.Equal(t, encryptedBuffer, encryptedBuffer3)

	// Checks that all decrypted contents
	decContent, err := k.Decrypt(encryptedBuffer)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	decContent, err = k.Decrypt(encryptedBuffer2)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	decContent, err = k.Decrypt(encryptedBuffer3)
	require.NoError(t, err)
	require.Equal(t, content, string(decContent))

	t.Run("key reinitialization from config", func(t *testing.T) {
		// Dump the key configuration to string
		cfgBtes, err := json.Marshal(cfg)
		require.NoError(t, err)
		t.Logf("deterministic key config is : %s", string(cfgBtes))

		var cfg2 convergent.ConvergentEncryptionConfig

		t.Log(string(cfgBtes))

		// Marshal it as a KeyConfig
		err = json.Unmarshal(cfgBtes, &cfg2)
		require.NoError(t, err)

		// Reload the key from its configuration
		k, err = convergent.NewKey(hash, cfg2)
		require.NoError(t, err)
		// check encrypt/decrypt
		encryptedBufferBis, err := k.Encrypt([]byte(content))
		require.NoError(t, err)
		decContent, err = k.Decrypt(encryptedBufferBis)
		require.NoError(t, err)
		assert.Equal(t, content, string(decContent))
		// Check the deterministic nonce
		assert.Equal(t, encryptedBuffer, encryptedBufferBis)
	})

	t.Run("with multiple config", func(t *testing.T) {
		cfg1 := convergent.ConvergentEncryptionConfig{
			Cipher:    aesgcm.CipherName,
			Timestamp: time.Now().Unix(),
		}

		k, err := convergent.NewKey(hash, cfg1)
		require.NoError(t, err)

		encryptedBuffer1, err := k.Encrypt([]byte(content))
		require.NoError(t, err)

		cfg1.Timestamp = time.Now().Add(-1 * time.Minute).Unix()
		cfg2 := convergent.ConvergentEncryptionConfig{
			Cipher:      aesgcm.CipherName,
			Timestamp:   time.Now().Unix(),
			SecretValue: "secret value",
		}

		k, err = convergent.NewKey(hash, cfg1, cfg2)
		require.NoError(t, err)

		encryptedBuffer2, err := k.Encrypt([]byte(content))
		require.NoError(t, err)

		// With the salt, the encyption should be equals to the encryption without salt
		assert.NotEqual(t, encryptedBuffer1, encryptedBuffer2)

		k, err = convergent.NewKey(hash, cfg1, cfg2)
		require.NoError(t, err)

		decryptedContent, err := k.Decrypt(encryptedBuffer1)
		require.NoError(t, err)

		require.Equal(t, []byte(content), decryptedContent)
	})
}

func TestWriteAndRead(t *testing.T) {
	var content = "this is a very sensitive content"

	k, err := keyloader.LoadKey("test")
	require.NoError(t, err)

	var buf bytes.Buffer
	w := symmecrypt.NewWriter(&buf, k)
	_, err = io.Copy(w, strings.NewReader(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := symmecrypt.NewReader(bytes.NewReader(buf.Bytes()), k)
	require.NoError(t, err)

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err)

	assert.Equal(t, content, out.String())
}

func TestChunksWriterAndChunksReader(t *testing.T) {
	var chunckSize = 11
	var content = "this is a very sensitive content"

	k, err := keyloader.LoadKey("test")
	require.NoError(t, err)

	var encryptedWriter bytes.Buffer
	cw := stream.NewWriter(&encryptedWriter, k, chunckSize)

	n, err := io.Copy(cw, strings.NewReader(content))
	require.NoError(t, err)

	err = cw.Close()
	require.NoError(t, err)

	encryptedContent := encryptedWriter.Bytes()
	t.Logf("%d bytes encrypted: %x", n, encryptedContent)

	decryptedOutput := bytes.Buffer{}
	cr := stream.NewReader(bytes.NewReader(encryptedContent), k, chunckSize)

	n, err = io.Copy(&decryptedOutput, cr)
	require.NoError(t, err)
	result := decryptedOutput.String()
	t.Logf("%d bytes decrypted: %s", n, result)

	assert.Equal(t, content, result)
}

func BenchmarkChunksWriter(b *testing.B) {
	var chunckSize = 10
	var content = "this is a very sensitive content"

	for n := 0; n < b.N; n++ {
		k, err := keyloader.LoadKey("test")
		require.NoError(b, err)

		var encryptedWriter bytes.Buffer
		cw := stream.NewWriter(&encryptedWriter, k, chunckSize)

		_, err = io.Copy(cw, strings.NewReader(content))
		require.NoError(b, err)

		err = cw.Close()
		require.NoError(b, err)
	}
}

func BenchmarkChunksReader(b *testing.B) {
	var chunckSize = 10
	var content = "this is a very sensitive content"

	k, err := keyloader.LoadKey("test")
	require.NoError(b, err)

	var encryptedWriter bytes.Buffer
	cw := stream.NewWriter(&encryptedWriter, k, chunckSize)

	n, err := io.Copy(cw, strings.NewReader(content))
	require.NoError(b, err)

	err = cw.Close()
	require.NoError(b, err)

	encryptedContent := encryptedWriter.Bytes()
	b.Logf("%d bytes encrypted: %x", n, encryptedContent)

	for n := 0; n < b.N; n++ {
		decryptedOutput := bytes.Buffer{}
		cr := stream.NewReader(bytes.NewReader(encryptedContent), k, chunckSize)
		_, err := io.Copy(&decryptedOutput, cr)
		require.NoError(b, err)
		result := decryptedOutput.String()
		assert.Equal(b, content, result)
	}
}
