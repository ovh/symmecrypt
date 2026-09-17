package aesgcmsiv

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ovh/symmecrypt"
)

// rfc8452Vectors are the AEAD_AES_256_GCM_SIV test vectors from RFC 8452,
// Appendix C.2, plus the AES-256 counter wrap tests from Appendix C.3.
// result is ciphertext||tag, without the nonce.
var rfc8452Vectors = []struct {
	key, nonce, plaintext, aad, result string
}{
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "",
		aad:       "",
		result:    "07f5f4169bbf55a8400cd47ea6fd400f",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "0100000000000000",
		aad:       "",
		result:    "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "010000000000000000000000",
		aad:       "",
		result:    "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "01000000000000000000000000000000",
		aad:       "",
		result:    "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "0100000000000000000000000000000002000000000000000000000000000000",
		aad:       "",
		result: "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f" +
			"e819e63abcd020b006a976397632eb5d",
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "030000000000000000000000",
		plaintext: "0100000000000000000000000000000002000000000000000000000000000000" +
			"03000000000000000000000000000000",
		aad: "",
		result: "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3" +
			"9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "030000000000000000000000",
		plaintext: "0100000000000000000000000000000002000000000000000000000000000000" +
			"0300000000000000000000000000000004000000000000000000000000000000",
		aad: "",
		result: "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7" +
			"e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce" +
			"112864c269fc0d9d88c61fa47e39aa08",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "0200000000000000",
		aad:       "01",
		result:    "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "020000000000000000000000",
		aad:       "01",
		result:    "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "02000000000000000000000000000000",
		aad:       "01",
		result:    "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "0200000000000000000000000000000003000000000000000000000000000000",
		aad:       "01",
		result: "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365" +
			"aea1bad12702e1965604374aab96dbbc",
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "030000000000000000000000",
		plaintext: "0200000000000000000000000000000003000000000000000000000000000000" +
			"04000000000000000000000000000000",
		aad: "01",
		result: "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47" +
			"fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb",
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "030000000000000000000000",
		plaintext: "0200000000000000000000000000000003000000000000000000000000000000" +
			"0400000000000000000000000000000005000000000000000000000000000000",
		aad: "01",
		result: "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9" +
			"8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89" +
			"5bde0285037c5de81e5b570a049b62a0",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "02000000",
		aad:       "010000000000000000000000",
		result:    "22b3f4cd1835e517741dfddccfa07fa4661b74cf",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "0300000000000000000000000000000004000000",
		aad:       "010000000000000000000000000000000200",
		result: "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59" +
			"cabfe307",
	},
	{
		key:       "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:     "030000000000000000000000",
		plaintext: "030000000000000000000000000000000400",
		aad:       "0100000000000000000000000000000002000000",
		result: "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc205" +
			"6543",
	},
	{
		key:       "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
		nonce:     "e0eaf5284d884a0e77d31646",
		plaintext: "",
		aad:       "",
		result:    "169fbb2fbf389a995f6390af22228a62",
	},
	{
		key:       "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
		nonce:     "e4b47801afc0577e34699b9e",
		plaintext: "671fdd",
		aad:       "4fbdc66f14",
		result:    "0eaccb93da9bb81333aee0c785b240d319719d",
	},
	{
		key:       "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
		nonce:     "2f6d1f0434d8848c1177441f",
		plaintext: "195495860f04",
		aad:       "6787f3ea22c127aaf195",
		result:    "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c",
	},
	{
		key:       "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
		nonce:     "9f572c614b4745914474e7c7",
		plaintext: "c9882e5386fd9f92ec",
		aad:       "489c8fde2be2cf97e74e932d4ed87d",
		result:    "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2",
	},
	{
		key:       "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
		nonce:     "5c9e940fea2f582950a70d5a",
		plaintext: "1db2316fd568378da107b52b",
		aad:       "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
		result:    "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5",
	},
	{
		key:       "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
		nonce:     "6de71860f762ebfbd08284e4",
		plaintext: "21702de0de18baa9c9596291b08466",
		aad:       "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
		result:    "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
	},
	{
		key:       "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
		nonce:     "028ec6eb5ea7e298342a94d4",
		plaintext: "b202b370ef9768ec6561c4fe6b7e7296fa85",
		aad:       "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
		result: "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d" +
			"0a49",
	},
	{
		key:       "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
		nonce:     "688089e55540db1872504e1c",
		plaintext: "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
		aad: "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f" +
			"167541",
		result: "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1d" +
			"ed1a286594",
	},
	{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		nonce:     "000000000000000000000000",
		plaintext: "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
		aad:       "",
		result: "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea" +
			"ffffffff000000000000000000000000",
	},
	{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		nonce:     "000000000000000000000000",
		plaintext: "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
		aad:       "",
		result: "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff00000000" +
			"0000000000000000",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex in test vector: %v", err)
	}
	return b
}

func TestRFC8452Vectors(t *testing.T) {
	for i, v := range rfc8452Vectors {
		key := mustHex(t, v.key)
		nonce := mustHex(t, v.nonce)
		plaintext := mustHex(t, v.plaintext)
		aad := mustHex(t, v.aad)
		result := mustHex(t, v.result)

		g, err := newGCMSIV(key)
		if err != nil {
			t.Fatalf("vector %d: newGCMSIV: %v", i, err)
		}

		ct := g.Seal(nil, nonce, plaintext, aad)
		if !bytes.Equal(ct, result) {
			t.Errorf("vector %d: Seal mismatch\ngot  %x\nwant %x", i, ct, result)
		}

		pt, err := g.Open(nil, nonce, result, aad)
		if err != nil {
			t.Fatalf("vector %d: Open: %v", i, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Errorf("vector %d: Open mismatch\ngot  %x\nwant %x", i, pt, plaintext)
		}
	}
}

func TestOpenRejectsTamperedData(t *testing.T) {
	v := rfc8452Vectors[len(rfc8452Vectors)-1]
	key, nonce, aad, result := mustHex(t, v.key), mustHex(t, v.nonce), mustHex(t, v.aad), mustHex(t, v.result)

	g, err := newGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}

	// flip every bit of the ciphertext
	for i := range result {
		for j := 0; j < 8; j++ {
			result[i] ^= 1 << j
			if _, err := g.Open(nil, nonce, result, aad); err == nil {
				t.Fatalf("expected authentication error flipping byte %d bit %d", i, j)
			}
			result[i] ^= 1 << j
		}
	}

	// truncations
	for i := 0; i < len(result); i++ {
		if _, err := g.Open(nil, nonce, result[:i], aad); err == nil {
			t.Fatalf("expected error on ciphertext truncated to %d bytes", i)
		}
	}

	// tampered AAD
	for i := range aad {
		aad[i] ^= 0x01
		if _, err := g.Open(nil, nonce, result, aad); err == nil {
			t.Fatalf("expected authentication error with tampered AAD at byte %d", i)
		}
		aad[i] ^= 0x01
	}
}

func TestInvalidKeySizes(t *testing.T) {
	for _, size := range []int{0, 8, 15, 17, 24, 31, 33, 64} {
		if _, err := newGCMSIV(make([]byte, size)); err == nil {
			t.Errorf("expected error with key size %d", size)
		}
	}
}

func TestSymmecryptRoundTrip(t *testing.T) {
	k, err := symmecrypt.NewRandomKey(CipherName)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := k.Encrypt([]byte("foobar"), []byte("extra"))
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := k.Decrypt(encrypted, []byte("extra"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "foobar" {
		t.Errorf("expected foobar, got %q", decrypted)
	}

	if _, err := k.Decrypt(encrypted, []byte("wrong extra")); err == nil {
		t.Error("expected authentication error with wrong extra data")
	}
	if _, err := k.Decrypt(encrypted); err == nil {
		t.Error("expected authentication error with missing extra data")
	}
}

// TestSequenceKeyIsDeterministic encodes why this cipher is suitable for
// convergent encryption: with deterministic (sequential) nonces, identical
// plaintexts must produce identical ciphertexts, and nonce reuse must not
// compromise the key (SIV nonce-misuse resistance).
func TestSequenceKeyIsDeterministic(t *testing.T) {
	f, err := symmecrypt.GetKeyFactory(CipherName)
	if err != nil {
		t.Fatal(err)
	}

	rawKey := mustHex(t, rfc8452Vectors[0].key)

	k1, err := f.NewSequenceKey(string(rawKey))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := f.NewSequenceKey(string(rawKey))
	if err != nil {
		t.Fatal(err)
	}

	c1, err := k1.Encrypt([]byte("identical plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := k2.Encrypt([]byte("identical plaintext"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(c1, c2) {
		t.Error("sequence keys with the same material should produce identical ciphertexts")
	}

	pt, err := k2.Decrypt(c1)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "identical plaintext" {
		t.Errorf("unexpected plaintext %q", pt)
	}
}
