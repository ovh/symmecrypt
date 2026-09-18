package keyloader_test

import (
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/keyloader"
)

// TestWatchKeyCloseStopsGoroutine encodes the resource contract of WatchKey:
// each watch key runs a background reload goroutine for the lifetime of the
// key, so the key must be closable — otherwise every WatchKey call leaks a
// goroutine (and pins the key material) for the process lifetime, unbounded
// in per-tenant or per-request usage.
func TestWatchKeyCloseStopsGoroutine(t *testing.T) {
	store := configstore.NewStore()
	store.InMemory("test").Add(configstore.NewItem(
		keyloader.EncryptionKeyConfigName,
		`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"watch-test","sealed":false,"timestamp":1522325806,"cipher":"aes-gcm"}`,
		1,
	))

	before := runtime.NumGoroutine()

	const n = 10
	keys := make([]symmecrypt.Key, 0, n)
	for i := 0; i < n; i++ {
		k, err := keyloader.WatchKeyFromStore("watch-test", store)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}

	// sanity: the watch goroutines exist
	if got := runtime.NumGoroutine(); got < before+n {
		t.Fatalf("expected at least %d watch goroutines, have %d -> %d", n, before, got)
	}

	// the keys still work
	encrypted, err := keys[0].Encrypt([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys[0].Decrypt(encrypted); err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		closer, ok := k.(io.Closer)
		if !ok {
			t.Fatal("a watch key must implement io.Closer to release its watch goroutine")
		}
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
		// closing twice must be safe
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// goroutine exit is asynchronous: poll until they are gone
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watch goroutines leaked after Close: %d -> %d", before, runtime.NumGoroutine())
}
