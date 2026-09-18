package keyloader_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/keyloader"
)

// TestWatchErrorLogIsFormatted encodes the logging contract: LogErrorFunc is
// Println-style (default: log.Println), so call sites must pre-format their
// message. Passing printf-style format verbs produces garbled logs like
// "error for key '%s': %s watch-log-test <err>".
func TestWatchErrorLogIsFormatted(t *testing.T) {
	var mu sync.Mutex
	var messages []string
	orig := symmecrypt.LogErrorFunc
	symmecrypt.LogErrorFunc = func(v ...interface{}) {
		mu.Lock()
		messages = append(messages, strings.TrimSpace(fmt.Sprintln(v...)))
		mu.Unlock()
	}
	t.Cleanup(func() { symmecrypt.LogErrorFunc = orig })

	store := configstore.NewStore()
	inmem := store.InMemory("test")
	inmem.Add(configstore.NewItem(
		keyloader.EncryptionKeyConfigName,
		`{"key":"5fdb8af280b007a46553dfddb3f42bc10619dcabca8d4fdf5239b09445ab1a41","identifier":"watch-log-test","sealed":false,"timestamp":1522325806,"cipher":"aes-gcm"}`,
		1,
	))

	if _, err := keyloader.WatchKeyFromStore("watch-log-test", store); err != nil {
		t.Fatal(err)
	}

	// poison the store with a conflicting revision (same identifier, same
	// timestamp) so the watch reload fails and logs an error
	inmem.Add(configstore.NewItem(
		keyloader.EncryptionKeyConfigName,
		`{"key":"7db2b4b695e11563edca94b0f9c7ad16919fc11eac414c1b1706cbaa3c3e61a4","identifier":"watch-log-test","sealed":false,"timestamp":1522325806,"cipher":"aes-gcm"}`,
		1,
	))
	var got string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// re-notify each round: the watch goroutine registers its watcher
		// channel asynchronously and may miss an early notification
		store.NotifyWatchers()
		mu.Lock()
		if len(messages) > 0 {
			got = messages[0]
		}
		mu.Unlock()
		if got != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == "" {
		t.Fatal("no error was logged by the watch reload failure")
	}

	if strings.Contains(got, "%s") || strings.Contains(got, "%v") || strings.Contains(got, "%w") {
		t.Fatalf("log message contains unexpanded format verbs: %q", got)
	}
	if !strings.Contains(got, "watch-log-test") {
		t.Fatalf("log message should name the key identifier: %q", got)
	}
}
