package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ovh/configstore"

	"github.com/ovh/symmecrypt/ciphers/aesgcm"
	"github.com/ovh/symmecrypt/ciphers/aesgcmsiv"
	"github.com/ovh/symmecrypt/ciphers/chacha20poly1305"
	"github.com/ovh/symmecrypt/ciphers/hmac"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
)

const encryptionKeyEnv = "ENCRYPTION_KEY_BASE64"

var ciphers = []string{
	aesgcm.CipherName,
	aesgcmsiv.CipherName,
	chacha20poly1305.CipherName,
	xchacha20poly1305.CipherName,
	hmac.CipherName,
}

var rootUsage = fmt.Sprintf(`symmecrypt - symmetric encryption toolsuite (https://github.com/ovh/symmecrypt)

Usage: symmecrypt <command> [flags]

Commands:
  key new       generate a new random encryption key config
  key rotate    add a new revision to an existing key (key rollover)
  key inspect   show key config metadata (never prints key material)
  key seal      seal key config(s) with a shamir seal
  key unseal    unseal key config(s)
  encrypt       encrypt data (stdin/--in to stdout/--out)
  decrypt       decrypt data (stdin/--in to stdout/--out)
  seal new      generate a new shamir seal and its shards
  help          show this help, or a command help (e.g. 'symmecrypt help key')

Key sources for encrypt/decrypt (in order of precedence):
  --key-file PATH   key config(s): JSON lines or base64 items
  --config PATH     configstore file ('- key: encryption-key' items)
  %s env var: comma-separated base64-encoded key config JSONs

Available ciphers: %s (default: %s)

Examples:
  export %s=$(symmecrypt key new --base64)
  echo hello | symmecrypt encrypt --base64 | symmecrypt decrypt --base64
  symmecrypt encrypt --stream --in big.tar --out big.tar.enc
`, encryptionKeyEnv, joinCiphers(), keyloader.DefaultCipher, encryptionKeyEnv)

func joinCiphers() string {
	out := ""
	for i, c := range ciphers {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

// usageError is returned on CLI misuse: main prints the relevant usage on
// stderr and exits with code 2.
type usageError struct {
	msg   string
	usage string
}

func (e usageError) Error() string { return e.msg }

func usageErrorf(usage, format string, args ...interface{}) usageError {
	return usageError{msg: fmt.Sprintf(format, args...), usage: usage}
}

// run dispatches the CLI. It is the single entrypoint used by main and tests:
// no global state, everything flows through the given streams.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErrorf(rootUsage, "missing command")
	}

	switch args[0] {
	case "key":
		return cmdKey(args[1:], stdin, stdout, stderr)
	case "seal":
		return cmdSeal(args[1:], stdout, stderr)
	case "encrypt":
		return runCrypt(true, args[1:], stdin, stdout, stderr)
	case "decrypt":
		return runCrypt(false, args[1:], stdin, stdout, stderr)
	case "help", "-h", "--help":
		if len(args) > 1 {
			return run(append(args[1:], "--help"), stdin, stdout, stderr)
		}
		fmt.Fprint(stdout, rootUsage)
		return nil
	default:
		return usageErrorf(rootUsage, "unknown command '%s'", args[0])
	}
}

func main() {
	// silence configstore's informational logging (std log goes to stderr)
	configstore.LogInfoFunc = func(string, ...interface{}) {}

	err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		// help was requested and printed by the FlagSet
	default:
		var uErr usageError
		if errors.As(err, &uErr) {
			fmt.Fprintf(os.Stderr, "symmecrypt: error: %s\n\n%s", uErr.msg, uErr.usage)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "symmecrypt: error: %v\n", err)
		os.Exit(1)
	}
}
