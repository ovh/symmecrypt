package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"

	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/ovh/symmecrypt/stream"
)

// writerOnly masks any Closer implemented by the underlying writer.
type writerOnly struct{ io.Writer }

// runCrypt implements both encrypt and decrypt: the two commands share the
// exact same flag surface and only differ by the direction of the operation.
func runCrypt(encrypting bool, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	name := "encrypt"
	if !encrypting {
		name = "decrypt"
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	keyID := fs.String("key", "", "key identifier (required only if several identifiers are loaded)")
	keyFile := fs.String("key-file", "", "key config file (default: "+encryptionKeyEnv+" env var)")
	configFile := fs.String("config", "", "configstore file containing the key configs")
	var extras stringsFlag
	fs.Var(&extras, "extra", "extra data for MAC; must match between encrypt and decrypt (repeatable)")
	useBase64 := fs.Bool("base64", false, "base64-wrap the ciphertext (output of encrypt, input of decrypt)")
	inPath := fs.String("in", "-", "input file ('-' for stdin)")
	outPath := fs.String("out", "-", "output file ('-' for stdout)")
	useStream := fs.Bool("stream", false, "chunked stream format for large inputs; NOT compatible with the non-stream format")
	sealFile := fs.String("seal-file", "", "seal config file (required if the key configs are sealed)")
	var shards, shardFiles stringsFlag
	fs.Var(&shards, "shard", "seal shard (repeatable)")
	fs.Var(&shardFiles, "shard-file", "file containing seal shards, one per line (repeatable)")
	usage := usageOf(fs, fmt.Sprintf("Usage: symmecrypt %s [flags]\n\n%s data from stdin (or --in) to stdout (or --out).\n", name, map[bool]string{true: "Encrypt", false: "Decrypt"}[encrypting]))

	if err := parseFlags(fs, usage, args, stdout); err != nil {
		return err
	}

	cfgs, err := loadKeyConfigs(*keyFile, *configFile, false, stdin)
	if err != nil {
		return err
	}
	cfgs, err = selectIdentifier(cfgs, *keyID)
	if err != nil {
		return err
	}
	cfgs, err = unsealConfigs(cfgs, *sealFile, shards, shardFiles)
	if err != nil {
		return err
	}
	k, err := keyloader.NewKey(cfgs...)
	if err != nil {
		return err
	}

	extraBytes := make([][]byte, 0, len(extras))
	for _, e := range extras {
		extraBytes = append(extraBytes, []byte(e))
	}

	in, err := openInput(*inPath, stdin)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := openOutput(*outPath, stdout)
	if err != nil {
		return err
	}

	if encrypting {
		err = doEncrypt(k, in, out, extraBytes, *useBase64, *useStream)
	} else {
		err = doDecrypt(k, in, out, extraBytes, *useBase64, *useStream)
	}
	if err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func doEncrypt(k symmecrypt.Key, in io.Reader, out io.Writer, extras [][]byte, useBase64, useStream bool) error {
	var b64 io.WriteCloser
	if useBase64 {
		b64 = base64.NewEncoder(base64.StdEncoding, out)
		out = b64
	}

	if useStream {
		// hide the Closer from stream.NewWriter: its Close would also close
		// the destination, which runCrypt already manages
		sw := stream.NewWriter(writerOnly{out}, k, stream.ChunkSize, extras...)
		if _, err := io.Copy(sw, in); err != nil {
			return err
		}
		// Close order matters: the stream writer flushes the last chunk into
		// the base64 encoder, which then flushes its padding.
		if err := sw.Close(); err != nil {
			return err
		}
	} else {
		data, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		encrypted, err := k.Encrypt(data, extras...)
		if err != nil {
			return err
		}
		if _, err := out.Write(encrypted); err != nil {
			return err
		}
	}

	if b64 != nil {
		return b64.Close()
	}
	return nil
}

func doDecrypt(k symmecrypt.Key, in io.Reader, out io.Writer, extras [][]byte, useBase64, useStream bool) error {
	if useBase64 {
		in = base64.NewDecoder(base64.StdEncoding, in)
	}

	if useStream {
		sr := stream.NewReader(in, k, stream.ChunkSize, extras...)
		_, err := io.Copy(out, sr)
		return err
	}

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	decrypted, err := k.Decrypt(data, extras...)
	if err != nil {
		return err
	}
	_, err = out.Write(decrypted)
	return err
}
