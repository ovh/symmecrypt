# symmecrypt

*symmecrypt* is a symmetric encryption toolsuite.
It provides recommended implementations of crypto algorithms and facilities around configuration management
and encryption key lifecycle.

[![GoDoc](https://godoc.org/github.com/ovh/symmecrypt?status.svg)](https://godoc.org/github.com/ovh/symmecrypt) [![Go Report Card](https://goreportcard.com/badge/github.com/ovh/symmecrypt)](https://goreportcard.com/report/github.com/ovh/symmecrypt)

## Overview

* [*symmecrypt*](https://github.com/ovh/symmecrypt): Symmetrical encryption with MAC. Built-in cipher implementations provided, but extensible. Also provides a keyring mechanism for easy key rollover.
* [*symmecrypt/seal*](https://github.com/ovh/symmecrypt/tree/master/seal): Encryption through a symmetric key split in shards (shamir)
* [*symmecrypt/keyloader*](https://github.com/ovh/symmecrypt/tree/master/keyloader): Configuration manager that loads symmecrypt compatible keys from configuration, and supports key *seal* and *hot-reloading*.


## Dependencies

* [*configstore*](https://github.com/ovh/configstore): *symmecrypt/seal* and *symmecrypt/keyloader* provide configuration management facilities, that rely on the *configstore* library. It provides file system, in memory sources, as well as data source abstraction (*providers*), so that any piece of code can easily bridge it with its own configuration management.


## Example

```go
    k, err := keyloader.LoadKey("storage")
    if err != nil {
        panic(err)
    }

    encrypted, err := k.Encrypt([]byte("foobar"), []byte("additional"), []byte("mac"), []byte("data"))
    if err != nil {
        panic(err)
    }

    // decryption will fail if you do not provide the same additional data
    // of course, you can also encrypt/decrypt without additional data
    decrypted, err := k.Decrypt(encrypted, []byte("additional"), []byte("mac"), []byte("data"))
    if err != nil {
        panic(err)
    }

    // output: foobar
    fmt.Println(string(decrypted))
```

## Configuration format

Package `configstore` is used for sourcing and managing key configuration values.

```go
    // before loading a key by its identifier, package `configstore` needs to
    // be configured so it knows about possible configuration sources
    //
    // this would load keys from a file named "key.txt" that contains a key with
    // the identifier "storage":
    configstore.File("key.txt")
    // more options can be found here: https://github.com/ovh/configstore
    k, err := keyloader.LoadKey("storage")
```

`symmecrypt` looks for items in the config store that are of key `encryption-key`, its value is expected to be a JSON string containing the key itself.

If loading from a text file this would look like:

```
- key: encryption-key
  value: '{"identifier":"storage","cipher":"aes-gcm","timestamp":1559309532,"key":"b6a942c0c0c75cc87f37d9e880c440ac124e040f263611d9d236b8ed92e35521"}'
```

or when done in code:

```go
  item := configstore.NewItem("encryption-key", `{"identifier":"storage","cipher":"aes-gcm","timestamp":1559309532,"key":"b6a942c0c0c75cc87f37d9e880c440ac124e040f263611d9d236b8ed92e35521"}`, 0)
```

## Key rollover

It is important to be able to easily rollover keys when doing symmetric encryption.

For that, one needs to be able to keep decrypting old ciphertexts using the old key,
while encrypting new entries with a new, different key.

Then, the old ciphertexts should all be re-encrypted using the new key.

*symmecrypt* + *symmecrypt/keyloader* make that easy, by providing a keyring / composite key implementation that encrypts with the latest key, while decrypting with *any* key of the keyring.

Encryption keys are fetched from the configuration, and are expected to have the following format:
```
    encryption-key: {"cipher":"aes-gcm","key":"442fca912da8309613542e7bb29788a44c162cde6ee4f0f5b1322132f65a2ddc","identifier":"storage","timestamp":1522138216}
    encryption-key: {"cipher":"aes-gcm","key":"49a9bc2774e7976c44f4bb6e1e3e6fc70e629be5923a511c8187b72bdc8f848c","identifier":"storage","timestamp":1522138240}
    
```
With this configuration, the previous example code would automatically instantiate a composite key through *keyloader.LoadKey()*, and be able to decrypt using either key, while all new encryptions would use the timestamp == 1522138240 key.


## Seal

If you do not want to rely on the confidentiality of your configuration to protect your encryption keys, you can *seal* them.

*symmecrypt/seal* provides encryption through a symmetric key which is split in several shards (shamir algorithm). The number of existing shards and the minimum threshold needed to unlock the seal can be configured when first generating it.

*symmecrypt/keyloader* uses *symmecrypt/seal* to generate and load encryption keys which are themselves encrypted. This is controlled via the *sealed* boolean property in a key configuration.

When generating a key via *symmecrypt/keyloader.GenerateKey*, use *sealed* = true. This will use the singleton global instance of the *symmecrypt/seal* package to directly seal the key.

When loading a key via *symmecrypt/keyloader.LoadKey*, the returned key will automatically decrypt itself and become usable as soon as the singleton global instance of *symmecrypt/seal* becomes unsealed (human operation).

A sealed encryption key is unusable on its own, which makes your configuration less at risk. Additionally, the metadata of the key (identifier, timestamp, cipher...) are passed as additional MAC data when encrypting/decrypting the key, preventing any alteration.


```
    seal:           {"min": 2, "total": 3, "nonce": "9cce8734c707881b1b00d24c3d9cee13"} // Seal definition
    encryption-key: {"cipher":"aes-gcm","key":"3414e0524c6a52018849b562b74e611748caf842dd653abc53469c986993f79d4406c662a1a7a9bef141ea88e0464e5bd79857f496418df81bb19ec391174af1d956603c7b8c2825a528972610b25483601c3083ef14c62c31e04f69","identifier":"storage","sealed":true,"timestamp":1522138887}
    encryption-key: {"cipher":"aes-gcm","key":"52ef448282bfbdaedcbda970a54b8626ef97a58ffc5489897554c8cba85cf4001d93b23751aaffb5ef2175192bb83ee7c0568634e8d0c7e4ae39f5102402d984220c64d4c6450b034b841844be818a6c5b0ef9016d92b9de1de5408c","identifier":"storage","sealed":true,"timestamp":1522138924}
    
```

These keys can be generated via *symmecrypt/keyloader.GenerateKey()*, and are recognized and correctly instantiated by *symmecrypt/keyloader.LoadKey()*.


## Supporting your old crypto code

If you want to start using *symmecrypt* but currently depend on another different implementation, no worries.
*symmecrypt* supports custom types/ciphers. You can register a named factory via *symmecrypt.RegisterCipher()*, which has to return an object respecting the *symmecrypt.Key* interface, and will be invoked by *symmecrypt/keyloader* when this cipher is specified in a key configuration.
That way, you can bridge your old code painlessly, and can get rid of the compatibility bridge once you rollover your encrypted data.

Or you can also decide to keep your own Key implementation, and use it through the keyloader that way.

Note: no matter its cipher (built-in or extended), a key can optionally be sealed without additional logic, this is all handled by *symmecrypt/keyloader* itself.


```
    seal:           {"min": 2, "total": 3, "nonce": "9cce8734c707881b1b00d24c3d9cee13"} // Seal definition
    encryption-key: {"cipher":"old-aes-algo","key":"3414e0524c6a52018849b562b74e611748caf842dd653abc53469c986993f79d4406c662a1a7a9bef141ea88e0464e5bd79857f496418df81bb19ec391174af1d956603c7b8c2825a528972610b25483601c3083ef14c62c31e04f69","identifier":"storage","sealed":true,"timestamp":1522138887}
    encryption-key: {"cipher":"aes-gcm","key":"52ef448282bfbdaedcbda970a54b8626ef97a58ffc5489897554c8cba85cf4001d93b23751aaffb5ef2175192bb83ee7c0568634e8d0c7e4ae39f5102402d984220c64d4c6450b034b841844be818a6c5b0ef9016d92b9de1de5408c","identifier":"storage","sealed":true,"timestamp":1522138924}

```

```go
    symmecrypt.RegisterCipher("old-aes-algo", OldAESFactory)

    k, err := keyloader.LoadKey("storage")
    if err != nil {
        panic(err)
    }

    encrypted, err := k.Encrypt([]byte("foobar"), []byte("additional"), []byte("mac"), []byte("data"))
    if err != nil {
        panic(err)
    }

    decrypted, err := k.Decrypt(encrypted, []byte("additional"), []byte("mac"), []byte("data"))
    if err != nil {
        panic(err)
    }

    // output: foobar
    fmt.Println(string(decrypted))
```

With such a configuration, any of your previous ciphertexts can be read using your old implementation, but any new data will be encrypted using *symmecrypt*'s aes-gcm implementation.


## Available ciphers

*symmecrypt* provides built-in implementations of symmetric authenticated ciphers:

### aes-gcm

Robust | Fast | Proven
--- | --- | ---
:star::star: | :star::star::star: | :star::star::star:

[AES Galois/Counter mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final) (256bits), with built-in authentication.

:exclamation: **Nonces are randomly generated and should not be repeated with *aes-gcm*, remember to rollover your key on a regular basis. Nonce size is 96 bits, which is not ideal for random generation due to the risk of collision, prefer *xchacha20-poly1305*.**

### chacha20-poly1305

Robust | Fast | Proven
--- | --- | ---
:star::star: | :star::star::star: | :star::star:

[ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539), with built-in authentication.

:exclamation: **Nonces are randomly generated and should not be repeated with *chacha20-poly1305*, remember to rollover your key on a regular basis. Nonce size is 96 bits, which is not ideal for random generation due to the risk of collision, prefer *xchacha20-poly1305*.**


### xchacha20-poly1305

Robust | Fast | Proven
--- | --- | ---
:star::star::star: | :star::star::star: | :star::star:

Variant of [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) with extended nonce, with built-in authentication.

:exclamation: **Nonces are randomly generated and should not be repeated with *xchacha20-poly1305*, remember to rollover your key on a regular basis. Nonce size is 192 bits, which is acceptable for random generation.**

### aes-gcm-siv

Robust | Fast | Proven
--- | --- | ---
:star::star::star: | :star::star: | :star::star:

[AES-GCM-SIV](https://tools.ietf.org/html/rfc8452) (256 bits), a nonce misuse-resistant AEAD, with built-in authentication.

:exclamation: **This is one of the rare ciphers which is not weak to nonce reuse: repeating a nonce only reveals whether two messages are identical, without compromising the key. Slower than *aes-gcm* (two passes over the data).**

### hmac

Robust | Fast | Proven
--- | --- | ---
:star::star::star: | :star::star::star: | :star::star::star:

:exclamation: **DOES NOT GUARANTEE CONFIDENTIALITY.**

HMAC-sha512 for authentication only. Note: if the input consists only of printable characters, so will the output.

## Command-line tool

A command-line tool is available as a companion to the library ([source](https://github.com/ovh/symmecrypt/tree/master/cmd/symmecrypt)).
It is also the quickest way to discover what the library does — each command below maps to a library concept.

```bash
go install github.com/ovh/symmecrypt/cmd/symmecrypt@latest
```

### Generate a key

`key new` produces a key configuration (the same JSON the library loads through *keyloader*):

```bash
$ symmecrypt key new --cipher aes-gcm --identifier storage
{"identifier":"storage","cipher":"aes-gcm","timestamp":1758124991,"key":"46ca74bf..."}
```

### Encrypt / decrypt

Keys are provided via `--key-file`, `--config` (configstore file) or the `ENCRYPTION_KEY_BASE64`
environment variable (comma-separated list of base64-encoded key configs):

```bash
$ export ENCRYPTION_KEY_BASE64=$(symmecrypt key new --base64)
$ echo hello | symmecrypt encrypt --base64 | symmecrypt decrypt --base64
hello
```

Extra data act as additional authenticated data (MAC): decryption fails unless the same values are passed.

```bash
$ echo hello | symmecrypt encrypt --base64 --extra ctx1 --extra ctx2 > data.enc
$ symmecrypt decrypt --base64 --extra ctx1 --extra ctx2 < data.enc     # ok
$ symmecrypt decrypt --base64 < data.enc                               # fails
```

### Key rollover

`key rotate` adds a new revision (same identifier, newer timestamp). The library keyring then
encrypts with the newest key while still decrypting older ciphertexts. `key inspect` shows the
metadata — never the key material.

```bash
$ symmecrypt key rotate --key-file key.json > keyring.json
$ symmecrypt key inspect --key-file keyring.json
IDENTIFIER  CIPHER              TIMESTAMP             SEALED
storage     xchacha20-poly1305  2026-09-17T16:20:04Z  false
storage     xchacha20-poly1305  2026-09-17T15:03:11Z  false
```

### configstore integration

`--config` reads keys from a [configstore](https://github.com/ovh/configstore) file, the same
format the library consumes in production:

```yaml
- key: encryption-key
  value: '{"identifier":"storage","cipher":"xchacha20-poly1305","timestamp":1758124991,"key":"..."}'
```

```bash
$ echo hello | symmecrypt encrypt --config config.yml --base64
```

### Large files

`--stream` switches to the chunked format of the *symmecrypt/stream* package (256KiB chunks,
constant memory). The stream format is **not** compatible with the plain format.

```bash
$ symmecrypt encrypt --stream --in backup.tar --out backup.tar.enc
$ symmecrypt decrypt --stream --in backup.tar.enc --out backup.tar
```

### Seal (shamir)

`seal new` generates a seal (see [symmecrypt/seal](https://github.com/ovh/symmecrypt/tree/master/seal)):
the config goes to stdout, the shards to stderr — shown once, distribute them.

```bash
$ symmecrypt seal new --min 2 --total 3 > seal.json 2> shards.txt
$ symmecrypt key new | symmecrypt key seal --seal-file seal.json --shard-file shards.txt > sealed.key
$ echo hello | symmecrypt encrypt --key-file sealed.key --seal-file seal.json \
    --shard "$SHARD_1" --shard "$SHARD_2" --base64
```

### Migration from the previous CLI

The CLI was rewritten (kingpin dropped for the standard library) with a new command layout:

| Before | After |
|---|---|
| `symmecrypt new [cipher] --key=ID` | `symmecrypt key new --cipher NAME --identifier ID` |
| default cipher `aes-gcm` | default cipher `xchacha20-poly1305` (pass `--cipher aes-gcm` for the old default) |
| flags accepted anywhere | flags must follow the command |
| empty stdin exited silently | empty input is processed normally |

The `ENCRYPTION_KEY_BASE64` format is unchanged.

## License

*symmecrypt* is released under a BSD 3-Clause license (see [LICENSE](LICENSE)), with the following exception:

* `ciphers/aesgcmsiv/polyval.go` and `ciphers/aesgcmsiv/siv.go` are derived from the
  [Tink](https://github.com/tink-crypto/tink-go) project, Copyright Google LLC,
  licensed under the Apache License 2.0 (see [ciphers/aesgcmsiv/LICENSE](ciphers/aesgcmsiv/LICENSE)),
  modified to implement Go's `cipher.AEAD` interface.
