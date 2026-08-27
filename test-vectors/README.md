# Buddy compatibility test vectors

The files in this directory are deterministic known-answer tests for the Buddy
vault profile. They let independent implementations confirm byte-for-byte
compatibility without using a real vault or the Buddy desktop application.

`v1.json` covers one continuous `buddy-vault-v1` chain:

1. encode a non-ASCII password as UTF-8;
2. derive a 32-byte master key with the persisted Argon2id parameters;
3. derive the verifier, entry, and attachment-envelope keys with HKDF-SHA-256;
4. authenticate a deterministic verifier blob; and
5. decrypt a deterministic, record-bound entry payload; and
6. unwrap a deterministic, record-bound attachment key envelope.

Run the Rust reference check with:

```shell
cargo test --test compatibility_vectors --locked
```

## Encoding rules

- The JSON files are UTF-8 without a byte-order mark.
- A field ending in `_utf8` is a JSON string whose Unicode scalar values are
  encoded directly as UTF-8. No Unicode normalization, trimming, case folding,
  terminator, or prefix is applied.
- A field ending in `_hex` is a byte string encoded as exactly two lowercase
  hexadecimal characters per byte, in byte order, without whitespace or a
  `0x` prefix. The empty byte string is `""`.
- JSON integers are base-10 integers. `mem_cost` is measured in KiB; all
  explicit lengths are measured in bytes.
- XChaCha20-Poly1305 uses a 32-byte key, a 24-byte nonce, and a 16-byte
  authentication tag. A `ciphertext_and_tag_hex` value is the ciphertext
  followed immediately by the tag. The verifier uses empty associated data;
  entries and attachment-key envelopes use the record context below.
- HKDF uses no caller-supplied salt. In RFC 5869 terms, an absent salt is
  treated as a string of 32 zero bytes for SHA-256.

## Associated-data framing

Entry and attachment-envelope contexts contain four byte strings in order:

```text
entry:                  profile, "entry", vault_id, entry_id
attachment key envelope: profile, "entry-blob-envelope", vault_id, blob_id
```

`profile` is the ASCII/UTF-8 byte string `buddy-vault-v1`. IDs are encoded as
their exact UTF-8 bytes. Each field is framed independently as an unsigned
64-bit big-endian byte length followed by that many field bytes:

```text
U64BE(length(field_1)) || field_1 ||
U64BE(length(field_2)) || field_2 ||
U64BE(length(field_3)) || field_3 ||
U64BE(length(field_4)) || field_4
```

This associated data is authenticated but not encrypted or stored separately.
Readers reconstruct it from the profile and the cleartext row identifiers. A
different record type, vault ID, or record ID MUST fail authentication.

The redundant UTF-8 and hexadecimal plaintext fields are intentional: they
make encoding mistakes visible instead of allowing two implementations to
agree on the wrong text representation.

## Versioning policy

The vectors are draft until their first tagged repository release. At that
point, every published vector file is immutable:

- do not change or remove existing fields, values, or their meanings;
- retain old files so old vaults and recovery tools remain testable;
- add a new versioned file for any incompatible cryptographic or encoding
  change; and
- give a new profile a new identifier, such as `buddy-vault-v2`.

Crate releases, vault profiles, and vector filenames are separate version
spaces. For example, crate `0.1.1` may still implement `buddy-vault-v1` and test
it with `v1.json`.

Adding more test cases without changing the vault profile should use a new,
descriptively named file that declares the same profile. Correcting a published
known-answer value requires a new file and an explanation; silently replacing
the old value would destroy its use as a compatibility contract.

## Safety

All passwords, keys, salts, nonces, plaintexts, and ciphertexts here are public
fixtures. They are deliberately predictable and must never be copied into
production vault creation or encryption code.

See [`../docs/vault-format-v1.md`](../docs/vault-format-v1.md) for the normative
cryptographic and storage layout.
