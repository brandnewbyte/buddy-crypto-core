# Buddy crypto core

The small, network-free Rust crate that implements the cryptographic operations
used by [Buddy Password Manager](https://pwbuddy.com) vaults.

This repository exists so Buddy's security-sensitive implementation can be
inspected, tested, and reused by independent recovery tools without requiring
the commercial desktop application.

## Boundary

Included:

- Argon2id master-key derivation with parameters persisted per vault
- HKDF-SHA-256 purpose separation for verifier, entry, and attachment keys
- XChaCha20-Poly1305 authenticated encryption with record-context binding
- Master-password verifier creation and validation
- Zeroing of temporary plaintext JSON and key buffers where the API permits it
- Stable compatibility tests for the Buddy vault profile

Deliberately excluded from the crate implementation:

- Vault storage and SQLite schemas
- Filesystem or network access
- Browser integration
- Biometrics and operating-system keyrings
- Licensing, updates, analytics, and UI code
- Cryptography used only to import third-party password-manager exports

## Current vault profile

| Purpose | Primitive | Current profile |
| --- | --- | --- |
| Master key | Argon2id | 64 MiB, `t=3`, `p=4`, version `0x13`, 16-byte random salt, 32-byte output |
| Key separation | HKDF-SHA-256 | `vault-verification-v1`, `entry-key-v1`, `entry-blob-key-v1` |
| Authenticated encryption | XChaCha20-Poly1305 | 32-byte key, random 24-byte nonce, 16-byte tag, record-bound AAD for entries and attachment envelopes |
| Randomness | Operating-system CSPRNG | Via RustCrypto's `OsRng` |

KDF parameters are stored alongside each vault. Changing the recommended
profile for newly created vaults therefore does not make older vaults
unreadable.

## App versions

| Crate tag | Buddy app |
| --- | --- |
| `v0.1.0` | 1.1.0 and later |

## Use

```rust
use buddy_crypto_core::{Crypto, KdfParams, verify_master_password};

let params = KdfParams::recommended();
let master_key = verify_master_password(
    &vault_salt,
    &verifier_nonce,
    &verifier_ciphertext,
    password.as_bytes(),
    &params,
)?;

let entry = Crypto::decrypt::<MyEntry>(entry_key, nonce, &ciphertext)?;
```

Run the isolated suite with:

```shell
cargo test
cargo clippy --all-targets -- -D warnings
```

Machine-readable compatibility values live in
[`test-vectors/v1.json`](test-vectors/v1.json). Their encoding and versioning
rules are documented in [`test-vectors/README.md`](test-vectors/README.md), and
the complete recovery contract is in
[`docs/vault-format-v1.md`](docs/vault-format-v1.md). The integration suite
consumes the published vectors through the crate's public API, giving Buddy and
independent recovery tools a shared compatibility contract.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT License ([`LICENSE-MIT`](LICENSE-MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project is licensed as above, without additional terms or
conditions.

## Security status

This code has **not yet completed an independent third-party audit**. Public
source and tests improve inspectability; they are not a substitute for an
audit. Security reports can be sent to `support@pwbuddy.com` or through the
process published at <https://pwbuddy.com/security>.

## Publication checklist

This crate is intentionally marked `publish = false` until the following
release decisions are complete:

- enable the repository's GitHub security features and configure release
  signing.
