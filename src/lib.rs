//! Network-free cryptographic primitives used by Buddy password vaults.
//!
//! This crate contains the security-sensitive operations required to derive a
//! vault master key, separate purpose-specific keys, authenticate a master
//! password, and encrypt or decrypt vault records. It deliberately contains no
//! filesystem, database, networking, licensing, updater, or UI code.
//!
//! # Security status
//!
//! This code has not yet completed an independent third-party audit. Publishing
//! it makes the implementation inspectable; it does not make the implementation
//! automatically safe.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF context for the key that authenticates a vault master password.
pub const VAULT_VERIFICATION_CTX: &[u8] = b"vault-verification-v1";

/// HKDF context for encrypted entry metadata.
pub const ENTRY_CTX: &[u8] = b"entry-key-v1";

/// HKDF context for encrypted attachment-key envelopes.
pub const ENTRY_BLOB_CTX: &[u8] = b"entry-blob-key-v1";

/// Vault-format profile included in authenticated record contexts.
pub const VAULT_PROFILE: &[u8] = b"buddy-vault-v1";

const ENTRY_AAD_RECORD_TYPE: &[u8] = b"entry";
const ENTRY_BLOB_ENVELOPE_AAD_RECORD_TYPE: &[u8] = b"entry-blob-envelope";

/// Persisted Argon2 parameters for a Buddy vault or encrypted export.
///
/// The parameters travel with encrypted data so raising future defaults never
/// makes an existing vault unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Currently `argon2id`.
    pub algo: String,
    /// Memory cost in KiB.
    pub mem_cost: u32,
    /// Number of iterations.
    pub time_cost: u32,
    /// Number of lanes.
    pub parallelism: u32,
    /// Argon2 version (`0x13` is version 19).
    pub version: u32,
}

impl KdfParams {
    /// Current cost profile for newly created or rekeyed vaults.
    pub fn recommended() -> Self {
        Self {
            algo: "argon2id".to_string(),
            mem_cost: 64 * 1024,
            time_cost: 3,
            parallelism: 4,
            version: 0x13,
        }
    }

    /// Construct the exact Argon2 implementation described by this profile.
    pub fn argon2(&self) -> Result<Argon2<'static>, String> {
        if self.algo != "argon2id" {
            return Err(format!("unsupported kdf algo: {}", self.algo));
        }

        let version = match self.version {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            version => return Err(format!("unsupported argon2 version: {version:#x}")),
        };

        let params = Params::new(self.mem_cost, self.time_cost, self.parallelism, Some(32))
            .map_err(|error| format!("invalid kdf params: {error}"))?;

        Ok(Argon2::new(Algorithm::Argon2id, version, params))
    }
}

/// Failure while sealing or opening authenticated data.
#[derive(Debug)]
pub enum CryptoError {
    Encryption,
    Decryption,
    Deserialize(serde_json::Error),
    Serialize(serde_json::Error),
}

impl std::error::Error for CryptoError {}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encryption => formatter.write_str("encryption failed"),
            Self::Decryption => formatter.write_str("decryption failed"),
            Self::Deserialize(error) => write!(formatter, "decrypted JSON is invalid: {error}"),
            Self::Serialize(error) => write!(formatter, "value could not be serialized: {error}"),
        }
    }
}

/// Authenticated encryption helpers retained as a type for desktop API
/// compatibility. Keys are 256-bit and nonces are 192-bit.
pub struct Crypto;

impl Crypto {
    /// Encrypt raw bytes using XChaCha20-Poly1305 and a random nonce.
    pub fn encrypt_bytes(key: [u8; 32], value: &[u8]) -> Result<([u8; 24], Vec<u8>), CryptoError> {
        Self::encrypt_bytes_with_aad(key, value, &[])
    }

    /// Encrypt raw bytes and authenticate an unencrypted record context.
    pub fn encrypt_bytes_with_aad(
        key: [u8; 32],
        value: &[u8],
        associated_data: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), CryptoError> {
        let nonce = generate_nonce();
        let ciphertext = encrypt_bytes_with_nonce(&key, &nonce, value, associated_data)?;
        Ok((nonce, ciphertext))
    }

    /// Authenticate and decrypt raw bytes using XChaCha20-Poly1305.
    pub fn decrypt_bytes(
        key: [u8; 32],
        nonce: [u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::decrypt_bytes_with_aad(key, nonce, ciphertext, &[])
    }

    /// Authenticate a record context and decrypt raw bytes.
    pub fn decrypt_bytes_with_aad(
        key: [u8; 32],
        nonce: [u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::Decryption)
    }

    /// Serialize a value as JSON, wipe the plaintext serialization on drop,
    /// and encrypt it using XChaCha20-Poly1305.
    pub fn encrypt<T>(key: [u8; 32], value: &T) -> Result<([u8; 24], Vec<u8>), CryptoError>
    where
        T: Serialize,
    {
        Self::encrypt_with_aad(key, value, &[])
    }

    /// Serialize and encrypt JSON while authenticating an unencrypted record
    /// context. The plaintext serialization is wiped on drop.
    pub fn encrypt_with_aad<T>(
        key: [u8; 32],
        value: &T,
        associated_data: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), CryptoError>
    where
        T: Serialize,
    {
        let plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(CryptoError::Serialize)?);

        Self::encrypt_bytes_with_aad(key, plaintext.as_slice(), associated_data)
    }

    /// Authenticate and decrypt JSON, wiping the intermediate plaintext buffer
    /// after deserialization.
    pub fn decrypt<T>(key: [u8; 32], nonce: [u8; 24], ciphertext: &[u8]) -> Result<T, CryptoError>
    where
        T: DeserializeOwned,
    {
        Self::decrypt_with_aad(key, nonce, ciphertext, &[])
    }

    /// Authenticate a record context and decrypt JSON, wiping the intermediate
    /// plaintext buffer after deserialization.
    pub fn decrypt_with_aad<T>(
        key: [u8; 32],
        nonce: [u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<T, CryptoError>
    where
        T: DeserializeOwned,
    {
        let plaintext = Zeroizing::new(Self::decrypt_bytes_with_aad(
            key,
            nonce,
            ciphertext,
            associated_data,
        )?);
        serde_json::from_slice(plaintext.as_slice()).map_err(CryptoError::Deserialize)
    }
}

/// Build the canonical associated data for an encrypted entry payload.
pub fn entry_aad(vault_id: &str, entry_id: &str) -> Vec<u8> {
    record_aad(ENTRY_AAD_RECORD_TYPE, vault_id, entry_id)
}

/// Build the canonical associated data for an attachment-key envelope.
pub fn entry_blob_envelope_aad(vault_id: &str, blob_id: &str) -> Vec<u8> {
    record_aad(ENTRY_BLOB_ENVELOPE_AAD_RECORD_TYPE, vault_id, blob_id)
}

fn record_aad(record_type: &[u8], vault_id: &str, record_id: &str) -> Vec<u8> {
    let fields = [
        VAULT_PROFILE,
        record_type,
        vault_id.as_bytes(),
        record_id.as_bytes(),
    ];
    let capacity = fields.iter().map(|field| 8 + field.len()).sum();
    let mut output = Vec::with_capacity(capacity);

    for field in fields {
        let length = u64::try_from(field.len()).expect("AAD field length exceeds u64");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field);
    }

    output
}

/// Generate a random 256-bit key using the operating system CSPRNG.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Derive a purpose-specific 256-bit subkey using HKDF-SHA-256.
pub fn derive_subkey(master_key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .expect("a 32-byte HKDF expansion is always valid for SHA-256");
    output
}

/// Generate a random 192-bit XChaCha20-Poly1305 nonce.
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Create the verifier fields persisted with a vault and return its derived
/// master key to the caller creating that vault.
pub fn create_verifier(
    password: &str,
    params: &KdfParams,
) -> ([u8; 16], [u8; 24], Vec<u8>, Zeroizing<[u8; 32]>) {
    let mut kdf_salt = [0u8; 16];
    OsRng.fill_bytes(&mut kdf_salt);

    let mut master_key = Zeroizing::new([0u8; 32]);
    let argon2 = params.argon2().expect("invalid KDF parameters");
    argon2
        .hash_password_into(password.as_bytes(), &kdf_salt, &mut *master_key)
        .expect("Argon2 key derivation failed");

    let verification_key = derive_subkey(&master_key, VAULT_VERIFICATION_CTX);
    let nonce = generate_nonce();
    let mut verifier_plaintext = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *verifier_plaintext);
    let ciphertext = encrypt_bytes_with_nonce(
        &verification_key,
        &nonce,
        verifier_plaintext.as_slice(),
        &[],
    )
    .expect("verifier encryption failed");

    (kdf_salt, nonce, ciphertext, master_key)
}

/// Derive a master key from a password and authenticate it against the vault's
/// verifier blob.
pub fn verify_master_password(
    kdf_salt: &[u8; 16],
    verifier_nonce: &[u8; 24],
    verifier_ciphertext: &[u8],
    password: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut master_key = Zeroizing::new([0u8; 32]);
    params
        .argon2()?
        .hash_password_into(password, kdf_salt, &mut *master_key)
        .map_err(|_| "failed to derive key")?;

    verify_master_key(verifier_nonce, verifier_ciphertext, &master_key)?;
    Ok(master_key)
}

/// Authenticate an already-derived master key against a vault verifier.
pub fn verify_master_key(
    verifier_nonce: &[u8; 24],
    verifier_ciphertext: &[u8],
    master_key: &[u8; 32],
) -> Result<(), String> {
    let verification_key = derive_subkey(master_key, VAULT_VERIFICATION_CTX);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&verification_key));

    cipher
        .decrypt(XNonce::from_slice(verifier_nonce), verifier_ciphertext)
        .map_err(|_| "invalid password")?;

    Ok(())
}

fn encrypt_bytes_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 24],
    value: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: value,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Encryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn bytes<const N: usize>(encoded: &str) -> [u8; N] {
        hex::decode(encoded)
            .unwrap()
            .try_into()
            .unwrap_or_else(|value: Vec<u8>| panic!("expected {N} bytes, got {}", value.len()))
    }

    fn fast_kdf() -> KdfParams {
        KdfParams {
            algo: "argon2id".into(),
            mem_cost: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            version: 0x13,
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Record {
        title: String,
        username: String,
    }

    #[test]
    fn recommended_profile_is_stable() {
        assert_eq!(
            KdfParams::recommended(),
            KdfParams {
                algo: "argon2id".into(),
                mem_cost: 65_536,
                time_cost: 3,
                parallelism: 4,
                version: 0x13,
            }
        );
    }

    #[test]
    fn invalid_kdf_algorithm_and_version_are_rejected() {
        let mut params = fast_kdf();
        params.algo = "argon2d".into();
        assert!(params.argon2().is_err());

        params.algo = "argon2id".into();
        params.version = 0x14;
        assert!(params.argon2().is_err());
    }

    #[test]
    fn purpose_specific_keys_are_distinct() {
        let master_key = bytes("bbb9499ebe142c3dbb6e617cb2814aef7401502b8129804cc596d7e3bb81f257");
        let verifier = derive_subkey(&master_key, VAULT_VERIFICATION_CTX);
        let entry = derive_subkey(&master_key, ENTRY_CTX);
        let blob = derive_subkey(&master_key, ENTRY_BLOB_CTX);

        assert_eq!(
            hex::encode(verifier),
            "81f036c9376e55f55aa0e33f32161a945d4da00bb081b88e6f782d9c8e9fe6a9"
        );
        assert_eq!(
            hex::encode(entry),
            "b3914d71cba5a3bb5d0cec4dd3f176ffc2a8e2a75738f8ddbd631a0851706f93"
        );
        assert_eq!(
            hex::encode(blob),
            "7ef0213cd8dbb8b501fe74dfc54c57ac492330a0a41abf95bc3a17492a8b7106"
        );
    }

    #[test]
    fn raw_bytes_round_trip_and_tampering_is_rejected() {
        let key = generate_key();
        let associated_data = entry_aad("vault-id", "entry-id");
        let (nonce, mut ciphertext) =
            Crypto::encrypt_bytes_with_aad(key, b"secret", &associated_data).unwrap();

        assert_eq!(
            Crypto::decrypt_bytes_with_aad(key, nonce, &ciphertext, &associated_data).unwrap(),
            b"secret"
        );
        assert!(
            Crypto::decrypt_bytes_with_aad(
                key,
                nonce,
                &ciphertext,
                &entry_aad("vault-id", "other-entry-id"),
            )
            .is_err()
        );

        ciphertext[0] ^= 1;
        assert!(Crypto::decrypt_bytes_with_aad(key, nonce, &ciphertext, &associated_data).is_err());
    }

    #[test]
    fn json_round_trip_wipes_intermediate_buffers() {
        let key = generate_key();
        let expected = Record {
            title: "Example".into(),
            username: "robert@example.com".into(),
        };
        let (nonce, ciphertext) = Crypto::encrypt(key, &expected).unwrap();
        let actual: Record = Crypto::decrypt(key, nonce, &ciphertext).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn verifier_accepts_the_password_and_rejects_other_credentials() {
        let params = fast_kdf();
        let (salt, nonce, ciphertext, master_key) = create_verifier("correct", &params);

        let derived =
            verify_master_password(&salt, &nonce, &ciphertext, b"correct", &params).unwrap();

        assert_eq!(*derived, *master_key);
        assert!(verify_master_password(&salt, &nonce, &ciphertext, b"wrong", &params,).is_err());
        assert!(verify_master_key(&nonce, &ciphertext, &[0u8; 32]).is_err());
    }

    #[test]
    fn kdf_profile_round_trips_through_json() {
        let profile = KdfParams::recommended();
        let encoded = serde_json::to_string(&profile).unwrap();
        let decoded: KdfParams = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn deterministic_compatibility_vector_is_stable() {
        let verifier_key =
            bytes("81f036c9376e55f55aa0e33f32161a945d4da00bb081b88e6f782d9c8e9fe6a9");
        let verifier_nonce = bytes("202122232425262728292a2b2c2d2e2f3031323334353637");
        let verifier_plaintext: [u8; 32] =
            bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let verifier_ciphertext =
            encrypt_bytes_with_nonce(&verifier_key, &verifier_nonce, &verifier_plaintext, &[])
                .unwrap();

        assert_eq!(
            hex::encode(verifier_ciphertext),
            "6a5f25039351e3f912a6f70137401970211beea90289aeb193ae79c69a329ffd4f5a29b172ee5981adc5f8aed430d84e"
        );

        let entry_key = bytes("b3914d71cba5a3bb5d0cec4dd3f176ffc2a8e2a75738f8ddbd631a0851706f93");
        let entry_nonce = bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
        let entry_aad = entry_aad(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        let entry_ciphertext = encrypt_bytes_with_nonce(
            &entry_key,
            &entry_nonce,
            br#"{"icon":null,"groups":[]}"#,
            &entry_aad,
        )
        .unwrap();

        assert_eq!(
            hex::encode(&entry_aad),
            "000000000000000e62756464792d7661756c742d76310000000000000005656e747279000000000000002431313131313131312d313131312d343131312d383131312d313131313131313131313131000000000000002432323232323232322d323232322d343232322d383232322d323232323232323232323232"
        );
        assert_eq!(
            hex::encode(&entry_ciphertext),
            "35e8d175a146996b64fbf5fb7135c7eea5daf4044862c9f90da55de78fd1da516d2ee16fcdc5c20db0"
        );

        let entry_blob_key =
            bytes("7ef0213cd8dbb8b501fe74dfc54c57ac492330a0a41abf95bc3a17492a8b7106");
        let envelope_nonce = bytes("808182838485868788898a8b8c8d8e8f9091929394959697");
        let data_key: [u8; 32] =
            bytes("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
        let envelope_aad = entry_blob_envelope_aad(
            "11111111-1111-4111-8111-111111111111",
            "33333333-3333-4333-8333-333333333333",
        );
        let envelope_ciphertext =
            encrypt_bytes_with_nonce(&entry_blob_key, &envelope_nonce, &data_key, &envelope_aad)
                .unwrap();

        assert_eq!(
            hex::encode(&envelope_aad),
            "000000000000000e62756464792d7661756c742d76310000000000000013656e7472792d626c6f622d656e76656c6f7065000000000000002431313131313131312d313131312d343131312d383131312d313131313131313131313131000000000000002433333333333333332d333333332d343333332d383333332d333333333333333333333333"
        );
        assert_eq!(
            hex::encode(&envelope_ciphertext),
            "8f6e5b6028fa2fba76938fedd38b150ebdc59fbd13d18c0c4d6f2aab52f84fb8baed3485cdfdb704a279c0c382d4baf4"
        );
    }
}
