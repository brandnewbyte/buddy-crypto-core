use buddy_crypto_core::{
    Crypto, ENTRY_BLOB_CTX, ENTRY_CTX, KdfParams, VAULT_VERIFICATION_CTX, derive_subkey, entry_aad,
    entry_blob_envelope_aad, verify_master_key, verify_master_password,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    profile: String,
    kdf: KdfVector,
    derived_keys: DerivedKeys,
    verifier: AuthenticatedEncryption,
    authenticated_encryption: EntryEncryption,
    entry_blob_envelope: EntryBlobEnvelope,
}

#[derive(Deserialize)]
struct KdfVector {
    password_utf8: String,
    password_hex: String,
    salt_hex: String,
    params: KdfParams,
    output_length_bytes: usize,
    master_key_hex: String,
}

#[derive(Deserialize)]
struct DerivedKeys {
    algorithm: String,
    salt_hex: String,
    output_length_bytes: usize,
    vault_verification: DerivedKey,
    entry: DerivedKey,
    entry_blob: DerivedKey,
}

#[derive(Deserialize)]
struct DerivedKey {
    info_utf8: String,
    key_hex: String,
}

#[derive(Deserialize)]
struct AuthenticatedEncryption {
    algorithm: String,
    key_hex: String,
    nonce_hex: String,
    associated_data_hex: String,
    plaintext_hex: String,
    ciphertext_and_tag_hex: String,
}

#[derive(Deserialize)]
struct EntryEncryption {
    algorithm: String,
    record_type: String,
    vault_id: String,
    entry_id: String,
    key_source: String,
    key_hex: String,
    nonce_hex: String,
    associated_data_hex: String,
    plaintext_utf8: String,
    plaintext_hex: String,
    ciphertext_and_tag_hex: String,
}

#[derive(Deserialize)]
struct EntryBlobEnvelope {
    algorithm: String,
    record_type: String,
    vault_id: String,
    blob_id: String,
    key_source: String,
    key_hex: String,
    nonce_hex: String,
    associated_data_hex: String,
    plaintext_key_hex: String,
    ciphertext_and_tag_hex: String,
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex must contain whole bytes");
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "hex must be lowercase without a prefix"
    );
    hex::decode(encoded).expect("vector contains invalid hex")
}

fn bytes<const N: usize>(encoded: &str) -> [u8; N] {
    decode_hex(encoded)
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("expected {N} bytes, got {}", value.len()))
}

#[test]
fn published_v1_vectors_match_the_public_api() {
    let vectors: Vectors = serde_json::from_str(include_str!("../test-vectors/v1.json")).unwrap();
    assert_eq!(vectors.profile, "buddy-vault-v1");

    let kdf = vectors.kdf;
    assert_eq!(kdf.params, KdfParams::recommended());
    assert_eq!(kdf.output_length_bytes, 32);
    assert_eq!(kdf.password_utf8.as_bytes(), decode_hex(&kdf.password_hex));

    let salt = bytes::<16>(&kdf.salt_hex);
    let mut master_key = [0u8; 32];
    kdf.params
        .argon2()
        .unwrap()
        .hash_password_into(kdf.password_utf8.as_bytes(), &salt, &mut master_key)
        .unwrap();
    assert_eq!(master_key, bytes::<32>(&kdf.master_key_hex));

    let derived = vectors.derived_keys;
    assert_eq!(derived.algorithm, "hkdf-sha256");
    assert!(decode_hex(&derived.salt_hex).is_empty());
    assert_eq!(derived.output_length_bytes, 32);
    assert_eq!(
        derived.vault_verification.info_utf8.as_bytes(),
        VAULT_VERIFICATION_CTX
    );
    assert_eq!(derived.entry.info_utf8.as_bytes(), ENTRY_CTX);
    assert_eq!(derived.entry_blob.info_utf8.as_bytes(), ENTRY_BLOB_CTX);

    let verification_key = derive_subkey(&master_key, VAULT_VERIFICATION_CTX);
    let entry_key = derive_subkey(&master_key, ENTRY_CTX);
    let entry_blob_key = derive_subkey(&master_key, ENTRY_BLOB_CTX);
    assert_eq!(
        verification_key,
        bytes::<32>(&derived.vault_verification.key_hex)
    );
    assert_eq!(entry_key, bytes::<32>(&derived.entry.key_hex));
    assert_eq!(entry_blob_key, bytes::<32>(&derived.entry_blob.key_hex));

    let verifier = vectors.verifier;
    assert_eq!(verifier.algorithm, "xchacha20poly1305");
    assert!(decode_hex(&verifier.associated_data_hex).is_empty());
    assert_eq!(verification_key, bytes::<32>(&verifier.key_hex));
    let verifier_nonce = bytes::<24>(&verifier.nonce_hex);
    let verifier_ciphertext = decode_hex(&verifier.ciphertext_and_tag_hex);
    let verifier_plaintext = decode_hex(&verifier.plaintext_hex);
    assert_eq!(verifier_ciphertext.len(), verifier_plaintext.len() + 16);
    assert_eq!(
        Crypto::decrypt_bytes(verification_key, verifier_nonce, &verifier_ciphertext).unwrap(),
        verifier_plaintext
    );
    assert_eq!(
        *verify_master_password(
            &salt,
            &verifier_nonce,
            &verifier_ciphertext,
            kdf.password_utf8.as_bytes(),
            &kdf.params,
        )
        .unwrap(),
        master_key
    );
    verify_master_key(&verifier_nonce, &verifier_ciphertext, &master_key).unwrap();
    assert!(
        verify_master_password(
            &salt,
            &verifier_nonce,
            &verifier_ciphertext,
            b"wrong password",
            &kdf.params,
        )
        .is_err()
    );

    let encrypted = vectors.authenticated_encryption;
    assert_eq!(encrypted.algorithm, "xchacha20poly1305");
    assert_eq!(encrypted.record_type, "entry");
    assert_eq!(encrypted.key_source, "derived_keys.entry");
    assert_eq!(entry_key, bytes::<32>(&encrypted.key_hex));
    let associated_data = entry_aad(&encrypted.vault_id, &encrypted.entry_id);
    assert_eq!(associated_data, decode_hex(&encrypted.associated_data_hex));
    assert_eq!(
        encrypted.plaintext_utf8.as_bytes(),
        decode_hex(&encrypted.plaintext_hex)
    );
    let ciphertext = decode_hex(&encrypted.ciphertext_and_tag_hex);
    assert_eq!(ciphertext.len(), encrypted.plaintext_utf8.len() + 16);
    assert_eq!(
        Crypto::decrypt_bytes_with_aad(
            entry_key,
            bytes::<24>(&encrypted.nonce_hex),
            &ciphertext,
            &associated_data,
        )
        .unwrap(),
        encrypted.plaintext_utf8.as_bytes()
    );
    assert!(
        Crypto::decrypt_bytes_with_aad(
            entry_key,
            bytes::<24>(&encrypted.nonce_hex),
            &ciphertext,
            &entry_aad(&encrypted.vault_id, "different-entry-id"),
        )
        .is_err()
    );
    assert!(
        Crypto::decrypt_bytes_with_aad(
            entry_key,
            bytes::<24>(&encrypted.nonce_hex),
            &ciphertext,
            &entry_aad("different-vault-id", &encrypted.entry_id),
        )
        .is_err()
    );
    assert!(
        Crypto::decrypt_bytes_with_aad(
            entry_key,
            bytes::<24>(&encrypted.nonce_hex),
            &ciphertext,
            &entry_blob_envelope_aad(&encrypted.vault_id, &encrypted.entry_id),
        )
        .is_err()
    );

    let envelope = vectors.entry_blob_envelope;
    assert_eq!(envelope.algorithm, "xchacha20poly1305");
    assert_eq!(envelope.record_type, "entry-blob-envelope");
    assert_eq!(envelope.key_source, "derived_keys.entry_blob");
    assert_eq!(entry_blob_key, bytes::<32>(&envelope.key_hex));
    let envelope_aad = entry_blob_envelope_aad(&envelope.vault_id, &envelope.blob_id);
    assert_eq!(envelope_aad, decode_hex(&envelope.associated_data_hex));
    let envelope_ciphertext = decode_hex(&envelope.ciphertext_and_tag_hex);
    assert_eq!(envelope_ciphertext.len(), 48);
    assert_eq!(
        Crypto::decrypt_bytes_with_aad(
            entry_blob_key,
            bytes::<24>(&envelope.nonce_hex),
            &envelope_ciphertext,
            &envelope_aad,
        )
        .unwrap(),
        decode_hex(&envelope.plaintext_key_hex)
    );
    assert!(
        Crypto::decrypt_bytes_with_aad(
            entry_blob_key,
            bytes::<24>(&envelope.nonce_hex),
            &envelope_ciphertext,
            &entry_blob_envelope_aad(&envelope.vault_id, "different-blob-id"),
        )
        .is_err()
    );
}
