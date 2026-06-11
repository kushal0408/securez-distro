/*
 * SecureZ+ OS — CrypticEngine
 * crypto_core.h — Core cryptographic primitives (internal)
 *
 * All crypto operations use libsodium. We NEVER roll our own.
 * CrypticEngine is an orchestrator, not a cipher.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_CRYPTO_CORE_H
#define SECUREZ_CRYPTO_CORE_H

#include <stddef.h>
#include <stdint.h>

/* ── Key Derivation (Argon2id) ───────────────────────────────── */

/* Argon2id parameters — intentionally expensive to resist brute force */
#define CRYPTIC_KDF_OPSLIMIT_NORMAL    3
#define CRYPTIC_KDF_MEMLIMIT_NORMAL    (256 * 1024 * 1024)  /* 256 MB */
#define CRYPTIC_KDF_OPSLIMIT_SENSITIVE 4
#define CRYPTIC_KDF_MEMLIMIT_SENSITIVE (512 * 1024 * 1024)  /* 512 MB */
#define CRYPTIC_KDF_OPSLIMIT_MASTER    6
#define CRYPTIC_KDF_MEMLIMIT_MASTER    (1024 * 1024 * 1024) /* 1 GB */

#define CRYPTIC_KEY_LEN    32  /* 256-bit keys */
#define CRYPTIC_SALT_LEN   16
#define CRYPTIC_NONCE_LEN  24  /* XChaCha20 nonce */
#define CRYPTIC_MAC_LEN    16  /* Poly1305 MAC */
#define CRYPTIC_HASH_LEN   32  /* BLAKE2b-256 */
#define CRYPTIC_SIG_LEN    64  /* Ed25519 signature */
#define CRYPTIC_SIGN_PK_LEN 32
#define CRYPTIC_SIGN_SK_LEN 64

/*
 * Derive an encryption key from a password using Argon2id.
 *
 * @param key       Output buffer (CRYPTIC_KEY_LEN bytes, must be mlock'd)
 * @param password  User-supplied password (null-terminated)
 * @param salt      Random salt (CRYPTIC_SALT_LEN bytes, stored with ciphertext)
 * @param opslimit  CPU cost (use CRYPTIC_KDF_OPSLIMIT_* constants)
 * @param memlimit  Memory cost in bytes (use CRYPTIC_KDF_MEMLIMIT_* constants)
 * @return 0 on success, -1 on failure
 */
int crypto_derive_key(uint8_t *key, const char *password,
                      const uint8_t *salt, uint64_t opslimit,
                      size_t memlimit);

/* ── Authenticated Encryption (XChaCha20-Poly1305) ───────────── */

/*
 * Encrypt a buffer with XChaCha20-Poly1305 AEAD.
 *
 * @param ciphertext  Output buffer (plaintext_len + CRYPTIC_MAC_LEN bytes)
 * @param ct_len      Output: actual ciphertext length
 * @param plaintext   Input data
 * @param pt_len      Length of plaintext
 * @param nonce       Random nonce (CRYPTIC_NONCE_LEN bytes, stored with ciphertext)
 * @param key         Encryption key (CRYPTIC_KEY_LEN bytes)
 * @return 0 on success, -1 on failure
 */
int crypto_encrypt_buffer(uint8_t *ciphertext, unsigned long long *ct_len,
                          const uint8_t *plaintext, size_t pt_len,
                          const uint8_t *nonce, const uint8_t *key);

/*
 * Decrypt a buffer with XChaCha20-Poly1305 AEAD.
 *
 * @param plaintext   Output buffer (ciphertext_len - CRYPTIC_MAC_LEN bytes)
 * @param pt_len      Output: actual plaintext length
 * @param ciphertext  Input data (includes MAC)
 * @param ct_len      Length of ciphertext
 * @param nonce       Nonce used during encryption
 * @param key         Decryption key (same as encryption key)
 * @return 0 on success, -1 on failure (tampered or wrong key)
 */
int crypto_decrypt_buffer(uint8_t *plaintext, unsigned long long *pt_len,
                          const uint8_t *ciphertext, size_t ct_len,
                          const uint8_t *nonce, const uint8_t *key);

/* ── Digital Signatures (Ed25519) ────────────────────────────── */

/*
 * Generate an Ed25519 signing keypair.
 *
 * @param pk  Public key output (CRYPTIC_SIGN_PK_LEN bytes)
 * @param sk  Secret key output (CRYPTIC_SIGN_SK_LEN bytes, will be mlock'd)
 * @return 0 on success, -1 on failure
 */
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Sign a message with Ed25519 (detached signature).
 *
 * @param sig      Signature output (CRYPTIC_SIG_LEN bytes)
 * @param message  Message to sign
 * @param msg_len  Message length
 * @param sk       Secret key (CRYPTIC_SIGN_SK_LEN bytes)
 * @return 0 on success, -1 on failure
 */
int crypto_sign_buffer(uint8_t *sig, const uint8_t *message,
                       size_t msg_len, const uint8_t *sk);

/*
 * Verify an Ed25519 detached signature.
 *
 * @param sig      Signature (CRYPTIC_SIG_LEN bytes)
 * @param message  Original message
 * @param msg_len  Message length
 * @param pk       Public key (CRYPTIC_SIGN_PK_LEN bytes)
 * @return 0 if valid, -1 if invalid/forged
 */
int crypto_verify_signature(const uint8_t *sig, const uint8_t *message,
                            size_t msg_len, const uint8_t *pk);

/* ── Hashing (BLAKE2b) ──────────────────────────────────────── */

/*
 * Compute BLAKE2b-256 hash of a buffer.
 *
 * @param hash     Output (CRYPTIC_HASH_LEN bytes)
 * @param data     Input data
 * @param data_len Input length
 * @return 0 on success, -1 on failure
 */
int crypto_hash_buffer(uint8_t *hash, const uint8_t *data, size_t data_len);

/*
 * Compute BLAKE2b-256 hash of a file (streaming, handles large files).
 *
 * @param hash      Output (CRYPTIC_HASH_LEN bytes)
 * @param filepath  Path to file
 * @return 0 on success, -1 on failure
 */
int crypto_hash_file(uint8_t *hash, const char *filepath);

/* ── Random ─────────────────────────────────────────────────── */

/*
 * Fill buffer with cryptographically secure random bytes.
 * Uses libsodium's randombytes_buf (backed by /dev/urandom).
 */
void crypto_random_bytes(uint8_t *buf, size_t len);

/*
 * Generate a random salt for key derivation.
 */
void crypto_generate_salt(uint8_t *salt);

/* ── Password Hashing (for storage) ─────────────────────────── */

#define CRYPTIC_PWHASH_STR_LEN 128

/*
 * Hash a password for storage (Argon2id, includes salt).
 *
 * @param hash_out  Output string (CRYPTIC_PWHASH_STR_LEN bytes)
 * @param password  Password to hash
 * @return 0 on success, -1 on failure
 */
int crypto_password_hash(char *hash_out, const char *password);

/*
 * Verify a password against a stored hash.
 *
 * @param stored_hash  Previously stored hash string
 * @param password     Password to verify
 * @return 0 if match, -1 if mismatch
 */
int crypto_password_verify(const char *stored_hash, const char *password);

/* ── Utility ────────────────────────────────────────────────── */

/*
 * Convert binary data to hex string.
 *
 * @param hex       Output buffer (must be at least bin_len*2 + 1)
 * @param bin       Binary input
 * @param bin_len   Length of binary input
 */
void crypto_bin_to_hex(char *hex, const uint8_t *bin, size_t bin_len);

#endif /* SECUREZ_CRYPTO_CORE_H */
