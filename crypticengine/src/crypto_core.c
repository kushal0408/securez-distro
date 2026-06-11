/*
 * SecureZ+ OS — CrypticEngine
 * crypto_core.c — Core cryptographic primitives
 *
 * ALL operations delegate to libsodium. Zero homebrew crypto.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "crypto_core.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* ── Key Derivation (Argon2id) ───────────────────────────────── */

int crypto_derive_key(uint8_t *key, const char *password,
                      const uint8_t *salt, uint64_t opslimit,
                      size_t memlimit)
{
    if (!key || !password || !salt) {
        errno = EINVAL;
        return -1;
    }

    if (crypto_pwhash(key, CRYPTIC_KEY_LEN,
                      password, strlen(password),
                      salt,
                      opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        /* Out of memory or other failure */
        fprintf(stderr, "[CrypticEngine] Key derivation failed (OOM?)\n");
        return -1;
    }

    return 0;
}

/* ── Authenticated Encryption (XChaCha20-Poly1305) ───────────── */

int crypto_encrypt_buffer(uint8_t *ciphertext, unsigned long long *ct_len,
                          const uint8_t *plaintext, size_t pt_len,
                          const uint8_t *nonce, const uint8_t *key)
{
    if (!ciphertext || !plaintext || !nonce || !key) {
        errno = EINVAL;
        return -1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, ct_len,
            plaintext, pt_len,
            NULL, 0,    /* No additional data */
            NULL,       /* nsec (unused) */
            nonce, key) != 0) {
        fprintf(stderr, "[CrypticEngine] Encryption failed\n");
        return -1;
    }

    return 0;
}

int crypto_decrypt_buffer(uint8_t *plaintext, unsigned long long *pt_len,
                          const uint8_t *ciphertext, size_t ct_len,
                          const uint8_t *nonce, const uint8_t *key)
{
    if (!plaintext || !ciphertext || !nonce || !key) {
        errno = EINVAL;
        return -1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, pt_len,
            NULL,       /* nsec (unused) */
            ciphertext, ct_len,
            NULL, 0,    /* No additional data */
            nonce, key) != 0) {
        /* Authentication failed — tampered or wrong key */
        return -1;
    }

    return 0;
}

/* ── Digital Signatures (Ed25519) ────────────────────────────── */

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) {
        errno = EINVAL;
        return -1;
    }

    return crypto_sign_ed25519_keypair(pk, sk) == 0 ? 0 : -1;
}

int crypto_sign_buffer(uint8_t *sig, const uint8_t *message,
                       size_t msg_len, const uint8_t *sk)
{
    if (!sig || !message || !sk) {
        errno = EINVAL;
        return -1;
    }

    return crypto_sign_ed25519_detached(sig, NULL, message, msg_len, sk) == 0 ? 0 : -1;
}

int crypto_verify_signature(const uint8_t *sig, const uint8_t *message,
                            size_t msg_len, const uint8_t *pk)
{
    if (!sig || !message || !pk) {
        errno = EINVAL;
        return -1;
    }

    return crypto_sign_ed25519_verify_detached(sig, message, msg_len, pk) == 0 ? 0 : -1;
}

/* ── Hashing (BLAKE2b) ──────────────────────────────────────── */

int crypto_hash_buffer(uint8_t *hash, const uint8_t *data, size_t data_len)
{
    if (!hash || (!data && data_len > 0)) {
        errno = EINVAL;
        return -1;
    }

    return crypto_generichash(hash, CRYPTIC_HASH_LEN,
                              data, data_len,
                              NULL, 0) == 0 ? 0 : -1;
}

int crypto_hash_file(uint8_t *hash, const char *filepath)
{
    if (!hash || !filepath) {
        errno = EINVAL;
        return -1;
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        return -1;
    }

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, NULL, 0, CRYPTIC_HASH_LEN) != 0) {
        fclose(f);
        return -1;
    }

    uint8_t buf[8192];
    size_t nread;

    while ((nread = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (crypto_generichash_update(&state, buf, nread) != 0) {
            fclose(f);
            sodium_memzero(buf, sizeof(buf));
            return -1;
        }
    }

    int ferr = ferror(f);
    fclose(f);
    sodium_memzero(buf, sizeof(buf));

    if (ferr) {
        return -1;
    }

    return crypto_generichash_final(&state, hash, CRYPTIC_HASH_LEN) == 0 ? 0 : -1;
}

/* ── Random ─────────────────────────────────────────────────── */

void crypto_random_bytes(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
}

void crypto_generate_salt(uint8_t *salt)
{
    randombytes_buf(salt, CRYPTIC_SALT_LEN);
}

/* ── Password Hashing (for storage) ─────────────────────────── */

int crypto_password_hash(char *hash_out, const char *password)
{
    if (!hash_out || !password) {
        errno = EINVAL;
        return -1;
    }

    return crypto_pwhash_str(hash_out, password, strlen(password),
                             crypto_pwhash_OPSLIMIT_SENSITIVE,
                             crypto_pwhash_MEMLIMIT_SENSITIVE) == 0 ? 0 : -1;
}

int crypto_password_verify(const char *stored_hash, const char *password)
{
    if (!stored_hash || !password) {
        errno = EINVAL;
        return -1;
    }

    return crypto_pwhash_str_verify(stored_hash, password,
                                    strlen(password)) == 0 ? 0 : -1;
}

/* ── Utility ────────────────────────────────────────────────── */

void crypto_bin_to_hex(char *hex, const uint8_t *bin, size_t bin_len)
{
    sodium_bin2hex(hex, bin_len * 2 + 1, bin, bin_len);
}
