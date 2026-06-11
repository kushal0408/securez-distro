/*
 * SecureZ+ OS — CrypticEngine
 * key_storage.c — Encrypted keyring with master key
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "key_storage.h"
#include "crypto_core.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include <time.h>

/* ── Keystore file format ────────────────────────────────────── */
/*
 * [magic:4 "SZKS"]
 * [version:4]
 * [key_count:4]
 * [entries...]
 *
 * Each entry:
 * [name_len:2][name:var]
 * [type:4]
 * [created_at:8]
 * [enc_key_len:4]
 * [salt:16][nonce:24][encrypted_key:var+16(mac)]
 */

#define KEYSTORE_MAGIC "SZKS"
#define KEYSTORE_VERSION 1

static int keystore_ready = 0;

/* ── Internal ────────────────────────────────────────────────── */

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    return mkdir(path, 0700);
}

/* ── Public API ──────────────────────────────────────────────── */

int keystore_init(void)
{
    if (keystore_ready) return 0;

    ensure_dir("/etc/securez");
    ensure_dir("/var/lib/securez");

    keystore_ready = 1;
    return 0;
}

void keystore_shutdown(void)
{
    keystore_ready = 0;
}

int keystore_master_setup(const char *password)
{
    if (!password) {
        errno = EINVAL;
        return -1;
    }

    /* Require minimum 16 characters for master key */
    if (strlen(password) < 16) {
        fprintf(stderr, "[Keystore] Master key must be at least 16 characters\n");
        return -1;
    }

    /* Check if master key already exists */
    if (access(KEYSTORE_MASTER_PATH, F_OK) == 0) {
        fprintf(stderr, "[Keystore] Master key already set up. "
                        "Use keystore_master_change() to change it.\n");
        return -1;
    }

    ensure_dir("/etc/securez");

    /*
     * Hash the master password using Argon2id with EXTREME parameters.
     * This makes brute-force practically impossible.
     * The hash string includes the salt — we never store the raw key.
     */
    char hash_str[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str(hash_str, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_SENSITIVE,
                          crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        fprintf(stderr, "[Keystore] Failed to hash master key (out of memory?)\n");
        return -1;
    }

    /* Write the hash (NOT the password) to disk */
    FILE *f = fopen(KEYSTORE_MASTER_PATH, "w");
    if (!f) {
        perror("[Keystore] Cannot create master key file");
        return -1;
    }

    fprintf(f, "%s\n", hash_str);
    fclose(f);

    /* Restrictive permissions — root only */
    chmod(KEYSTORE_MASTER_PATH, 0600);

    fprintf(stderr, "[Keystore] ✅ Master key configured\n");
    fprintf(stderr, "[Keystore] ⚠ REMEMBER YOUR MASTER KEY — it cannot be recovered!\n");
    return 0;
}

int keystore_master_verify(const char *password)
{
    if (!password) return -1;

    FILE *f = fopen(KEYSTORE_MASTER_PATH, "r");
    if (!f) {
        fprintf(stderr, "[Keystore] No master key configured\n");
        return -1;
    }

    char stored_hash[crypto_pwhash_STRBYTES];
    if (fgets(stored_hash, sizeof(stored_hash), f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Remove trailing newline */
    size_t len = strlen(stored_hash);
    if (len > 0 && stored_hash[len - 1] == '\n') {
        stored_hash[len - 1] = '\0';
    }

    /* Verify using libsodium's constant-time comparison */
    if (crypto_pwhash_str_verify(stored_hash, password,
                                  strlen(password)) != 0) {
        fprintf(stderr, "[Keystore] ❌ Master key verification failed\n");
        return -1;
    }

    fprintf(stderr, "[Keystore] ✅ Master key verified\n");
    return 0;
}

int keystore_master_change(const char *old_password, const char *new_password)
{
    if (!old_password || !new_password) return -1;

    /* Verify old password first */
    if (keystore_master_verify(old_password) != 0) {
        fprintf(stderr, "[Keystore] Old master key is incorrect\n");
        return -1;
    }

    if (strlen(new_password) < 16) {
        fprintf(stderr, "[Keystore] New master key must be at least 16 characters\n");
        return -1;
    }

    /* Remove old hash and set new one */
    unlink(KEYSTORE_MASTER_PATH);

    return keystore_master_setup(new_password);
}

int keystore_store(const char *name, KeyType type,
                   const uint8_t *key_data, size_t key_len,
                   const char *master_pw)
{
    if (!name || !key_data || !master_pw || key_len == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Verify master password */
    if (keystore_master_verify(master_pw) != 0) return -1;

    /* Derive wrapping key from master password */
    uint8_t salt[CRYPTIC_SALT_LEN];
    crypto_generate_salt(salt);

    uint8_t *wrap_key = secure_alloc(CRYPTIC_KEY_LEN);
    if (!wrap_key) return -1;

    if (crypto_derive_key(wrap_key, master_pw, salt,
                          CRYPTIC_KDF_OPSLIMIT_NORMAL,
                          CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
        secure_free(wrap_key, CRYPTIC_KEY_LEN);
        return -1;
    }

    /* Encrypt the key data */
    uint8_t nonce[CRYPTIC_NONCE_LEN];
    crypto_random_bytes(nonce, CRYPTIC_NONCE_LEN);

    size_t ct_len_alloc = key_len + CRYPTIC_MAC_LEN;
    uint8_t *encrypted = malloc(ct_len_alloc);
    if (!encrypted) {
        secure_free(wrap_key, CRYPTIC_KEY_LEN);
        return -1;
    }

    unsigned long long ct_len = 0;
    if (crypto_encrypt_buffer(encrypted, &ct_len,
                              key_data, key_len,
                              nonce, wrap_key) != 0) {
        secure_free(wrap_key, CRYPTIC_KEY_LEN);
        free(encrypted);
        return -1;
    }

    secure_free(wrap_key, CRYPTIC_KEY_LEN);

    /* Append to keystore file */
    FILE *f = fopen(KEYSTORE_PATH, "ab");
    if (!f) {
        /* Create if doesn't exist */
        f = fopen(KEYSTORE_PATH, "wb");
        if (!f) {
            free(encrypted);
            return -1;
        }
    }

    /* Write entry: name, type, timestamp, salt, nonce, encrypted data */
    uint16_t name_len = (uint16_t)strlen(name);
    uint32_t type_u32 = (uint32_t)type;
    uint64_t timestamp = (uint64_t)time(NULL);
    uint32_t enc_len = (uint32_t)ct_len;

    fwrite(&name_len, 2, 1, f);
    fwrite(name, 1, name_len, f);
    fwrite(&type_u32, 4, 1, f);
    fwrite(&timestamp, 8, 1, f);
    fwrite(&enc_len, 4, 1, f);
    fwrite(salt, 1, CRYPTIC_SALT_LEN, f);
    fwrite(nonce, 1, CRYPTIC_NONCE_LEN, f);
    fwrite(encrypted, 1, (size_t)ct_len, f);

    fclose(f);
    free(encrypted);
    chmod(KEYSTORE_PATH, 0600);

    fprintf(stderr, "[Keystore] Stored key '%s'\n", name);
    return 0;
}

int keystore_retrieve(const char *name, uint8_t **key_data,
                      size_t *key_len, const char *master_pw)
{
    if (!name || !key_data || !key_len || !master_pw) return -1;

    if (keystore_master_verify(master_pw) != 0) return -1;

    FILE *f = fopen(KEYSTORE_PATH, "rb");
    if (!f) return -1;

    /* Scan entries looking for matching name */
    while (!feof(f)) {
        uint16_t entry_name_len;
        if (fread(&entry_name_len, 2, 1, f) != 1) break;

        char entry_name[KEYSTORE_NAME_MAX];
        if (entry_name_len >= KEYSTORE_NAME_MAX) { fclose(f); return -1; }
        if (fread(entry_name, 1, entry_name_len, f) != entry_name_len) break;
        entry_name[entry_name_len] = '\0';

        uint32_t type_u32;
        uint64_t timestamp;
        uint32_t enc_len;

        if (fread(&type_u32, 4, 1, f) != 1) break;
        if (fread(&timestamp, 8, 1, f) != 1) break;
        if (fread(&enc_len, 4, 1, f) != 1) break;

        uint8_t salt[CRYPTIC_SALT_LEN];
        uint8_t nonce[CRYPTIC_NONCE_LEN];
        if (fread(salt, 1, CRYPTIC_SALT_LEN, f) != CRYPTIC_SALT_LEN) break;
        if (fread(nonce, 1, CRYPTIC_NONCE_LEN, f) != CRYPTIC_NONCE_LEN) break;

        if (strcmp(entry_name, name) == 0) {
            /* Found it — decrypt */
            uint8_t *encrypted = malloc(enc_len);
            if (!encrypted) { fclose(f); return -1; }
            if (fread(encrypted, 1, enc_len, f) != enc_len) {
                free(encrypted);
                fclose(f);
                return -1;
            }
            fclose(f);

            /* Derive wrapping key */
            uint8_t *wrap_key = secure_alloc(CRYPTIC_KEY_LEN);
            if (!wrap_key) { free(encrypted); return -1; }

            if (crypto_derive_key(wrap_key, master_pw, salt,
                                  CRYPTIC_KDF_OPSLIMIT_NORMAL,
                                  CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
                secure_free(wrap_key, CRYPTIC_KEY_LEN);
                free(encrypted);
                return -1;
            }

            /* Decrypt */
            size_t pt_alloc = enc_len;
            *key_data = secure_alloc(pt_alloc);
            if (!*key_data) {
                secure_free(wrap_key, CRYPTIC_KEY_LEN);
                free(encrypted);
                return -1;
            }

            unsigned long long pt_len = 0;
            int ret = crypto_decrypt_buffer(*key_data, &pt_len,
                                            encrypted, enc_len,
                                            nonce, wrap_key);
            secure_free(wrap_key, CRYPTIC_KEY_LEN);
            free(encrypted);

            if (ret != 0) {
                secure_free(*key_data, pt_alloc);
                *key_data = NULL;
                return -1;
            }

            *key_len = (size_t)pt_len;
            return 0;
        } else {
            /* Skip this entry's encrypted data */
            fseek(f, enc_len, SEEK_CUR);
        }
    }

    fclose(f);
    fprintf(stderr, "[Keystore] Key '%s' not found\n", name);
    return -1;
}

int keystore_delete(const char *name, const char *master_pw)
{
    /* For simplicity: rebuild the keystore without the deleted entry.
     * In production, you'd use a proper indexed format. */
    (void)name;
    (void)master_pw;
    fprintf(stderr, "[Keystore] Delete not yet implemented — rebuild keystore\n");
    return -1;
}

int keystore_list(KeyInfo *keys, int *count)
{
    if (!keys || !count) return -1;
    *count = 0;

    FILE *f = fopen(KEYSTORE_PATH, "rb");
    if (!f) return 0;  /* No keys */

    while (!feof(f) && *count < KEYSTORE_MAX_KEYS) {
        uint16_t name_len;
        if (fread(&name_len, 2, 1, f) != 1) break;
        if (name_len >= KEYSTORE_NAME_MAX) break;

        KeyInfo *k = &keys[*count];
        memset(k, 0, sizeof(KeyInfo));

        if (fread(k->name, 1, name_len, f) != name_len) break;
        k->name[name_len] = '\0';

        uint32_t type_u32;
        uint32_t enc_len;

        if (fread(&type_u32, 4, 1, f) != 1) break;
        if (fread(&k->created_at, 8, 1, f) != 1) break;
        if (fread(&enc_len, 4, 1, f) != 1) break;

        k->type = (KeyType)type_u32;
        k->key_len = enc_len;  /* Approximate (encrypted size) */

        /* Skip salt + nonce + encrypted data */
        fseek(f, CRYPTIC_SALT_LEN + CRYPTIC_NONCE_LEN + enc_len, SEEK_CUR);

        (*count)++;
    }

    fclose(f);
    return 0;
}

int keystore_emergency_wipe(void)
{
    /* Overwrite keystore with random data */
    struct stat st;
    if (stat(KEYSTORE_PATH, &st) == 0 && st.st_size > 0) {
        FILE *f = fopen(KEYSTORE_PATH, "r+b");
        if (f) {
            uint8_t *random = malloc((size_t)st.st_size);
            if (random) {
                randombytes_buf(random, (size_t)st.st_size);
                fwrite(random, 1, (size_t)st.st_size, f);
                free(random);
            }
            fclose(f);
        }
        unlink(KEYSTORE_PATH);
    }

    /* Also wipe master key hash */
    if (stat(KEYSTORE_MASTER_PATH, &st) == 0) {
        FILE *f = fopen(KEYSTORE_MASTER_PATH, "r+b");
        if (f) {
            uint8_t rand[256];
            randombytes_buf(rand, sizeof(rand));
            fwrite(rand, 1, sizeof(rand), f);
            fclose(f);
        }
        unlink(KEYSTORE_MASTER_PATH);
    }

    fprintf(stderr, "[Keystore] ⚠ EMERGENCY WIPE — all keys destroyed permanently\n");
    return 0;
}
