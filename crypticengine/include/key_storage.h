/*
 * SecureZ+ OS — CrypticEngine
 * key_storage.h — Encrypted keyring management
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_KEY_STORAGE_H
#define SECUREZ_KEY_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#define KEYSTORE_NAME_MAX      64
#define KEYSTORE_MAX_KEYS      128
#define KEYSTORE_PATH          "/etc/securez/keystore.db"
#define KEYSTORE_MASTER_PATH   "/etc/securez/master.key"

typedef enum {
    KEY_TYPE_ENCRYPTION = 0,  /* AES/XChaCha20 key */
    KEY_TYPE_SIGNING,         /* Ed25519 secret key */
    KEY_TYPE_CONTAINER,       /* Container password hash */
    KEY_TYPE_CUSTOM           /* User-defined */
} KeyType;

typedef struct {
    char     name[KEYSTORE_NAME_MAX];
    KeyType  type;
    size_t   key_len;
    uint64_t created_at;       /* Unix timestamp */
    uint64_t last_used;        /* Unix timestamp */
    int      locked;           /* 1 if currently locked */
} KeyInfo;

/*
 * Initialize the keyring.
 * Opens or creates the keystore file.
 * Master key must be set up before storing keys.
 *
 * @return 0 on success, -1 on failure
 */
int keystore_init(void);

/*
 * Shut down the keyring.
 * Wipes all decrypted keys from memory.
 */
void keystore_shutdown(void);

/*
 * Set up the master key (first-time setup).
 *
 * Derives a verification hash from the password using Argon2id
 * with extreme parameters (1GB RAM, 6 iterations).
 * The master key itself is NEVER stored — only the verification hash.
 *
 * @param password  Master password (minimum 16 characters)
 * @return 0 on success, -1 on failure
 */
int keystore_master_setup(const char *password);

/*
 * Verify the master key.
 *
 * @param password  Master password to verify
 * @return 0 if correct, -1 if wrong
 */
int keystore_master_verify(const char *password);

/*
 * Change the master key.
 * Requires the old password. Re-encrypts all stored keys.
 *
 * @param old_password  Current master password
 * @param new_password  New master password
 * @return 0 on success, -1 on failure
 */
int keystore_master_change(const char *old_password, const char *new_password);

/*
 * Store a key in the encrypted keyring.
 *
 * @param name      Key name (unique identifier)
 * @param type      Key type
 * @param key_data  Raw key data (will be encrypted for storage)
 * @param key_len   Length of key data
 * @param master_pw Master password (to derive wrapping key)
 * @return 0 on success, -1 on failure
 */
int keystore_store(const char *name, KeyType type,
                   const uint8_t *key_data, size_t key_len,
                   const char *master_pw);

/*
 * Retrieve a key from the keyring.
 *
 * @param name      Key name
 * @param key_data  Output buffer (secure_alloc'd, caller must secure_free)
 * @param key_len   Output: length of key data
 * @param master_pw Master password (to derive unwrapping key)
 * @return 0 on success, -1 on failure
 */
int keystore_retrieve(const char *name, uint8_t **key_data,
                      size_t *key_len, const char *master_pw);

/*
 * Delete a key from the keyring.
 *
 * @param name      Key name
 * @param master_pw Master password
 * @return 0 on success, -1 on failure
 */
int keystore_delete(const char *name, const char *master_pw);

/*
 * List all keys in the keyring (metadata only, not key data).
 *
 * @param keys   Output array (must hold KEYSTORE_MAX_KEYS entries)
 * @param count  Output: number of keys
 * @return 0 on success, -1 on failure
 */
int keystore_list(KeyInfo *keys, int *count);

/*
 * Emergency wipe: overwrite the entire keystore with random data.
 * All keys are PERMANENTLY lost. This is IRREVERSIBLE.
 *
 * @return 0 on success, -1 on failure
 */
int keystore_emergency_wipe(void);

#endif /* SECUREZ_KEY_STORAGE_H */
