/*
 * SecureZ+ OS — CrypticEngine
 * cryptic.h — Public API
 *
 * CrypticEngine is the security orchestration engine for SecureZ+ OS.
 * It coordinates vetted cryptographic primitives (libsodium) with
 * Linux security subsystems (LUKS, fscrypt, namespaces, cgroups)
 * to provide a unified security interface.
 *
 * CrypticEngine is an ORCHESTRATOR, not a cipher.
 * All crypto operations delegate to libsodium.
 * All isolation delegates to the Linux kernel.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_CRYPTIC_H
#define SECUREZ_CRYPTIC_H

#include "crypto_core.h"
#include "secure_memory.h"
#include "secure_session.h"
#include "hidden_container.h"
#include "key_storage.h"
#include "nxe_format.h"
#include "integrity.h"

#include <stddef.h>
#include <stdint.h>

/* ── Version ─────────────────────────────────────────────────── */

#define CRYPTIC_VERSION_MAJOR  1
#define CRYPTIC_VERSION_MINOR  0
#define CRYPTIC_VERSION_PATCH  0
#define CRYPTIC_VERSION_STRING "1.0.0"

/* ── Engine Lifecycle ────────────────────────────────────────── */

/*
 * Initialize the CrypticEngine.
 *
 * Must be called before any other cryptic_* function.
 * Initializes:
 *  - libsodium
 *  - Secure memory subsystem
 *  - Session subsystem
 *  - Container subsystem
 *
 * @return 0 on success, -1 on failure
 */
int cryptic_init(void);

/*
 * Shut down the CrypticEngine.
 *
 * Cleans up all resources:
 *  - Wipes all cached keys from memory
 *  - Destroys all active sessions
 *  - Closes all open containers
 *  - Frees all secure memory
 */
void cryptic_shutdown(void);

/*
 * Get CrypticEngine version string.
 *
 * @return Version string (e.g., "1.0.0")
 */
const char *cryptic_version(void);

/* ── File Encryption ─────────────────────────────────────────── */

/*
 * Encrypt a file using XChaCha20-Poly1305.
 *
 * Key is derived from password using Argon2id.
 * Output file has .szenc extension appended.
 * Original file is NOT deleted (use cryptic_secure_delete for that).
 *
 * File format: [salt:16][nonce:24][ciphertext+mac]
 *
 * @param path      Path to file to encrypt
 * @param password  Encryption password
 * @return 0 on success, -1 on failure
 */
int cryptic_encrypt_file(const char *path, const char *password);

/*
 * Decrypt a .szenc file.
 *
 * @param path      Path to .szenc file
 * @param password  Decryption password
 * @return 0 on success, -1 on failure (wrong password or corrupted)
 */
int cryptic_decrypt_file(const char *path, const char *password);

/* ── Folder Encryption (fscrypt) ─────────────────────────────── */

/*
 * Lock (encrypt) a folder using kernel fscrypt.
 *
 * fscrypt provides real, kernel-enforced per-directory encryption.
 * This is a REAL security boundary — even root cannot read locked data.
 *
 * @param path      Directory path
 * @param password  Encryption password
 * @return 0 on success, -1 on failure
 */
int cryptic_lock_folder(const char *path, const char *password);

/*
 * Unlock (decrypt) a locked folder.
 *
 * @param path      Directory path
 * @param password  Decryption password
 * @return 0 on success, -1 on failure
 */
int cryptic_unlock_folder(const char *path, const char *password);

/* ── Secure File Deletion ────────────────────────────────────── */

/*
 * Securely delete a file.
 *
 * Overwrites with:
 *  1. All zeros
 *  2. All ones
 *  3. Cryptographic random
 * Then unlinks the file.
 *
 * NOTE: On SSDs with wear leveling, this may not fully erase data.
 * For true erasure on SSDs, use full-disk encryption (LUKS) and
 * discard the key.
 *
 * @param path  File to securely delete
 * @return 0 on success, -1 on failure
 */
int cryptic_secure_delete(const char *path);

/* ── File Hashing ────────────────────────────────────────────── */

/*
 * Compute BLAKE2b-256 hash of a file and return as hex string.
 *
 * @param path     File to hash
 * @param hex_out  Output buffer (must be at least 65 bytes for hash + null)
 * @return 0 on success, -1 on failure
 */
int cryptic_hash_file(const char *path, char *hex_out);

/* ── Daemon Communication ────────────────────────────────────── */

#define CRYPTICD_SOCKET_PATH  "/run/crypticd.sock"

/*
 * Send a command to the CrypticEngine daemon.
 *
 * @param json_cmd   JSON command string
 * @param response   Output: JSON response (caller must free)
 * @return 0 on success, -1 on failure
 */
int cryptic_daemon_command(const char *json_cmd, char **response);

/*
 * Check if the CrypticEngine daemon is running.
 *
 * @return 1 if running, 0 if not
 */
int cryptic_daemon_is_running(void);

#endif /* SECUREZ_CRYPTIC_H */
