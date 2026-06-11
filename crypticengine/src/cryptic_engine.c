/*
 * SecureZ+ OS — CrypticEngine
 * cryptic_engine.c — Main engine orchestrator
 *
 * Coordinates all CrypticEngine subsystems and provides the
 * high-level file encryption/decryption/deletion API.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "cryptic.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

static int engine_initialized = 0;

/* ── File format for .szenc encrypted files ──────────────────── */
/*
 * Layout: [salt:16][nonce:24][ciphertext+mac]
 * Total overhead: 16 + 24 + 16(mac) = 56 bytes
 */
#define SZENC_HEADER_LEN  (CRYPTIC_SALT_LEN + CRYPTIC_NONCE_LEN)
#define SZENC_EXTENSION   ".szenc"

/* ── Engine Lifecycle ────────────────────────────────────────── */

int cryptic_init(void)
{
    if (engine_initialized) return 0;

    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "[CrypticEngine] FATAL: Failed to initialize libsodium\n");
        return -1;
    }

    /* Initialize secure memory subsystem */
    if (secure_memory_init() != 0) {
        fprintf(stderr, "[CrypticEngine] FATAL: Failed to initialize secure memory\n");
        return -1;
    }

    /* Initialize session subsystem */
    if (session_init() != 0) {
        fprintf(stderr, "[CrypticEngine] WARNING: Failed to initialize sessions "
                        "(may need root)\n");
        /* Non-fatal — sessions require root */
    }

    /* Initialize container subsystem */
    if (container_init() != 0) {
        fprintf(stderr, "[CrypticEngine] WARNING: Failed to initialize containers "
                        "(may need root)\n");
        /* Non-fatal — containers require root */
    }

    engine_initialized = 1;
    fprintf(stderr, "[CrypticEngine] Initialized v%s\n", CRYPTIC_VERSION_STRING);
    return 0;
}

void cryptic_shutdown(void)
{
    if (!engine_initialized) return;

    /* Close all containers */
    container_close_all();

    /* Destroy all sessions */
    session_shutdown();

    /* Wipe all secure memory (keys, etc.) */
    secure_memory_shutdown();

    engine_initialized = 0;
    fprintf(stderr, "[CrypticEngine] Shut down — all keys wiped\n");
}

const char *cryptic_version(void)
{
    return CRYPTIC_VERSION_STRING;
}

/* ── File Encryption ─────────────────────────────────────────── */

int cryptic_encrypt_file(const char *path, const char *password)
{
    if (!path || !password) {
        errno = EINVAL;
        return -1;
    }

    /* Read input file */
    FILE *f_in = fopen(path, "rb");
    if (!f_in) {
        perror("[CrypticEngine] Cannot open input file");
        return -1;
    }

    fseek(f_in, 0, SEEK_END);
    long file_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    if (file_size < 0 || file_size > (1L << 30)) { /* Max 1 GB */
        fprintf(stderr, "[CrypticEngine] File too large (max 1 GB)\n");
        fclose(f_in);
        return -1;
    }

    size_t pt_len = (size_t)file_size;
    uint8_t *plaintext = malloc(pt_len);
    if (!plaintext) {
        fclose(f_in);
        return -1;
    }

    if (fread(plaintext, 1, pt_len, f_in) != pt_len) {
        fclose(f_in);
        free(plaintext);
        return -1;
    }
    fclose(f_in);

    /* Generate salt and nonce */
    uint8_t salt[CRYPTIC_SALT_LEN];
    uint8_t nonce[CRYPTIC_NONCE_LEN];
    crypto_generate_salt(salt);
    crypto_random_bytes(nonce, CRYPTIC_NONCE_LEN);

    /* Derive encryption key from password (Argon2id) */
    uint8_t *key = secure_alloc(CRYPTIC_KEY_LEN);
    if (!key) {
        sodium_memzero(plaintext, pt_len);
        free(plaintext);
        return -1;
    }

    if (crypto_derive_key(key, password, salt,
                          CRYPTIC_KDF_OPSLIMIT_NORMAL,
                          CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
        secure_free(key, CRYPTIC_KEY_LEN);
        sodium_memzero(plaintext, pt_len);
        free(plaintext);
        return -1;
    }

    /* Encrypt (ciphertext includes MAC) */
    size_t ct_alloc = pt_len + CRYPTIC_MAC_LEN;
    uint8_t *ciphertext = malloc(ct_alloc);
    if (!ciphertext) {
        secure_free(key, CRYPTIC_KEY_LEN);
        sodium_memzero(plaintext, pt_len);
        free(plaintext);
        return -1;
    }

    unsigned long long ct_len = 0;
    int ret = crypto_encrypt_buffer(ciphertext, &ct_len,
                                    plaintext, pt_len,
                                    nonce, key);

    /* Wipe sensitive data immediately */
    secure_free(key, CRYPTIC_KEY_LEN);
    sodium_memzero(plaintext, pt_len);
    free(plaintext);

    if (ret != 0) {
        free(ciphertext);
        return -1;
    }

    /* Build output path: <original>.szenc */
    size_t out_path_len = strlen(path) + strlen(SZENC_EXTENSION) + 1;
    char *out_path = malloc(out_path_len);
    if (!out_path) {
        free(ciphertext);
        return -1;
    }
    snprintf(out_path, out_path_len, "%s%s", path, SZENC_EXTENSION);

    /* Write: [salt][nonce][ciphertext+mac] */
    FILE *f_out = fopen(out_path, "wb");
    if (!f_out) {
        perror("[CrypticEngine] Cannot create output file");
        free(out_path);
        free(ciphertext);
        return -1;
    }

    int write_ok = 1;
    if (fwrite(salt, 1, CRYPTIC_SALT_LEN, f_out) != CRYPTIC_SALT_LEN) write_ok = 0;
    if (fwrite(nonce, 1, CRYPTIC_NONCE_LEN, f_out) != CRYPTIC_NONCE_LEN) write_ok = 0;
    if (fwrite(ciphertext, 1, (size_t)ct_len, f_out) != (size_t)ct_len) write_ok = 0;

    fclose(f_out);
    free(ciphertext);

    if (!write_ok) {
        unlink(out_path);
        free(out_path);
        return -1;
    }

    fprintf(stderr, "[CrypticEngine] Encrypted: %s → %s\n", path, out_path);
    free(out_path);
    return 0;
}

int cryptic_decrypt_file(const char *path, const char *password)
{
    if (!path || !password) {
        errno = EINVAL;
        return -1;
    }

    /* Read encrypted file */
    FILE *f_in = fopen(path, "rb");
    if (!f_in) {
        perror("[CrypticEngine] Cannot open encrypted file");
        return -1;
    }

    fseek(f_in, 0, SEEK_END);
    long file_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    if (file_size < (long)(SZENC_HEADER_LEN + CRYPTIC_MAC_LEN)) {
        fprintf(stderr, "[CrypticEngine] File too small to be a valid .szenc file\n");
        fclose(f_in);
        return -1;
    }

    /* Read salt and nonce */
    uint8_t salt[CRYPTIC_SALT_LEN];
    uint8_t nonce[CRYPTIC_NONCE_LEN];

    if (fread(salt, 1, CRYPTIC_SALT_LEN, f_in) != CRYPTIC_SALT_LEN ||
        fread(nonce, 1, CRYPTIC_NONCE_LEN, f_in) != CRYPTIC_NONCE_LEN) {
        fclose(f_in);
        return -1;
    }

    /* Read ciphertext (includes MAC) */
    size_t ct_len = (size_t)file_size - SZENC_HEADER_LEN;
    uint8_t *ciphertext = malloc(ct_len);
    if (!ciphertext) {
        fclose(f_in);
        return -1;
    }

    if (fread(ciphertext, 1, ct_len, f_in) != ct_len) {
        fclose(f_in);
        free(ciphertext);
        return -1;
    }
    fclose(f_in);

    /* Derive decryption key */
    uint8_t *key = secure_alloc(CRYPTIC_KEY_LEN);
    if (!key) {
        free(ciphertext);
        return -1;
    }

    if (crypto_derive_key(key, password, salt,
                          CRYPTIC_KDF_OPSLIMIT_NORMAL,
                          CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
        secure_free(key, CRYPTIC_KEY_LEN);
        free(ciphertext);
        return -1;
    }

    /* Decrypt */
    size_t pt_alloc = ct_len;  /* plaintext is smaller than ciphertext */
    uint8_t *plaintext = malloc(pt_alloc);
    if (!plaintext) {
        secure_free(key, CRYPTIC_KEY_LEN);
        free(ciphertext);
        return -1;
    }

    unsigned long long pt_len = 0;
    int ret = crypto_decrypt_buffer(plaintext, &pt_len,
                                    ciphertext, ct_len,
                                    nonce, key);

    secure_free(key, CRYPTIC_KEY_LEN);
    free(ciphertext);

    if (ret != 0) {
        sodium_memzero(plaintext, pt_alloc);
        free(plaintext);
        fprintf(stderr, "[CrypticEngine] Decryption failed — wrong password or corrupted file\n");
        return -1;
    }

    /* Build output path: strip .szenc extension */
    size_t path_len = strlen(path);
    size_t ext_len = strlen(SZENC_EXTENSION);
    char *out_path;

    if (path_len > ext_len &&
        strcmp(path + path_len - ext_len, SZENC_EXTENSION) == 0) {
        out_path = malloc(path_len - ext_len + 1);
        if (!out_path) {
            sodium_memzero(plaintext, pt_alloc);
            free(plaintext);
            return -1;
        }
        memcpy(out_path, path, path_len - ext_len);
        out_path[path_len - ext_len] = '\0';
    } else {
        /* No .szenc extension — append .dec */
        out_path = malloc(path_len + 5);
        if (!out_path) {
            sodium_memzero(plaintext, pt_alloc);
            free(plaintext);
            return -1;
        }
        snprintf(out_path, path_len + 5, "%s.dec", path);
    }

    /* Write decrypted output */
    FILE *f_out = fopen(out_path, "wb");
    if (!f_out) {
        perror("[CrypticEngine] Cannot create output file");
        sodium_memzero(plaintext, pt_alloc);
        free(plaintext);
        free(out_path);
        return -1;
    }

    int write_ok = (fwrite(plaintext, 1, (size_t)pt_len, f_out) == (size_t)pt_len);
    fclose(f_out);

    sodium_memzero(plaintext, pt_alloc);
    free(plaintext);

    if (!write_ok) {
        unlink(out_path);
        free(out_path);
        return -1;
    }

    fprintf(stderr, "[CrypticEngine] Decrypted: %s → %s\n", path, out_path);
    free(out_path);
    return 0;
}

/* ── Folder Encryption (fscrypt) ─────────────────────────────── */

int cryptic_lock_folder(const char *path, const char *password)
{
    if (!path || !password) {
        errno = EINVAL;
        return -1;
    }

    /* fscrypt lock uses kernel-native per-directory encryption.
     * This is a REAL security boundary. */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "fscrypt lock '%s' 2>&1", path);

    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "[CrypticEngine] fscrypt lock failed for %s "
                        "(is fscrypt set up on this filesystem?)\n", path);
        return -1;
    }

    fprintf(stderr, "[CrypticEngine] Folder locked: %s\n", path);
    return 0;
}

int cryptic_unlock_folder(const char *path, const char *password)
{
    if (!path || !password) {
        errno = EINVAL;
        return -1;
    }

    /* Unlock via fscrypt — the password is passed via fscrypt's own
     * interactive prompt or PAM integration */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "fscrypt unlock '%s' 2>&1", path);

    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "[CrypticEngine] fscrypt unlock failed for %s\n", path);
        return -1;
    }

    fprintf(stderr, "[CrypticEngine] Folder unlocked: %s\n", path);
    return 0;
}

/* ── Secure File Deletion ────────────────────────────────────── */

int cryptic_secure_delete(const char *path)
{
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        perror("[CrypticEngine] Cannot stat file");
        return -1;
    }

    size_t file_size = (size_t)st.st_size;
    if (file_size == 0) {
        /* Empty file — just unlink */
        unlink(path);
        return 0;
    }

    FILE *f = fopen(path, "r+b");
    if (!f) {
        perror("[CrypticEngine] Cannot open file for overwrite");
        return -1;
    }

    uint8_t *buf = malloc(file_size < 8192 ? file_size : 8192);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t chunk = file_size < 8192 ? file_size : 8192;

    /* Pass 1: Zeros */
    memset(buf, 0x00, chunk);
    fseek(f, 0, SEEK_SET);
    for (size_t written = 0; written < file_size; ) {
        size_t to_write = (file_size - written < chunk) ? file_size - written : chunk;
        fwrite(buf, 1, to_write, f);
        written += to_write;
    }
    fflush(f);
    fsync(fileno(f));

    /* Pass 2: Ones */
    memset(buf, 0xFF, chunk);
    fseek(f, 0, SEEK_SET);
    for (size_t written = 0; written < file_size; ) {
        size_t to_write = (file_size - written < chunk) ? file_size - written : chunk;
        fwrite(buf, 1, to_write, f);
        written += to_write;
    }
    fflush(f);
    fsync(fileno(f));

    /* Pass 3: Random */
    fseek(f, 0, SEEK_SET);
    for (size_t written = 0; written < file_size; ) {
        size_t to_write = (file_size - written < chunk) ? file_size - written : chunk;
        randombytes_buf(buf, to_write);
        fwrite(buf, 1, to_write, f);
        written += to_write;
    }
    fflush(f);
    fsync(fileno(f));

    fclose(f);
    free(buf);

    /* Finally unlink */
    if (unlink(path) != 0) {
        perror("[CrypticEngine] Cannot unlink file");
        return -1;
    }

    fprintf(stderr, "[CrypticEngine] Securely deleted: %s\n", path);
    return 0;
}

/* ── File Hashing ────────────────────────────────────────────── */

int cryptic_hash_file(const char *path, char *hex_out)
{
    if (!path || !hex_out) {
        errno = EINVAL;
        return -1;
    }

    uint8_t hash[CRYPTIC_HASH_LEN];
    if (crypto_hash_file(hash, path) != 0) {
        return -1;
    }

    crypto_bin_to_hex(hex_out, hash, CRYPTIC_HASH_LEN);
    return 0;
}

/* ── Daemon Communication ────────────────────────────────────── */

int cryptic_daemon_is_running(void)
{
    return access(CRYPTICD_SOCKET_PATH, F_OK) == 0;
}

int cryptic_daemon_command(const char *json_cmd, char **response)
{
    if (!json_cmd || !response) {
        errno = EINVAL;
        return -1;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CRYPTICD_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    /* Send command */
    size_t cmd_len = strlen(json_cmd);
    if (write(sock, json_cmd, cmd_len) != (ssize_t)cmd_len) {
        close(sock);
        return -1;
    }

    /* Signal end of command */
    shutdown(sock, SHUT_WR);

    /* Read response */
    char buf[4096];
    ssize_t nread = read(sock, buf, sizeof(buf) - 1);
    close(sock);

    if (nread <= 0) return -1;

    buf[nread] = '\0';
    *response = strdup(buf);
    return *response ? 0 : -1;
}
