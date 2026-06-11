/*
 * SecureZ+ OS — CrypticEngine
 * nxe_loader.c — .nxe binary loader (fileless execution via memfd_create)
 *
 * SECURITY NOTE: .nxe is SecureZ+'s signature feature. The encrypted-
 * then-execute-from-RAM approach provides at-rest confidentiality and
 * integrity verification. However, it is NOT a security boundary against
 * an attacker with root access — real isolation comes from namespaces,
 * LUKS, fscrypt, and AppArmor.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#define _GNU_SOURCE
#include "nxe_format.h"
#include "crypto_core.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* memfd_create may not be in older headers */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;

/* ── Internal helpers ────────────────────────────────────────── */

static int read_full_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0 || size > (100L << 20)) {  /* 100 MB limit */
        fclose(f);
        errno = EFBIG;
        return -1;
    }

    *data = malloc((size_t)size);
    if (!*data) {
        fclose(f);
        return -1;
    }

    *len = fread(*data, 1, (size_t)size, f);
    fclose(f);

    if (*len != (size_t)size) {
        free(*data);
        *data = NULL;
        return -1;
    }

    return 0;
}

static int validate_header(const NxeHeader *hdr)
{
    if (memcmp(hdr->magic, NXE_MAGIC, NXE_MAGIC_LEN) != 0) {
        fprintf(stderr, "[NXE] Invalid magic bytes — not a .nxe file\n");
        return -1;
    }

    if (hdr->version != NXE_VERSION_1_0) {
        fprintf(stderr, "[NXE] Unsupported version: 0x%08x\n", hdr->version);
        return -1;
    }

    if (hdr->payload_offset != sizeof(NxeHeader)) {
        fprintf(stderr, "[NXE] Invalid payload offset\n");
        return -1;
    }

    return 0;
}

/* ── Public API ──────────────────────────────────────────────── */

int nxe_load_and_exec(const char *path, const char *password,
                      char *const argv[], char *const envp[])
{
    uint8_t *file_data = NULL;
    size_t file_len = 0;

    if (read_full_file(path, &file_data, &file_len) != 0) {
        perror("[NXE] Cannot read .nxe file");
        return -1;
    }

    if (file_len < sizeof(NxeHeader)) {
        fprintf(stderr, "[NXE] File too small for .nxe header\n");
        free(file_data);
        return -1;
    }

    /* Parse header */
    NxeHeader hdr;
    memcpy(&hdr, file_data, sizeof(NxeHeader));

    if (validate_header(&hdr) != 0) {
        free(file_data);
        return -1;
    }

    /* Extract encrypted payload */
    if (hdr.payload_offset + hdr.payload_size > file_len) {
        fprintf(stderr, "[NXE] Payload extends beyond file\n");
        free(file_data);
        return -1;
    }

    const uint8_t *payload = file_data + hdr.payload_offset;
    size_t payload_len = hdr.payload_size;

    /* Step 1: Verify signature (if signed) */
    if (hdr.flags & NXE_FLAG_SIGNED) {
        if (crypto_verify_signature(hdr.signature, payload,
                                    payload_len, hdr.pubkey) != 0) {
            fprintf(stderr, "[NXE] ❌ SIGNATURE VERIFICATION FAILED — "
                            "binary may be tampered!\n");
            free(file_data);
            return -1;
        }
        fprintf(stderr, "[NXE] ✅ Signature verified\n");
    }

    /* Step 2: Decrypt payload (if encrypted) */
    uint8_t *elf_data = NULL;
    size_t elf_len = 0;

    if (hdr.flags & NXE_FLAG_ENCRYPTED) {
        if (!password) {
            fprintf(stderr, "[NXE] Binary is encrypted but no password provided\n");
            free(file_data);
            return -1;
        }

        /* Derive decryption key from password + salt in header */
        uint8_t *key = secure_alloc(CRYPTIC_KEY_LEN);
        if (!key) {
            free(file_data);
            return -1;
        }

        if (crypto_derive_key(key, password, hdr.salt,
                              CRYPTIC_KDF_OPSLIMIT_NORMAL,
                              CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
            secure_free(key, CRYPTIC_KEY_LEN);
            free(file_data);
            return -1;
        }

        /* Decrypt */
        elf_data = malloc(payload_len);  /* plaintext is smaller */
        if (!elf_data) {
            secure_free(key, CRYPTIC_KEY_LEN);
            free(file_data);
            return -1;
        }

        unsigned long long pt_len = 0;
        if (crypto_decrypt_buffer(elf_data, &pt_len,
                                  payload, payload_len,
                                  hdr.nonce, key) != 0) {
            fprintf(stderr, "[NXE] ❌ Decryption failed — wrong password or corrupted\n");
            secure_free(key, CRYPTIC_KEY_LEN);
            free(elf_data);
            free(file_data);
            return -1;
        }

        secure_free(key, CRYPTIC_KEY_LEN);
        elf_len = (size_t)pt_len;
    } else {
        /* Not encrypted — payload is raw ELF */
        elf_data = malloc(payload_len);
        if (!elf_data) {
            free(file_data);
            return -1;
        }
        memcpy(elf_data, payload, payload_len);
        elf_len = payload_len;
    }

    free(file_data);

    /* Step 3: Verify BLAKE2b hash of decrypted ELF */
    uint8_t actual_hash[CRYPTIC_HASH_LEN];
    if (crypto_hash_buffer(actual_hash, elf_data, elf_len) != 0) {
        sodium_memzero(elf_data, elf_len);
        free(elf_data);
        return -1;
    }

    if (memcmp(actual_hash, hdr.payload_hash, CRYPTIC_HASH_LEN) != 0) {
        fprintf(stderr, "[NXE] ❌ Payload hash mismatch — binary corrupted!\n");
        sodium_memzero(elf_data, elf_len);
        free(elf_data);
        return -1;
    }

    /* Step 4: Create anonymous memory file (NEVER touches disk) */
    int memfd = memfd_create("nxe_exec", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("[NXE] memfd_create failed");
        sodium_memzero(elf_data, elf_len);
        free(elf_data);
        return -1;
    }

    /* Write decrypted ELF to memfd */
    if (write(memfd, elf_data, elf_len) != (ssize_t)elf_len) {
        perror("[NXE] Failed to write to memfd");
        close(memfd);
        sodium_memzero(elf_data, elf_len);
        free(elf_data);
        return -1;
    }

    /* Wipe decrypted ELF from our memory immediately */
    sodium_memzero(elf_data, elf_len);
    free(elf_data);

    /* Make memfd executable */
    if (fchmod(memfd, 0500) != 0) {
        /* Some kernels don't support fchmod on memfd, ignore */
    }

    /* Step 5: Execute from memfd (the ELF never touches disk!) */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", memfd);

    fprintf(stderr, "[NXE] 🚀 Executing %s from memory\n", path);

    execve(fd_path, argv, envp ? envp : environ);

    /* If we get here, execve failed */
    perror("[NXE] execve failed");
    close(memfd);
    return -1;
}

int nxe_verify(const char *path)
{
    uint8_t *file_data = NULL;
    size_t file_len = 0;

    if (read_full_file(path, &file_data, &file_len) != 0) {
        return -1;
    }

    if (file_len < sizeof(NxeHeader)) {
        free(file_data);
        errno = EINVAL;
        return -1;
    }

    NxeHeader hdr;
    memcpy(&hdr, file_data, sizeof(NxeHeader));

    if (validate_header(&hdr) != 0) {
        free(file_data);
        return -1;
    }

    /* Verify signature if signed */
    if (hdr.flags & NXE_FLAG_SIGNED) {
        const uint8_t *payload = file_data + hdr.payload_offset;
        if (crypto_verify_signature(hdr.signature, payload,
                                    hdr.payload_size, hdr.pubkey) != 0) {
            fprintf(stderr, "[NXE] Signature verification FAILED\n");
            free(file_data);
            return -1;
        }
        fprintf(stderr, "[NXE] Signature OK\n");
    }

    free(file_data);
    fprintf(stderr, "[NXE] Verification passed for %s\n", path);
    return 0;
}

int nxe_inspect(const char *path, NxeHeader *info)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fread(info, sizeof(NxeHeader), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);

    return validate_header(info);
}
