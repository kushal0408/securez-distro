/*
 * SecureZ+ OS — CrypticEngine
 * nxe_builder.c — Build .nxe binaries from standard ELF executables
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
#include <getopt.h>
#include <sodium.h>

/* ── Build API ───────────────────────────────────────────────── */

int nxe_build(const char *elf_path, const char *nxe_path,
              const char *password, const uint8_t *sk,
              const uint8_t *pk, uint32_t permissions,
              uint32_t flags)
{
    if (!elf_path || !nxe_path) {
        errno = EINVAL;
        return -1;
    }

    /* Read input ELF */
    FILE *f_in = fopen(elf_path, "rb");
    if (!f_in) {
        perror("[NXE-Build] Cannot open input ELF");
        return -1;
    }

    fseek(f_in, 0, SEEK_END);
    long elf_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    if (elf_size <= 0 || elf_size > (100L << 20)) {
        fprintf(stderr, "[NXE-Build] Invalid ELF size\n");
        fclose(f_in);
        return -1;
    }

    uint8_t *elf_data = malloc((size_t)elf_size);
    if (!elf_data) {
        fclose(f_in);
        return -1;
    }

    if (fread(elf_data, 1, (size_t)elf_size, f_in) != (size_t)elf_size) {
        fclose(f_in);
        free(elf_data);
        return -1;
    }
    fclose(f_in);

    /* Verify it's actually an ELF */
    if (elf_size >= 4 && memcmp(elf_data, "\x7f""ELF", 4) != 0) {
        fprintf(stderr, "[NXE-Build] Warning: Input doesn't look like an ELF binary\n");
    }

    /* Build the header */
    NxeHeader hdr;
    memset(&hdr, 0, sizeof(hdr));

    memcpy(hdr.magic, NXE_MAGIC, NXE_MAGIC_LEN);
    hdr.version = NXE_VERSION_1_0;
    hdr.flags = flags | NXE_FLAG_RAM_ONLY;  /* Always RAM-only */
    hdr.permissions = permissions;
    hdr.payload_offset = sizeof(NxeHeader);

    /* Compute BLAKE2b hash of original ELF (before encryption) */
    if (crypto_hash_buffer(hdr.payload_hash, elf_data, (size_t)elf_size) != 0) {
        free(elf_data);
        return -1;
    }

    /* Prepare payload (encrypt if requested) */
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (password) {
        hdr.flags |= NXE_FLAG_ENCRYPTED;

        /* Generate random salt and nonce */
        crypto_generate_salt(hdr.salt);
        crypto_random_bytes(hdr.nonce, CRYPTIC_NONCE_LEN);

        /* Derive encryption key */
        uint8_t *key = secure_alloc(CRYPTIC_KEY_LEN);
        if (!key) {
            free(elf_data);
            return -1;
        }

        if (crypto_derive_key(key, password, hdr.salt,
                              CRYPTIC_KDF_OPSLIMIT_NORMAL,
                              CRYPTIC_KDF_MEMLIMIT_NORMAL) != 0) {
            secure_free(key, CRYPTIC_KEY_LEN);
            free(elf_data);
            return -1;
        }

        /* Encrypt ELF data */
        size_t ct_alloc = (size_t)elf_size + CRYPTIC_MAC_LEN;
        payload = malloc(ct_alloc);
        if (!payload) {
            secure_free(key, CRYPTIC_KEY_LEN);
            free(elf_data);
            return -1;
        }

        unsigned long long ct_len = 0;
        if (crypto_encrypt_buffer(payload, &ct_len,
                                  elf_data, (size_t)elf_size,
                                  hdr.nonce, key) != 0) {
            secure_free(key, CRYPTIC_KEY_LEN);
            free(payload);
            free(elf_data);
            return -1;
        }

        secure_free(key, CRYPTIC_KEY_LEN);
        payload_len = (size_t)ct_len;

        fprintf(stderr, "[NXE-Build] Encrypted payload: %zu → %zu bytes\n",
                (size_t)elf_size, payload_len);
    } else {
        /* No encryption — payload is raw ELF */
        payload = malloc((size_t)elf_size);
        if (!payload) {
            free(elf_data);
            return -1;
        }
        memcpy(payload, elf_data, (size_t)elf_size);
        payload_len = (size_t)elf_size;
    }

    hdr.payload_size = (uint32_t)payload_len;

    /* Sign if keys provided */
    if (sk && pk) {
        hdr.flags |= NXE_FLAG_SIGNED;
        memcpy(hdr.pubkey, pk, CRYPTIC_SIGN_PK_LEN);

        if (crypto_sign_buffer(hdr.signature, payload, payload_len, sk) != 0) {
            fprintf(stderr, "[NXE-Build] Signing failed\n");
            free(payload);
            free(elf_data);
            return -1;
        }

        fprintf(stderr, "[NXE-Build] Binary signed with Ed25519\n");
    }

    free(elf_data);

    /* Write output .nxe file */
    FILE *f_out = fopen(nxe_path, "wb");
    if (!f_out) {
        perror("[NXE-Build] Cannot create output file");
        free(payload);
        return -1;
    }

    int ok = 1;
    if (fwrite(&hdr, sizeof(hdr), 1, f_out) != 1) ok = 0;
    if (fwrite(payload, 1, payload_len, f_out) != payload_len) ok = 0;

    fclose(f_out);
    free(payload);

    if (!ok) {
        unlink(nxe_path);
        return -1;
    }

    fprintf(stderr, "[NXE-Build] Created: %s (%zu bytes)\n",
            nxe_path, sizeof(hdr) + payload_len);
    fprintf(stderr, "  Flags: %s%s%s%s\n",
            (hdr.flags & NXE_FLAG_ENCRYPTED) ? "ENCRYPTED " : "",
            (hdr.flags & NXE_FLAG_SIGNED) ? "SIGNED " : "",
            (hdr.flags & NXE_FLAG_RAM_ONLY) ? "RAM_ONLY " : "",
            (hdr.flags & NXE_FLAG_SANDBOXED) ? "SANDBOXED " : "");

    return 0;
}

/* ── CLI Tool ────────────────────────────────────────────────── */

#ifdef NXE_BUILD_MAIN

static void usage(const char *prog)
{
    fprintf(stderr,
        "SecureZ+ NXE Builder v1.0\n"
        "\n"
        "Usage: %s [OPTIONS] -i <input.elf> -o <output.nxe>\n"
        "\n"
        "Options:\n"
        "  -i, --input <file>    Input ELF binary\n"
        "  -o, --output <file>   Output .nxe file\n"
        "  -p, --password        Encrypt with password (prompted)\n"
        "  -s, --sign <keyfile>  Sign with Ed25519 secret key file\n"
        "  -P, --perms <flags>   Permission flags (hex, e.g., 0x07)\n"
        "  --sandbox             Enable sandboxed execution\n"
        "  -h, --help            Show this help\n"
        "\n"
        "Examples:\n"
        "  %s -i hello -o hello.nxe -p            # Encrypt with password\n"
        "  %s -i hello -o hello.nxe -s key.sec    # Sign with key\n"
        "  %s -i hello -o hello.nxe -p -s key.sec # Encrypt + sign\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    const char *input = NULL;
    const char *output = NULL;
    const char *keyfile = NULL;
    int do_encrypt = 0;
    int do_sandbox = 0;
    uint32_t perms = NXE_PERM_ALL;

    static struct option long_opts[] = {
        {"input",    required_argument, NULL, 'i'},
        {"output",   required_argument, NULL, 'o'},
        {"password", no_argument,       NULL, 'p'},
        {"sign",     required_argument, NULL, 's'},
        {"perms",    required_argument, NULL, 'P'},
        {"sandbox",  no_argument,       NULL, 'S'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "i:o:ps:P:Sh", long_opts, NULL)) != -1) {
        switch (c) {
            case 'i': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': do_encrypt = 1; break;
            case 's': keyfile = optarg; break;
            case 'P': perms = (uint32_t)strtoul(optarg, NULL, 0); break;
            case 'S': do_sandbox = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (!input || !output) {
        usage(argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    /* Get password if encrypting */
    char *password = NULL;
    if (do_encrypt) {
        password = getpass("Encryption password: ");
        if (!password || strlen(password) == 0) {
            fprintf(stderr, "Password required for encryption\n");
            return 1;
        }

        char *confirm = getpass("Confirm password: ");
        if (strcmp(password, confirm) != 0) {
            fprintf(stderr, "Passwords don't match\n");
            return 1;
        }
    }

    /* Load signing key if provided */
    uint8_t *sk = NULL, *pk = NULL;
    uint8_t sk_buf[CRYPTIC_SIGN_SK_LEN];
    uint8_t pk_buf[CRYPTIC_SIGN_PK_LEN];

    if (keyfile) {
        FILE *kf = fopen(keyfile, "rb");
        if (!kf) {
            perror("Cannot open key file");
            return 1;
        }
        /* Key file format: [sk:64][pk:32] */
        if (fread(sk_buf, 1, CRYPTIC_SIGN_SK_LEN, kf) != CRYPTIC_SIGN_SK_LEN ||
            fread(pk_buf, 1, CRYPTIC_SIGN_PK_LEN, kf) != CRYPTIC_SIGN_PK_LEN) {
            fprintf(stderr, "Invalid key file (expected 96 bytes: sk + pk)\n");
            fclose(kf);
            return 1;
        }
        fclose(kf);
        sk = sk_buf;
        pk = pk_buf;
    }

    uint32_t flags = 0;
    if (do_sandbox) flags |= NXE_FLAG_SANDBOXED;

    int ret = nxe_build(input, output, password, sk, pk, perms, flags);

    /* Wipe sensitive data */
    sodium_memzero(sk_buf, sizeof(sk_buf));

    return ret == 0 ? 0 : 1;
}

#endif /* NXE_BUILD_MAIN */
