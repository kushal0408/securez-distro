/*
 * SecureZ+ OS — CrypticEngine
 * nxe_format.h — .nxe Executable Format Specification
 *
 * The .nxe format is SecureZ+'s signature binary format.
 * It wraps standard ELF binaries with encryption and signing.
 *
 * SECURITY NOTE: .nxe is a flagship identity feature. It provides
 * defense-in-depth through encryption and signing, but the real
 * security boundaries are LUKS, fscrypt, namespaces, and AppArmor.
 * An attacker with root access can always extract the decrypted
 * binary from memory — this is inherent to any execution scheme.
 *
 * What .nxe DOES provide:
 *  - Confidentiality at rest (encrypted on disk)
 *  - Integrity verification (signed binaries)
 *  - Permission declarations (sandboxing hints)
 *  - Cool factor (it's what makes SecureZ+ unique)
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_NXE_FORMAT_H
#define SECUREZ_NXE_FORMAT_H

#include <stdint.h>
#include <stddef.h>

/* ── Magic & Version ─────────────────────────────────────────── */

#define NXE_MAGIC_0  'N'
#define NXE_MAGIC_1  'X'
#define NXE_MAGIC_2  'E'
#define NXE_MAGIC_3  0x01
#define NXE_MAGIC    "NXE\x01"
#define NXE_MAGIC_LEN 4

#define NXE_VERSION_1_0  0x00010000

/* ── Flags ───────────────────────────────────────────────────── */

#define NXE_FLAG_ENCRYPTED   0x00000001  /* Payload is encrypted */
#define NXE_FLAG_SIGNED      0x00000002  /* Payload has Ed25519 signature */
#define NXE_FLAG_RAM_ONLY    0x00000004  /* Execute via memfd_create only */
#define NXE_FLAG_SANDBOXED   0x00000008  /* Run with restricted permissions */

/* ── Permission Bits ─────────────────────────────────────────── */

#define NXE_PERM_NONE        0x00000000
#define NXE_PERM_NETWORK     0x00000001  /* App may access network */
#define NXE_PERM_FILESYSTEM  0x00000002  /* App may access filesystem */
#define NXE_PERM_DISPLAY     0x00000004  /* App may access display server */
#define NXE_PERM_AUDIO       0x00000008  /* App may access audio */
#define NXE_PERM_CAMERA      0x00000010  /* App may access camera */
#define NXE_PERM_USB         0x00000020  /* App may access USB devices */
#define NXE_PERM_IPC         0x00000040  /* App may use IPC */
#define NXE_PERM_DBUS        0x00000080  /* App may access D-Bus */
#define NXE_PERM_ALL         0xFFFFFFFF  /* Full permissions (trusted) */

/* ── .nxe File Header ────────────────────────────────────────── */

/*
 * Binary layout on disk:
 *
 * ┌─────────────────────────────────────┐  offset 0
 * │ NxeHeader (280 bytes, packed)       │
 * ├─────────────────────────────────────┤  offset 280
 * │ Encrypted ELF payload               │
 * │ (XChaCha20-Poly1305)               │
 * │ (includes 16-byte MAC at end)       │
 * └─────────────────────────────────────┘
 */

typedef struct __attribute__((packed)) {
    /* Magic identification: "NXE\x01" */
    uint8_t  magic[NXE_MAGIC_LEN];

    /* Format version (NXE_VERSION_1_0) */
    uint32_t version;

    /* Feature flags (NXE_FLAG_*) */
    uint32_t flags;

    /* Ed25519 detached signature over the encrypted payload.
     * Zeroed if NXE_FLAG_SIGNED is not set. */
    uint8_t  signature[64];

    /* Ed25519 public key of the signer.
     * Zeroed if NXE_FLAG_SIGNED is not set. */
    uint8_t  pubkey[32];

    /* BLAKE2b-256 hash of the DECRYPTED (original) ELF binary.
     * Used to verify integrity after decryption. */
    uint8_t  payload_hash[32];

    /* Permission declarations (NXE_PERM_*).
     * Enforced by the sandbox if NXE_FLAG_SANDBOXED is set. */
    uint32_t permissions;

    /* Offset in bytes from start of file to encrypted payload. */
    uint32_t payload_offset;

    /* Size in bytes of the encrypted payload (includes MAC). */
    uint32_t payload_size;

    /* XChaCha20-Poly1305 nonce (randomly generated per build). */
    uint8_t  nonce[24];

    /* Argon2id salt for key derivation from password. */
    uint8_t  salt[16];

    /* Reserved for future use. Must be zeroed. */
    uint8_t  reserved[64];

} NxeHeader;

/* Header should be exactly 256 bytes */
_Static_assert(sizeof(NxeHeader) == 256, "NxeHeader must be 256 bytes");

/* ── .nxe Loader API ─────────────────────────────────────────── */

/*
 * Load and execute a .nxe binary.
 *
 * Steps:
 *  1. Read and validate NxeHeader
 *  2. If SIGNED: verify Ed25519 signature
 *  3. If ENCRYPTED: derive key from password (Argon2id), decrypt payload
 *  4. Verify BLAKE2b hash of decrypted payload
 *  5. Create memfd (memfd_create, never touches disk)
 *  6. Write decrypted ELF to memfd
 *  7. If SANDBOXED: apply permission restrictions
 *  8. execve from /proc/self/fd/<memfd>
 *
 * @param path      Path to .nxe file
 * @param password  Decryption password (NULL if not encrypted)
 * @param argv      Arguments to pass to the binary (NULL-terminated)
 * @param envp      Environment variables (NULL-terminated, NULL for inherit)
 * @return Does not return on success; -1 on failure
 */
int nxe_load_and_exec(const char *path, const char *password,
                      char *const argv[], char *const envp[]);

/*
 * Verify a .nxe binary without executing it.
 *
 * Checks:
 *  - Magic bytes
 *  - Version compatibility
 *  - Signature (if signed)
 *  - Header consistency
 *
 * @param path  Path to .nxe file
 * @return 0 if valid, -1 if invalid (sets errno)
 */
int nxe_verify(const char *path);

/*
 * Inspect a .nxe binary and print its metadata.
 *
 * @param path  Path to .nxe file
 * @param info  Output: NxeHeader populated from file
 * @return 0 on success, -1 on failure
 */
int nxe_inspect(const char *path, NxeHeader *info);

/* ── .nxe Builder API ────────────────────────────────────────── */

/*
 * Build a .nxe binary from a standard ELF executable.
 *
 * @param elf_path    Path to input ELF binary
 * @param nxe_path    Path for output .nxe file
 * @param password    Encryption password (NULL to skip encryption)
 * @param sk          Ed25519 secret key for signing (NULL to skip signing)
 * @param pk          Ed25519 public key (NULL to skip signing)
 * @param permissions Permission flags (NXE_PERM_*)
 * @param flags       Additional flags (NXE_FLAG_RAM_ONLY, NXE_FLAG_SANDBOXED)
 * @return 0 on success, -1 on failure
 */
int nxe_build(const char *elf_path, const char *nxe_path,
              const char *password, const uint8_t *sk,
              const uint8_t *pk, uint32_t permissions,
              uint32_t flags);

#endif /* SECUREZ_NXE_FORMAT_H */
