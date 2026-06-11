/*
 * SecureZ+ OS — CrypticEngine
 * hidden_container.h — Hidden encrypted volumes with plausible deniability
 *
 * Uses LUKS with detached headers. Without the header file,
 * the container is indistinguishable from random data.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_HIDDEN_CONTAINER_H
#define SECUREZ_HIDDEN_CONTAINER_H

#include <stddef.h>
#include <stdint.h>

#define CONTAINER_NAME_MAX     64
#define CONTAINER_PATH_MAX     256
#define CONTAINER_MAX_ACTIVE   16

typedef enum {
    CONTAINER_STATE_CLOSED = 0,
    CONTAINER_STATE_OPEN,
    CONTAINER_STATE_ERROR
} ContainerState;

typedef struct {
    char            name[CONTAINER_NAME_MAX];
    char            vault_path[CONTAINER_PATH_MAX];    /* Encrypted volume file */
    char            header_path[CONTAINER_PATH_MAX];   /* Detached LUKS header */
    char            mount_path[CONTAINER_PATH_MAX];    /* Current mount point */
    char            mapper_name[CONTAINER_NAME_MAX];   /* /dev/mapper/<name> */
    ContainerState  state;
    size_t          size_mb;                           /* Total size in MB */
} ContainerInfo;

/*
 * Initialize the container subsystem.
 * Creates ~/.securez/containers/ if it doesn't exist.
 *
 * @return 0 on success, -1 on failure
 */
int container_init(void);

/*
 * Create a new hidden encrypted container.
 *
 * Creates:
 *  1. Sparse file at ~/.securez/containers/<name>.vault (filled with random)
 *  2. Detached LUKS header at ~/.securez/containers/<name>.header
 *  3. ext4 filesystem inside the encrypted volume
 *
 * Without the header file, the vault file looks like random noise.
 *
 * @param name      Container name
 * @param size_mb   Size in megabytes
 * @param password  Encryption password
 * @return 0 on success, -1 on failure
 */
int container_create(const char *name, size_t size_mb, const char *password);

/*
 * Open (mount) a hidden container.
 *
 * Steps:
 *  1. cryptsetup open with detached header
 *  2. Mount ext4 to /mnt/securez-vault/<name>
 *
 * @param name      Container name
 * @param password  Encryption password
 * @return 0 on success, -1 on failure
 */
int container_open(const char *name, const char *password);

/*
 * Close (unmount) a hidden container.
 *
 * Steps:
 *  1. Unmount filesystem
 *  2. cryptsetup close
 *  3. Wipe mount point directory
 *
 * @param name  Container name
 * @return 0 on success, -1 on failure
 */
int container_close(const char *name);

/*
 * Destroy a container permanently.
 * Overwrites vault and header files with random data, then deletes them.
 *
 * @param name      Container name
 * @param password  Password (required for confirmation)
 * @return 0 on success, -1 on failure
 */
int container_destroy(const char *name, const char *password);

/*
 * List all containers and their status.
 *
 * @param containers  Output array (must hold CONTAINER_MAX_ACTIVE entries)
 * @param count       Output: number of containers found
 * @return 0 on success, -1 on failure
 */
int container_list(ContainerInfo *containers, int *count);

/*
 * Get info about a specific container.
 *
 * @param name  Container name
 * @param info  Output: ContainerInfo
 * @return 0 on success, -1 on failure
 */
int container_get_info(const char *name, ContainerInfo *info);

/*
 * Close ALL open containers.
 * Used during shutdown or emergency wipe.
 */
void container_close_all(void);

#endif /* SECUREZ_HIDDEN_CONTAINER_H */
