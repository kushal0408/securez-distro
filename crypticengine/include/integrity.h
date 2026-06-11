/*
 * SecureZ+ OS — CrypticEngine
 * integrity.h — File integrity monitoring
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_INTEGRITY_H
#define SECUREZ_INTEGRITY_H

#include <stddef.h>
#include <stdint.h>

#define INTEGRITY_DB_PATH   "/var/lib/securez/integrity.db"
#define INTEGRITY_HASH_LEN  32  /* BLAKE2b-256 */

typedef enum {
    INTEGRITY_OK = 0,
    INTEGRITY_MODIFIED,
    INTEGRITY_MISSING,
    INTEGRITY_NEW,
    INTEGRITY_ERROR
} IntegrityStatus;

typedef struct {
    char             path[512];
    uint8_t          expected_hash[INTEGRITY_HASH_LEN];
    uint8_t          actual_hash[INTEGRITY_HASH_LEN];
    IntegrityStatus  status;
} IntegrityResult;

/*
 * Build the initial integrity database.
 * Hashes all files in the watched directories and stores in the database.
 *
 * Watched directories:
 *  /bin, /sbin, /usr/bin, /usr/sbin, /etc, /boot
 *
 * @return 0 on success, -1 on failure
 */
int integrity_init_database(void);

/*
 * Check all files against the integrity database.
 *
 * @param results   Output array of mismatches
 * @param max_results  Maximum results to return
 * @param count     Output: number of mismatches found
 * @return 0 if all OK, positive number = count of mismatches, -1 on error
 */
int integrity_check_all(IntegrityResult *results, int max_results, int *count);

/*
 * Check a single file against the database.
 *
 * @param path    File path to check
 * @param result  Output: integrity result
 * @return 0 if OK, 1 if mismatch, -1 on error
 */
int integrity_check_file(const char *path, IntegrityResult *result);

/*
 * Update the hash for a single file in the database.
 * Use after legitimate system updates.
 *
 * @param path  File path to update
 * @return 0 on success, -1 on failure
 */
int integrity_update_file(const char *path);

/*
 * Start continuous monitoring daemon (uses inotify).
 * Watches for modifications in real-time and logs alerts.
 * This function does not return (runs forever).
 *
 * @param callback  Function called on tamper detection (NULL for default logging)
 */
void integrity_monitor_daemon(void (*callback)(const char *path, IntegrityStatus status));

#endif /* SECUREZ_INTEGRITY_H */
