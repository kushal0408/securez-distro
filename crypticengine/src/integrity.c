/*
 * SecureZ+ OS — CrypticEngine
 * integrity.c — File integrity monitoring with inotify
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "integrity.h"
#include "crypto_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <syslog.h>
#include <signal.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN    (1024 * (EVENT_SIZE + 256))

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* ── Internal helpers ────────────────────────────────────────── */

static int hash_and_store(FILE *db, const char *path)
{
    uint8_t hash[INTEGRITY_HASH_LEN];
    if (crypto_hash_file(hash, path) != 0) return -1;

    char hex[INTEGRITY_HASH_LEN * 2 + 1];
    crypto_bin_to_hex(hex, hash, INTEGRITY_HASH_LEN);

    fprintf(db, "%s  %s\n", hex, path);
    return 0;
}

static int scan_directory_recursive(FILE *db, const char *dir_path,
                                     int *file_count)
{
    DIR *dir = opendir(dir_path);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(db, full_path, file_count);
        } else if (S_ISREG(st.st_mode)) {
            if (hash_and_store(db, full_path) == 0) {
                (*file_count)++;
            }
        }
    }

    closedir(dir);
    return 0;
}

/* ── Public API ──────────────────────────────────────────────── */

static const char *watched_dirs[] = {
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/etc", "/boot",
    NULL
};

int integrity_init_database(void)
{
    FILE *db = fopen(INTEGRITY_DB_PATH, "w");
    if (!db) {
        perror("[Integrity] Cannot create database");
        return -1;
    }

    fprintf(db, "# SecureZ+ Integrity Database\n");
    fprintf(db, "# Format: blake2b_hash  filepath\n");

    int file_count = 0;

    for (int i = 0; watched_dirs[i] != NULL; i++) {
        fprintf(stderr, "[Integrity] Scanning %s...\n", watched_dirs[i]);
        scan_directory_recursive(db, watched_dirs[i], &file_count);
    }

    fclose(db);

    fprintf(stderr, "[Integrity] ✅ Database created: %d files hashed\n", file_count);
    return 0;
}

int integrity_check_all(IntegrityResult *results, int max_results, int *count)
{
    if (!results || !count) return -1;
    *count = 0;

    FILE *db = fopen(INTEGRITY_DB_PATH, "r");
    if (!db) {
        fprintf(stderr, "[Integrity] No database found — run --init first\n");
        return -1;
    }

    char line[1024];
    int mismatches = 0;

    while (fgets(line, sizeof(line), db) && *count < max_results) {
        /* Skip comments */
        if (line[0] == '#' || line[0] == '\n') continue;

        /* Parse: "hex_hash  filepath\n" */
        char stored_hex[INTEGRITY_HASH_LEN * 2 + 1];
        char filepath[512];

        if (sscanf(line, "%64s %511s", stored_hex, filepath) != 2) continue;

        IntegrityResult *r = &results[*count];
        strncpy(r->path, filepath, sizeof(r->path) - 1);

        /* Convert stored hex to binary */
        size_t bin_len;
        if (sodium_hex2bin(r->expected_hash, INTEGRITY_HASH_LEN,
                           stored_hex, strlen(stored_hex),
                           NULL, &bin_len, NULL) != 0) continue;

        /* Check if file still exists */
        if (access(filepath, F_OK) != 0) {
            r->status = INTEGRITY_MISSING;
            (*count)++;
            mismatches++;
            syslog(LOG_CRIT, "[SecureZ+ INTEGRITY] MISSING: %s", filepath);
            continue;
        }

        /* Compute current hash */
        if (crypto_hash_file(r->actual_hash, filepath) != 0) {
            r->status = INTEGRITY_ERROR;
            (*count)++;
            continue;
        }

        /* Compare */
        if (memcmp(r->expected_hash, r->actual_hash, INTEGRITY_HASH_LEN) != 0) {
            r->status = INTEGRITY_MODIFIED;
            (*count)++;
            mismatches++;
            syslog(LOG_CRIT, "[SecureZ+ INTEGRITY] MODIFIED: %s", filepath);
        } else {
            r->status = INTEGRITY_OK;
            /* Don't add OK results to save space */
        }
    }

    fclose(db);
    return mismatches;
}

int integrity_check_file(const char *path, IntegrityResult *result)
{
    if (!path || !result) return -1;

    strncpy(result->path, path, sizeof(result->path) - 1);

    if (access(path, F_OK) != 0) {
        result->status = INTEGRITY_MISSING;
        return 1;
    }

    /* Compute current hash */
    if (crypto_hash_file(result->actual_hash, path) != 0) {
        result->status = INTEGRITY_ERROR;
        return -1;
    }

    /* Look up expected hash in database */
    FILE *db = fopen(INTEGRITY_DB_PATH, "r");
    if (!db) return -1;

    char line[1024];
    int found = 0;

    while (fgets(line, sizeof(line), db)) {
        if (line[0] == '#') continue;

        char stored_hex[INTEGRITY_HASH_LEN * 2 + 1];
        char filepath[512];

        if (sscanf(line, "%64s %511s", stored_hex, filepath) != 2) continue;

        if (strcmp(filepath, path) == 0) {
            size_t bin_len;
            sodium_hex2bin(result->expected_hash, INTEGRITY_HASH_LEN,
                           stored_hex, strlen(stored_hex),
                           NULL, &bin_len, NULL);
            found = 1;
            break;
        }
    }
    fclose(db);

    if (!found) {
        result->status = INTEGRITY_NEW;
        return 1;
    }

    if (memcmp(result->expected_hash, result->actual_hash, INTEGRITY_HASH_LEN) == 0) {
        result->status = INTEGRITY_OK;
        return 0;
    } else {
        result->status = INTEGRITY_MODIFIED;
        return 1;
    }
}

int integrity_update_file(const char *path)
{
    (void)path;
    /* TODO: Update single entry in database */
    fprintf(stderr, "[Integrity] Single file update: re-run --init for now\n");
    return -1;
}

void integrity_monitor_daemon(void (*callback)(const char *path, IntegrityStatus status))
{
    openlog("securez-integrity", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Integrity monitor started");

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        syslog(LOG_ERR, "inotify_init failed: %s", strerror(errno));
        return;
    }

    /* Watch all critical directories */
    for (int i = 0; watched_dirs[i] != NULL; i++) {
        int wd = inotify_add_watch(inotify_fd, watched_dirs[i],
                                   IN_MODIFY | IN_CREATE | IN_DELETE |
                                   IN_MOVED_FROM | IN_MOVED_TO);
        if (wd < 0) {
            syslog(LOG_WARNING, "Cannot watch %s: %s",
                   watched_dirs[i], strerror(errno));
        } else {
            syslog(LOG_INFO, "Watching: %s", watched_dirs[i]);
        }
    }

    char buf[BUF_LEN];

    while (running) {
        int length = read(inotify_fd, buf, BUF_LEN);
        if (length < 0) {
            if (errno == EINTR) continue;
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len > 0) {
                IntegrityStatus status;

                if (event->mask & IN_DELETE) {
                    status = INTEGRITY_MISSING;
                    syslog(LOG_CRIT,
                           "[TAMPER] File deleted: %s", event->name);
                } else if (event->mask & (IN_MODIFY | IN_CREATE)) {
                    status = INTEGRITY_MODIFIED;
                    syslog(LOG_CRIT,
                           "[TAMPER] File modified: %s", event->name);
                } else {
                    status = INTEGRITY_MODIFIED;
                    syslog(LOG_WARNING,
                           "[TAMPER] File moved: %s", event->name);
                }

                if (callback) {
                    callback(event->name, status);
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    close(inotify_fd);
    closelog();
}

/* ── CLI entry point ─────────────────────────────────────────── */

#ifdef INTEGRITY_MAIN

#include <sodium.h>

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--init | --check | --daemon]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--init") == 0) {
        return integrity_init_database() == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "--check") == 0) {
        IntegrityResult results[1024];
        int count = 0;
        int mismatches = integrity_check_all(results, 1024, &count);

        if (mismatches == 0) {
            printf("✅ All files verified — no tampering detected\n");
            return 0;
        }

        printf("⚠ %d integrity issue(s) found:\n\n", count);
        for (int i = 0; i < count; i++) {
            const char *status_str;
            switch (results[i].status) {
                case INTEGRITY_MODIFIED: status_str = "MODIFIED"; break;
                case INTEGRITY_MISSING:  status_str = "MISSING";  break;
                case INTEGRITY_NEW:      status_str = "NEW";      break;
                default:                 status_str = "ERROR";    break;
            }
            printf("  [%s] %s\n", status_str, results[i].path);
        }
        return 1;
    }

    if (strcmp(argv[1], "--daemon") == 0) {
        printf("Starting integrity monitor daemon...\n");
        integrity_monitor_daemon(NULL);
        return 0;
    }

    fprintf(stderr, "Unknown option: %s\n", argv[1]);
    return 1;
}

#endif /* INTEGRITY_MAIN */
