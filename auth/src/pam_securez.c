/*
 * SecureZ+ OS — Authentication
 * pam_securez.c — PAM module for master key authentication
 *
 * Replaces default password auth with Argon2id (via CrypticEngine keystore).
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sodium.h>

#define MASTER_HASH_PATH "/etc/securez/master.key"

/* ── Helper: Verify password against stored Argon2id hash ────── */

static int verify_password(const char *password)
{
    FILE *f = fopen(MASTER_HASH_PATH, "r");
    if (!f) return PAM_AUTHINFO_UNAVAIL;

    char stored_hash[256];
    if (fgets(stored_hash, sizeof(stored_hash), f) == NULL) {
        fclose(f);
        return PAM_AUTHINFO_UNAVAIL;
    }
    fclose(f);

    /* Strip newline */
    size_t len = strlen(stored_hash);
    if (len > 0 && stored_hash[len - 1] == '\n') {
        stored_hash[len - 1] = '\0';
    }

    /* Verify using libsodium's constant-time comparison */
    if (crypto_pwhash_str_verify(stored_hash, password, strlen(password)) != 0) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

/* ── PAM Authentication ──────────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    if (sodium_init() < 0) {
        syslog(LOG_ERR, "pam_securez: libsodium init failed");
        return PAM_SYSTEM_ERR;
    }

    /* Get username */
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        syslog(LOG_ERR, "pam_securez: cannot determine user");
        return PAM_USER_UNKNOWN;
    }

    /* Get password */
    const char *password = NULL;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, "🔑 Master Key: ") != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_securez: cannot get password");
        return PAM_AUTH_ERR;
    }

    /* Verify against CrypticEngine master key */
    int result = verify_password(password);

    if (result == PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_securez: user '%s' authenticated", user);
    } else if (result == PAM_AUTH_ERR) {
        syslog(LOG_WARNING, "pam_securez: FAILED authentication for '%s'", user);
    } else {
        syslog(LOG_ERR, "pam_securez: master key not configured");
    }

    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* ── PAM Password Change ─────────────────────────────────────── */

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    if (sodium_init() < 0) return PAM_SYSTEM_ERR;

    if (flags & PAM_PRELIM_CHECK) return PAM_SUCCESS;

    /* Get old and new passwords */
    const char *old_pw = NULL, *new_pw = NULL;

    pam_get_authtok(pamh, PAM_OLDAUTHTOK, &old_pw, "Current master key: ");
    if (!old_pw || verify_password(old_pw) != PAM_SUCCESS) {
        return PAM_AUTH_ERR;
    }

    pam_get_authtok(pamh, PAM_AUTHTOK, &new_pw, "New master key (min 16 chars): ");
    if (!new_pw || strlen(new_pw) < 16) {
        pam_error(pamh, "Master key must be at least 16 characters");
        return PAM_AUTHTOK_ERR;
    }

    /* Hash and store new master key */
    char hash_str[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash_str, new_pw, strlen(new_pw),
                          crypto_pwhash_OPSLIMIT_SENSITIVE,
                          crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        return PAM_SYSTEM_ERR;
    }

    FILE *f = fopen(MASTER_HASH_PATH, "w");
    if (!f) return PAM_SYSTEM_ERR;
    fprintf(f, "%s\n", hash_str);
    fclose(f);
    chmod(MASTER_HASH_PATH, 0600);

    syslog(LOG_INFO, "pam_securez: master key changed");
    return PAM_SUCCESS;
}
