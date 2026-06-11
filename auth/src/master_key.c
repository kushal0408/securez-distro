/*
 * SecureZ+ OS — Master Key CLI Utility
 * master_key.c — Setup, verify, and change the master key
 *
 * Used by the first-boot wizard and by administrators.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <sodium.h>

#define MASTER_HASH_PATH "/etc/securez/master.key"

static char *read_password_stdin(void)
{
    static char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return NULL;
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
    return buf;
}

static char *prompt_password(const char *prompt)
{
    static char password[256];
    fprintf(stderr, "%s", prompt);

    struct termios old, new;
    if (tcgetattr(STDIN_FILENO, &old) == 0) {
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new);
    }

    if (fgets(password, sizeof(password), stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        fprintf(stderr, "\n");
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') password[len - 1] = '\0';
    return password;
}

static int do_setup(int from_stdin)
{
    char *password;

    if (from_stdin) {
        password = read_password_stdin();
    } else {
        password = prompt_password("🔑 Create Master Key (min 16 chars): ");
    }

    if (!password || strlen(password) < 16) {
        fprintf(stderr, "Error: Master key must be at least 16 characters\n");
        return 1;
    }

    if (!from_stdin) {
        char *confirm = prompt_password("🔑 Confirm Master Key: ");
        if (!confirm || strcmp(password, confirm) != 0) {
            fprintf(stderr, "Error: Keys don't match\n");
            return 1;
        }
    }

    /* Check if already exists */
    if (access(MASTER_HASH_PATH, F_OK) == 0) {
        fprintf(stderr, "Error: Master key already configured.\n");
        fprintf(stderr, "Use --change to update it.\n");
        return 1;
    }

    /* Hash with Argon2id (expensive — intentional) */
    fprintf(stderr, "Hashing master key (this takes a moment)...\n");

    char hash_str[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash_str, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_SENSITIVE,
                          crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        fprintf(stderr, "Error: Hashing failed (out of memory?)\n");
        return 1;
    }

    /* Ensure directory exists */
    mkdir("/etc/securez", 0700);

    FILE *f = fopen(MASTER_HASH_PATH, "w");
    if (!f) {
        perror("Cannot write master key file");
        return 1;
    }
    fprintf(f, "%s\n", hash_str);
    fclose(f);
    chmod(MASTER_HASH_PATH, 0600);

    fprintf(stderr, "✅ Master key configured\n");
    return 0;
}

static int do_verify(void)
{
    char *password = prompt_password("🔑 Enter Master Key: ");
    if (!password) return 1;

    FILE *f = fopen(MASTER_HASH_PATH, "r");
    if (!f) {
        fprintf(stderr, "Error: No master key configured\n");
        return 1;
    }

    char stored[crypto_pwhash_STRBYTES];
    if (fgets(stored, sizeof(stored), f) == NULL) {
        fclose(f);
        return 1;
    }
    fclose(f);

    size_t len = strlen(stored);
    if (len > 0 && stored[len - 1] == '\n') stored[len - 1] = '\0';

    if (crypto_pwhash_str_verify(stored, password, strlen(password)) == 0) {
        fprintf(stderr, "✅ Master key verified\n");
        return 0;
    } else {
        fprintf(stderr, "❌ Invalid master key\n");
        return 1;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "SecureZ+ Master Key Utility\n\n"
        "Usage: %s <command>\n\n"
        "Commands:\n"
        "  --setup     Set up a new master key (interactive)\n"
        "  --verify    Verify the master key\n"
        "  --change    Change the master key\n"
        "  --status    Check if master key is configured\n\n"
        "Pipe mode (for scripting):\n"
        "  echo 'password' | %s --setup\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--setup") == 0) {
        int from_stdin = !isatty(STDIN_FILENO);
        return do_setup(from_stdin);
    }
    else if (strcmp(argv[1], "--verify") == 0) {
        return do_verify();
    }
    else if (strcmp(argv[1], "--change") == 0) {
        char *old = prompt_password("Current Master Key: ");
        if (!old) return 1;

        FILE *f = fopen(MASTER_HASH_PATH, "r");
        if (!f) return 1;
        char stored[crypto_pwhash_STRBYTES];
        fgets(stored, sizeof(stored), f);
        fclose(f);
        size_t slen = strlen(stored);
        if (slen > 0 && stored[slen-1] == '\n') stored[slen-1] = '\0';

        if (crypto_pwhash_str_verify(stored, old, strlen(old)) != 0) {
            fprintf(stderr, "❌ Wrong current master key\n");
            return 1;
        }

        unlink(MASTER_HASH_PATH);
        return do_setup(0);
    }
    else if (strcmp(argv[1], "--status") == 0) {
        if (access(MASTER_HASH_PATH, F_OK) == 0) {
            printf("✅ Master key is configured\n");
            return 0;
        } else {
            printf("❌ Master key not configured\n");
            return 1;
        }
    }
    else {
        usage(argv[0]);
        return 1;
    }
}
