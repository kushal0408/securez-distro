/*
 * SecureZ+ OS — SecureZ Shell
 * crypto_cmds.c — Security commands (talk to CrypticEngine daemon)
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "commands.h"
#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CRYPTICD_SOCKET "/run/crypticd.sock"

/* ── Daemon communication ────────────────────────────────────── */

static char *send_daemon_cmd(const char *json_cmd)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CRYPTICD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return NULL;
    }

    write(sock, json_cmd, strlen(json_cmd));
    shutdown(sock, SHUT_WR);

    char buf[4096];
    ssize_t n = read(sock, buf, sizeof(buf) - 1);
    close(sock);

    if (n <= 0) return NULL;
    buf[n] = '\0';
    return strdup(buf);
}

/* ── Password prompt (no echo) ───────────────────────────────── */

char *prompt_password(const char *prompt)
{
    static char password[256];

    fprintf(stderr, "%s", prompt);

    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    if (fgets(password, sizeof(password), stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        fprintf(stderr, "\n");
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    /* Strip newline */
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') password[len - 1] = '\0';

    return password;
}

/* ── resolve to absolute path ────────────────────────────────── */

static char *resolve_path(const char *path, ShellState *state)
{
    static char resolved[1024];
    if (path[0] == '/') {
        strncpy(resolved, path, sizeof(resolved) - 1);
    } else {
        snprintf(resolved, sizeof(resolved), "%s/%s", state->cwd, path);
    }
    return resolved;
}

/* ── Commands ────────────────────────────────────────────────── */

int cmd_encrypt(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: encrypt <file>\n");
        return 1;
    }

    char *pw = prompt_password("🔑 Encryption password: ");
    if (!pw || strlen(pw) == 0) {
        fprintf(stderr, "Cancelled.\n");
        return 1;
    }

    char *confirm = prompt_password("🔑 Confirm password: ");
    if (!confirm || strcmp(pw, confirm) != 0) {
        fprintf(stderr, "Passwords don't match.\n");
        return 1;
    }

    char *path = resolve_path(argv[1], state);

    /* Try daemon first */
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "{\"cmd\":\"encrypt\",\"path\":\"%s\",\"password\":\"%s\"}",
             path, pw);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\"")) {
            printf("  \033[32m✅ Encrypted: %s → %s.szenc\033[0m\n", argv[1], argv[1]);
        } else {
            printf("  \033[31m❌ Encryption failed\033[0m\n");
        }
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running. "
                        "Start with: sudo systemctl start crypticd\n");
        return 1;
    }

    return 0;
}

int cmd_decrypt(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: decrypt <file.szenc>\n");
        return 1;
    }

    char *pw = prompt_password("🔑 Decryption password: ");
    if (!pw) return 1;

    char *path = resolve_path(argv[1], state);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "{\"cmd\":\"decrypt\",\"path\":\"%s\",\"password\":\"%s\"}",
             path, pw);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\"")) {
            printf("  \033[32m✅ Decrypted successfully\033[0m\n");
        } else {
            printf("  \033[31m❌ Decryption failed — wrong password?\033[0m\n");
        }
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
        return 1;
    }

    return 0;
}

int cmd_lock(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: lock <folder>\n");
        return 1;
    }

    char *path = resolve_path(argv[1], state);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"lock\",\"path\":\"%s\"}", path);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\""))
            printf("  \033[32m🔒 Folder locked: %s\033[0m\n", argv[1]);
        else
            printf("  \033[31m❌ Lock failed (is fscrypt set up?)\033[0m\n");
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
        return 1;
    }

    return 0;
}

int cmd_unlock(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: unlock <folder>\n");
        return 1;
    }

    char *pw = prompt_password("🔑 Folder password: ");
    if (!pw) return 1;

    char *path = resolve_path(argv[1], state);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "{\"cmd\":\"unlock\",\"path\":\"%s\",\"password\":\"%s\"}",
             path, pw);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\""))
            printf("  \033[32m🔓 Folder unlocked: %s\033[0m\n", argv[1]);
        else
            printf("  \033[31m❌ Unlock failed\033[0m\n");
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
        return 1;
    }

    return 0;
}

int cmd_hash(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: hash <file>\n");
        return 1;
    }

    char *path = resolve_path(argv[1], state);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"hash\",\"path\":\"%s\"}", path);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        /* Extract hash from response */
        char *hash_start = strstr(resp, "\"hash\":\"");
        if (hash_start) {
            hash_start += 8;
            char *hash_end = strchr(hash_start, '"');
            if (hash_end) {
                *hash_end = '\0';
                printf("  BLAKE2b: %s\n", hash_start);
                printf("  File:    %s\n", argv[1]);
            }
        } else {
            printf("  \033[31m❌ Hash failed\033[0m\n");
        }
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
        return 1;
    }

    return 0;
}

int cmd_wipe(int argc, char **argv, ShellState *state)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: wipe <file>\n");
        return 1;
    }

    /* Confirmation */
    printf("  \033[1;31m⚠ PERMANENTLY delete '%s'?\033[0m\n", argv[1]);
    printf("  This overwrites 3x then unlinks. UNRECOVERABLE.\n");
    printf("  Type 'yes' to confirm: ");

    char confirm[16];
    if (!fgets(confirm, sizeof(confirm), stdin) ||
        strncmp(confirm, "yes", 3) != 0) {
        printf("  Cancelled.\n");
        return 0;
    }

    char *path = resolve_path(argv[1], state);

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"wipe\",\"path\":\"%s\"}", path);

    char *resp = send_daemon_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\""))
            printf("  \033[32m🗑️  Securely wiped: %s\033[0m\n", argv[1]);
        else
            printf("  \033[31m❌ Wipe failed\033[0m\n");
        free(resp);
    } else {
        fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
        return 1;
    }

    return 0;
}

int cmd_vault(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        fprintf(stderr, "Usage: vault <create|open|close|list> [args]\n");
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: vault create <name> <size_mb>\n");
            return 1;
        }

        char *pw = prompt_password("🔑 Vault password: ");
        if (!pw) return 1;
        char *confirm = prompt_password("🔑 Confirm password: ");
        if (!confirm || strcmp(pw, confirm) != 0) {
            fprintf(stderr, "Passwords don't match.\n");
            return 1;
        }

        char cmd[4096];
        snprintf(cmd, sizeof(cmd),
                 "{\"cmd\":\"container_create\",\"name\":\"%s\","
                 "\"size\":%s,\"password\":\"%s\"}",
                 argv[2], argv[3], pw);

        char *resp = send_daemon_cmd(cmd);
        if (resp) {
            if (strstr(resp, "\"ok\""))
                printf("  \033[32m✅ Vault '%s' created (%sMB)\033[0m\n",
                       argv[2], argv[3]);
            else
                printf("  \033[31m❌ Vault creation failed\033[0m\n");
            free(resp);
        }
    }
    else if (strcmp(argv[1], "open") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: vault open <name>\n");
            return 1;
        }

        char *pw = prompt_password("🔑 Vault password: ");
        if (!pw) return 1;

        char cmd[4096];
        snprintf(cmd, sizeof(cmd),
                 "{\"cmd\":\"container_open\",\"name\":\"%s\","
                 "\"password\":\"%s\"}", argv[2], pw);

        char *resp = send_daemon_cmd(cmd);
        if (resp) {
            if (strstr(resp, "\"ok\""))
                printf("  \033[32m🔓 Vault '%s' opened at /mnt/securez-vault/%s\033[0m\n",
                       argv[2], argv[2]);
            else
                printf("  \033[31m❌ Wrong password or vault not found\033[0m\n");
            free(resp);
        }
    }
    else if (strcmp(argv[1], "close") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: vault close <name>\n");
            return 1;
        }

        char cmd[4096];
        snprintf(cmd, sizeof(cmd),
                 "{\"cmd\":\"container_close\",\"name\":\"%s\"}", argv[2]);

        char *resp = send_daemon_cmd(cmd);
        if (resp) {
            if (strstr(resp, "\"ok\""))
                printf("  \033[32m🔒 Vault '%s' closed\033[0m\n", argv[2]);
            else
                printf("  \033[31m❌ Close failed\033[0m\n");
            free(resp);
        }
    }
    else if (strcmp(argv[1], "list") == 0) {
        char *resp = send_daemon_cmd("{\"cmd\":\"container_list\"}");
        if (resp) {
            printf("  \033[1mVaults:\033[0m\n%s\n", resp);
            free(resp);
        }
    }
    else {
        fprintf(stderr, "vault: unknown subcommand '%s'\n", argv[1]);
        return 1;
    }

    return 0;
}
