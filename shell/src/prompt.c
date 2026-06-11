/*
 * SecureZ+ OS — SecureZ Shell
 * prompt.c — Themed prompt renderer
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* ANSI color codes */
#define C_RESET   "\001\033[0m\002"
#define C_BOLD    "\001\033[1m\002"
#define C_DIM     "\001\033[2m\002"
#define C_RED     "\001\033[31m\002"
#define C_GREEN   "\001\033[32m\002"
#define C_YELLOW  "\001\033[33m\002"
#define C_BLUE    "\001\033[34m\002"
#define C_CYAN    "\001\033[36m\002"
#define C_WHITE   "\001\033[37m\002"
#define C_BRED    "\001\033[1;31m\002"
#define C_BGREEN  "\001\033[1;32m\002"
#define C_BYELLOW "\001\033[1;33m\002"
#define C_BCYAN   "\001\033[1;36m\002"

/* ── Environment detection ───────────────────────────────────── */

static int detect_git_branch(char *branch, size_t len)
{
    /* Check for .git/HEAD in current or parent directories */
    char path[1024];
    char cwd[1024];

    if (!getcwd(cwd, sizeof(cwd))) return 0;

    while (1) {
        snprintf(path, sizeof(path), "%s/.git/HEAD", cwd);

        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            if (fgets(line, sizeof(line), f)) {
                fclose(f);

                /* Parse "ref: refs/heads/<branch>" */
                const char *prefix = "ref: refs/heads/";
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    const char *br = line + strlen(prefix);
                    size_t br_len = strlen(br);
                    if (br_len > 0 && br[br_len - 1] == '\n') br_len--;
                    if (br_len >= len) br_len = len - 1;
                    memcpy(branch, br, br_len);
                    branch[br_len] = '\0';
                    return 1;
                }

                /* Detached HEAD — use short hash */
                size_t hash_len = strlen(line);
                if (hash_len > 8) hash_len = 7;
                if (line[hash_len - 1] == '\n') hash_len--;
                memcpy(branch, line, hash_len);
                branch[hash_len] = '\0';
                return 1;
            }
            fclose(f);
        }

        /* Go up one directory */
        char *last_slash = strrchr(cwd, '/');
        if (!last_slash || last_slash == cwd) break;
        *last_slash = '\0';
    }

    return 0;
}

static int detect_tor(void)
{
    /* Check if Tor transparent proxy port (9040) is listening */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9040);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    return (result == 0) ? 1 : 0;
}

static int detect_vpn(void)
{
    /* Check for common VPN interfaces */
    return (access("/sys/class/net/wg0", F_OK) == 0 ||    /* WireGuard */
            access("/sys/class/net/tun0", F_OK) == 0 ||    /* OpenVPN */
            access("/sys/class/net/nordlynx", F_OK) == 0); /* NordVPN */
}

void detect_environment(ShellState *state)
{
    /* Update CWD */
    getcwd(state->cwd, sizeof(state->cwd));

    /* Detect secure session */
    const char *env = getenv("SECUREZ_SESSION");
    state->in_secure_session = (env && strcmp(env, "1") == 0);

    /* Detect git branch */
    state->git_branch[0] = '\0';
    detect_git_branch(state->git_branch, sizeof(state->git_branch));

    /* Detect Tor and VPN (cached — check less frequently) */
    static int check_counter = 0;
    if (check_counter % 10 == 0) {
        state->tor_active = detect_tor();
        state->vpn_active = detect_vpn();
    }
    check_counter++;
}

/* ── Prompt rendering ────────────────────────────────────────── */

/*
 * Normal prompt:
 *   ┌──[🛡️ SecureZ+]─[user@host]─[~/path]─[git:main]─[TOR]
 *   └──╼ $
 *
 * Root prompt (red):
 *   ┌──[🛡️ SecureZ+]─[root@host]─[/path]
 *   └──╼ #
 *
 * Secure session (yellow lock):
 *   ┌──[🔒 SECURE]─[user@session]─[~/path]
 *   └──╼ $
 */

static char *shorten_path(const char *cwd, const char *home)
{
    static char shortened[512];

    if (home && strncmp(cwd, home, strlen(home)) == 0) {
        snprintf(shortened, sizeof(shortened), "~%s", cwd + strlen(home));
    } else {
        strncpy(shortened, cwd, sizeof(shortened) - 1);
    }

    return shortened;
}

char *render_prompt(ShellState *state)
{
    static char prompt[2048];
    char *p = prompt;
    size_t remaining = sizeof(prompt);
    int n;

    /* Line 1 */
    if (state->in_secure_session) {
        /* Secure session prompt — yellow */
        n = snprintf(p, remaining,
                     C_BYELLOW "┌──[🔒 SECURE]" C_RESET
                     C_DIM "─" C_RESET
                     C_BYELLOW "[" C_RESET "%s@session" C_BYELLOW "]" C_RESET
                     C_DIM "─" C_RESET
                     C_CYAN "[%s]" C_RESET,
                     state->user,
                     shorten_path(state->cwd, state->home));
    } else if (state->is_root) {
        /* Root prompt — red */
        n = snprintf(p, remaining,
                     C_BRED "┌──[🛡️ SecureZ+]" C_RESET
                     C_DIM "─" C_RESET
                     C_BRED "[" C_RESET C_RED "root" C_RESET "@%s" C_BRED "]" C_RESET
                     C_DIM "─" C_RESET
                     C_RED "[%s]" C_RESET,
                     state->hostname,
                     shorten_path(state->cwd, state->home));
    } else {
        /* Normal prompt — cyan */
        n = snprintf(p, remaining,
                     C_BCYAN "┌──[🛡️ SecureZ+]" C_RESET
                     C_DIM "─" C_RESET
                     C_BGREEN "[" C_RESET "%s@%s" C_BGREEN "]" C_RESET
                     C_DIM "─" C_RESET
                     C_CYAN "[%s]" C_RESET,
                     state->user, state->hostname,
                     shorten_path(state->cwd, state->home));
    }
    p += n; remaining -= n;

    /* Git branch indicator */
    if (state->git_branch[0] != '\0') {
        n = snprintf(p, remaining,
                     C_DIM "─" C_RESET C_BLUE "[%s]" C_RESET,
                     state->git_branch);
        p += n; remaining -= n;
    }

    /* Tor indicator */
    if (state->tor_active) {
        n = snprintf(p, remaining,
                     C_DIM "─" C_RESET C_YELLOW "[TOR]" C_RESET);
        p += n; remaining -= n;
    }

    /* VPN indicator */
    if (state->vpn_active) {
        n = snprintf(p, remaining,
                     C_DIM "─" C_RESET C_GREEN "[VPN]" C_RESET);
        p += n; remaining -= n;
    }

    /* Line 2 */
    if (state->in_secure_session) {
        snprintf(p, remaining,
                 "\n" C_BYELLOW "└──╼" C_RESET " $ ");
    } else if (state->is_root) {
        snprintf(p, remaining,
                 "\n" C_BRED "└──╼" C_RESET " # ");
    } else {
        snprintf(p, remaining,
                 "\n" C_BCYAN "└──╼" C_RESET " $ ");
    }

    return strdup(prompt);
}
