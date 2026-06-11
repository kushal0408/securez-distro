/*
 * SecureZ+ OS — SecureZ Shell
 * session_cmds.c — Secure session and .nxe execution commands
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define CRYPTICD_SOCKET "/run/crypticd.sock"

/* Reuse from crypto_cmds.c */
extern char *prompt_password(const char *prompt);

static char *send_cmd(const char *json)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, CRYPTICD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return NULL;
    }

    write(sock, json, strlen(json));
    shutdown(sock, SHUT_WR);

    char buf[4096];
    ssize_t n = read(sock, buf, sizeof(buf) - 1);
    close(sock);

    if (n <= 0) return NULL;
    buf[n] = '\0';
    return strdup(buf);
}

/* ── securesession command ───────────────────────────────────── */

int cmd_securesession(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        printf("Usage: securesession <start|end|status>\n\n");
        printf("  start   — Start an isolated secure session\n");
        printf("  end     — End a session and wipe all RAM data\n");
        printf("  status  — Show active sessions\n");
        return 1;
    }

    if (strcmp(argv[1], "start") == 0) {
        printf("\n  \033[1;33m🔒 Starting Secure Session\033[0m\n\n");
        printf("  This will create an isolated environment with:\n");
        printf("    • Separate process namespace (PID isolation)\n");
        printf("    • Private filesystem view (mount namespace)\n");
        printf("    • RAM-only tmpfs (data never touches disk)\n");
        printf("    • Optional network isolation\n");
        printf("    • 512MB memory limit (cgroups v2)\n\n");
        printf("  \033[1mAll data will be DESTROYED when the session ends.\033[0m\n\n");
        printf("  Continue? [y/N]: ");

        char confirm[8];
        if (!fgets(confirm, sizeof(confirm), stdin) || confirm[0] != 'y') {
            printf("  Cancelled.\n");
            return 0;
        }

        char *resp = send_cmd("{\"cmd\":\"session_start\"}");
        if (resp) {
            if (strstr(resp, "\"ok\"")) {
                printf("\n  \033[32m✅ Secure session started!\033[0m\n");
                printf("  \033[2mAll files in tmpfs are RAM-only.\033[0m\n");
                printf("  \033[2mType 'securesession end' to destroy.\033[0m\n\n");
            } else {
                printf("  \033[31m❌ Failed to start session (need root?)\033[0m\n");
            }
            free(resp);
        } else {
            fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
            return 1;
        }
    }
    else if (strcmp(argv[1], "end") == 0) {
        int id = 1;  /* Default to session 1 */
        if (argc > 2) id = atoi(argv[2]);

        printf("  \033[1;33m⚠ Ending session %d — ALL DATA WILL BE WIPED\033[0m\n", id);
        printf("  Confirm? [y/N]: ");

        char confirm[8];
        if (!fgets(confirm, sizeof(confirm), stdin) || confirm[0] != 'y') {
            printf("  Cancelled.\n");
            return 0;
        }

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "{\"cmd\":\"session_end\",\"id\":%d}", id);

        char *resp = send_cmd(cmd);
        if (resp) {
            if (strstr(resp, "\"ok\""))
                printf("  \033[32m✅ Session destroyed — RAM wiped\033[0m\n");
            else
                printf("  \033[31m❌ Session not found\033[0m\n");
            free(resp);
        }
    }
    else if (strcmp(argv[1], "status") == 0) {
        char *resp = send_cmd("{\"cmd\":\"session_list\"}");
        if (resp) {
            /* Parse and display nicely */
            char *count_str = strstr(resp, "\"count\":");
            int count = count_str ? atoi(count_str + 8) : 0;

            if (count == 0) {
                printf("  No active secure sessions.\n");
            } else {
                printf("\n  \033[1m🔒 Active Secure Sessions: %d\033[0m\n\n", count);
                printf("  %-6s %-20s %-10s\n", "ID", "Name", "PID");
                printf("  %-6s %-20s %-10s\n", "──", "────────────────────", "─────");

                /* Basic parsing of the sessions array */
                char *s = strstr(resp, "\"sessions\":[");
                if (s) {
                    char *p = s;
                    while ((p = strstr(p, "\"id\":")) != NULL) {
                        int id = atoi(p + 5);
                        char name[64] = "—";
                        int pid = 0;

                        char *n = strstr(p, "\"name\":\"");
                        if (n) {
                            n += 8;
                            char *end = strchr(n, '"');
                            if (end) {
                                size_t len = (size_t)(end - n);
                                if (len >= sizeof(name)) len = sizeof(name) - 1;
                                memcpy(name, n, len);
                                name[len] = '\0';
                            }
                        }

                        char *pi = strstr(p, "\"pid\":");
                        if (pi) pid = atoi(pi + 6);

                        printf("  %-6d %-20s %-10d\n", id, name, pid);
                        p++;
                    }
                }
                printf("\n");
            }
            free(resp);
        } else {
            fprintf(stderr, "  ⚠ CrypticEngine daemon not running.\n");
            return 1;
        }
    }
    else {
        fprintf(stderr, "securesession: unknown subcommand '%s'\n", argv[1]);
        return 1;
    }

    return 0;
}

/* ── run (execute .nxe binary) ───────────────────────────────── */

int cmd_run_nxe(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        fprintf(stderr, "Usage: run <app.nxe> [args...]\n");
        return 1;
    }

    const char *nxe_path = argv[1];

    /* Check file exists */
    if (access(nxe_path, R_OK) != 0) {
        fprintf(stderr, "  \033[31m❌ Cannot read: %s\033[0m\n", nxe_path);
        return 1;
    }

    /* Check .nxe extension */
    const char *ext = strrchr(nxe_path, '.');
    if (!ext || strcmp(ext, ".nxe") != 0) {
        fprintf(stderr, "  ⚠ File doesn't have .nxe extension. Continue? [y/N]: ");
        char confirm[8];
        if (!fgets(confirm, sizeof(confirm), stdin) || confirm[0] != 'y') {
            return 0;
        }
    }

    printf("  \033[36m🚀 Loading .nxe binary: %s\033[0m\n", nxe_path);

    /* Ask for password if needed */
    char *pw = prompt_password("🔑 Password (or Enter if not encrypted): ");

    /* Build the load command for the daemon */
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "{\"cmd\":\"nxe_load\",\"path\":\"%s\"%s%s%s}",
             nxe_path,
             (pw && strlen(pw) > 0) ? ",\"password\":\"" : "",
             (pw && strlen(pw) > 0) ? pw : "",
             (pw && strlen(pw) > 0) ? "\"" : "");

    char *resp = send_cmd(cmd);
    if (resp) {
        if (strstr(resp, "\"ok\""))
            printf("  \033[32m✅ .nxe loaded and executing\033[0m\n");
        else
            printf("  \033[31m❌ .nxe load failed\033[0m\n");
        free(resp);
    } else {
        /* Direct execution fallback — fork and exec nxe-loader */
        pid_t pid = fork();
        if (pid == 0) {
            /* Build argv for nxe-loader */
            execl("/usr/bin/nxe-loader", "nxe-loader", nxe_path, NULL);
            perror("nxe-loader");
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
    }

    return 0;
}
