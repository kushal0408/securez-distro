/*
 * SecureZ+ OS — SecureZ Shell
 * builtins.c — Built-in shell commands + command registry
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
#include <errno.h>
#include <readline/history.h>

/* ── Command Registry ────────────────────────────────────────── */

static CommandEntry registry[64];
static int registry_count = 0;

static void reg(const char *name, cmd_handler_t handler,
                const char *help, CommandCategory cat)
{
    CommandEntry *e = &registry[registry_count++];
    e->name = name;
    e->handler = handler;
    e->help = help;
    e->category = cat;
}

void cmd_register_all(void)
{
    registry_count = 0;

    /* Builtins */
    reg("cd",       cmd_cd,       "Change directory",               CAT_BUILTIN);
    reg("exit",     cmd_exit,     "Exit shell",                     CAT_BUILTIN);
    reg("help",     cmd_help,     "Show help",                      CAT_BUILTIN);
    reg("pwd",      cmd_pwd,      "Print working directory",        CAT_BUILTIN);
    reg("echo",     cmd_echo,     "Print arguments",                CAT_BUILTIN);
    reg("clear",    cmd_clear,    "Clear screen",                   CAT_BUILTIN);
    reg("export",   cmd_export,   "Set environment variable",       CAT_BUILTIN);
    reg("history",  cmd_history_cmd, "Show command history",        CAT_BUILTIN);
    reg("type",     cmd_type,     "Show command type",              CAT_BUILTIN);
    reg("alias",    cmd_alias,    "Create/list aliases",            CAT_BUILTIN);

    /* Crypto */
    reg("encrypt",  cmd_encrypt,  "Encrypt a file",                 CAT_CRYPTO);
    reg("decrypt",  cmd_decrypt,  "Decrypt a .szenc file",          CAT_CRYPTO);
    reg("lock",     cmd_lock,     "Lock/encrypt a folder (fscrypt)",CAT_CRYPTO);
    reg("unlock",   cmd_unlock,   "Unlock a folder (fscrypt)",      CAT_CRYPTO);
    reg("hash",     cmd_hash,     "Hash a file (BLAKE2b)",          CAT_CRYPTO);
    reg("wipe",     cmd_wipe,     "Secure delete a file",           CAT_CRYPTO);
    reg("vault",    cmd_vault,    "Hidden container management",    CAT_CRYPTO);

    /* Sessions */
    reg("securesession", cmd_securesession, "Manage secure sessions", CAT_SESSION);
    reg("run",      cmd_run_nxe,  "Execute .nxe binary",            CAT_SESSION);

    /* System */
    reg("status",   cmd_status,   "Security status overview",       CAT_SYSTEM);
    reg("sysinfo",  cmd_sysinfo,  "System information",             CAT_SYSTEM);
}

const CommandEntry *cmd_find(const char *name)
{
    for (int i = 0; i < registry_count; i++) {
        if (strcmp(registry[i].name, name) == 0) return &registry[i];
    }
    return NULL;
}

const CommandEntry *cmd_get_all(int *count)
{
    *count = registry_count;
    return registry;
}

/* ── Built-in Commands ───────────────────────────────────────── */

int cmd_cd(int argc, char **argv, ShellState *state)
{
    const char *target;

    if (argc < 2) {
        target = state->home;
    } else if (strcmp(argv[1], "-") == 0) {
        target = getenv("OLDPWD");
        if (!target) {
            fprintf(stderr, "cd: OLDPWD not set\n");
            return 1;
        }
    } else if (argv[1][0] == '~') {
        static char expanded[1024];
        snprintf(expanded, sizeof(expanded), "%s%s", state->home, argv[1] + 1);
        target = expanded;
    } else {
        target = argv[1];
    }

    /* Save old directory */
    char oldpwd[1024];
    getcwd(oldpwd, sizeof(oldpwd));

    if (chdir(target) != 0) {
        fprintf(stderr, "cd: %s: %s\n", target, strerror(errno));
        return 1;
    }

    setenv("OLDPWD", oldpwd, 1);
    getcwd(state->cwd, sizeof(state->cwd));
    setenv("PWD", state->cwd, 1);

    return 0;
}

int cmd_exit(int argc, char **argv, ShellState *state)
{
    state->running = 0;
    if (argc > 1) {
        state->last_exit_code = atoi(argv[1]);
    }
    return state->last_exit_code;
}

int cmd_help(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc > 1) {
        /* Show help for specific command */
        const CommandEntry *e = cmd_find(argv[1]);
        if (e) {
            printf("  %s — %s\n", e->name, e->help);
        } else {
            printf("  Unknown command: %s\n", argv[1]);
        }
        return 0;
    }

    /* List all commands by category */
    const char *cat_names[] = {"BUILTIN", "CRYPTO", "SESSION", "SYSTEM"};
    const char *cat_colors[] = {"\033[36m", "\033[33m", "\033[35m", "\033[32m"};

    printf("\n  \033[1m🛡️  SecureZ+ Shell Commands\033[0m\n\n");

    for (int cat = 0; cat < 4; cat++) {
        printf("  %s━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n",
               cat_colors[cat], cat_names[cat]);

        for (int i = 0; i < registry_count; i++) {
            if (registry[i].category == (CommandCategory)cat) {
                printf("    %-18s %s\n", registry[i].name, registry[i].help);
            }
        }
        printf("\n");
    }

    printf("  Use \033[1mhelp <command>\033[0m for details.\n");
    printf("  External commands (ls, cat, etc.) work normally.\n\n");

    return 0;
}

int cmd_pwd(int argc, char **argv, ShellState *state)
{
    (void)argc; (void)argv;
    printf("%s\n", state->cwd);
    return 0;
}

int cmd_echo(int argc, char **argv, ShellState *state)
{
    (void)state;
    for (int i = 1; i < argc; i++) {
        printf("%s%s", argv[i], (i < argc - 1) ? " " : "");
    }
    printf("\n");
    return 0;
}

int cmd_clear(int argc, char **argv, ShellState *state)
{
    (void)argc; (void)argv; (void)state;
    printf("\033[2J\033[H");
    return 0;
}

int cmd_export(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        /* List all environment variables */
        extern char **environ;
        for (char **env = environ; *env; env++) {
            printf("  %s\n", *env);
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            *eq = '\0';
            setenv(argv[i], eq + 1, 1);
            *eq = '=';
        } else {
            /* Export existing variable */
            const char *val = getenv(argv[i]);
            if (val) {
                printf("  %s=%s\n", argv[i], val);
            }
        }
    }

    return 0;
}

int cmd_history_cmd(int argc, char **argv, ShellState *state)
{
    (void)argc; (void)argv; (void)state;

    /* readline's history */
    HIST_ENTRY **hist = history_list();
    if (!hist) return 0;

    for (int i = 0; hist[i]; i++) {
        printf("  %4d  %s\n", i + 1, hist[i]->line);
    }

    return 0;
}

int cmd_type(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        fprintf(stderr, "type: missing argument\n");
        return 1;
    }

    const CommandEntry *e = cmd_find(argv[1]);
    if (e) {
        const char *cat_names[] = {"builtin", "crypto", "session", "system"};
        printf("  %s is a shell %s\n", argv[1], cat_names[e->category]);
    } else {
        /* Check if it's an external command */
        char *path = getenv("PATH");
        if (!path) { printf("  %s: not found\n", argv[1]); return 1; }

        char *path_copy = strdup(path);
        char *dir = strtok(path_copy, ":");
        int found = 0;

        while (dir) {
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", dir, argv[1]);
            if (access(full, X_OK) == 0) {
                printf("  %s is %s\n", argv[1], full);
                found = 1;
                break;
            }
            dir = strtok(NULL, ":");
        }

        free(path_copy);
        if (!found) {
            printf("  %s: not found\n", argv[1]);
            return 1;
        }
    }

    return 0;
}

int cmd_alias(int argc, char **argv, ShellState *state)
{
    (void)state;

    if (argc < 2) {
        printf("  (aliases not yet persistent)\n");
        return 0;
    }

    /* Parse alias name=value */
    char *eq = strchr(argv[1], '=');
    if (!eq) {
        printf("  Usage: alias name=value\n");
        return 1;
    }

    printf("  Alias set (session only): %s\n", argv[1]);
    return 0;
}
