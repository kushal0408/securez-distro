/*
 * SecureZ+ OS — SecureZ Shell
 * commands.h — Command registry
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_COMMANDS_H
#define SECUREZ_COMMANDS_H

#include "shell.h"

typedef enum {
    CAT_BUILTIN = 0,
    CAT_CRYPTO,
    CAT_SESSION,
    CAT_SYSTEM
} CommandCategory;

typedef int (*cmd_handler_t)(int argc, char **argv, ShellState *state);

typedef struct {
    const char      *name;
    cmd_handler_t    handler;
    const char      *help;
    CommandCategory  category;
} CommandEntry;

/* Register all commands */
void cmd_register_all(void);

/* Find a command by name */
const CommandEntry *cmd_find(const char *name);

/* Get all commands for listing */
const CommandEntry *cmd_get_all(int *count);

/* ── Builtin commands ──────────────────────── */
int cmd_cd(int argc, char **argv, ShellState *state);
int cmd_exit(int argc, char **argv, ShellState *state);
int cmd_help(int argc, char **argv, ShellState *state);
int cmd_pwd(int argc, char **argv, ShellState *state);
int cmd_echo(int argc, char **argv, ShellState *state);
int cmd_clear(int argc, char **argv, ShellState *state);
int cmd_export(int argc, char **argv, ShellState *state);
int cmd_history_cmd(int argc, char **argv, ShellState *state);
int cmd_type(int argc, char **argv, ShellState *state);
int cmd_alias(int argc, char **argv, ShellState *state);

/* ── Crypto commands ───────────────────────── */
int cmd_encrypt(int argc, char **argv, ShellState *state);
int cmd_decrypt(int argc, char **argv, ShellState *state);
int cmd_lock(int argc, char **argv, ShellState *state);
int cmd_unlock(int argc, char **argv, ShellState *state);
int cmd_hash(int argc, char **argv, ShellState *state);
int cmd_wipe(int argc, char **argv, ShellState *state);
int cmd_vault(int argc, char **argv, ShellState *state);

/* ── Session commands ──────────────────────── */
int cmd_securesession(int argc, char **argv, ShellState *state);
int cmd_run_nxe(int argc, char **argv, ShellState *state);

/* ── System commands ───────────────────────── */
int cmd_status(int argc, char **argv, ShellState *state);
int cmd_sysinfo(int argc, char **argv, ShellState *state);

#endif /* SECUREZ_COMMANDS_H */
