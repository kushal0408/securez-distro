/*
 * SecureZ+ OS — SecureZ Shell
 * shell.h — Shell data structures
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_SHELL_H
#define SECUREZ_SHELL_H

#include <stddef.h>

#define MAX_LINE_LENGTH    4096
#define MAX_ARGS           256
#define MAX_PIPE_SEGMENTS  16
#define MAX_ALIASES        128
#define HISTORY_SIZE       1000

typedef struct {
    char    cwd[1024];
    char    user[64];
    char    hostname[64];
    char    home[256];
    int     is_root;
    int     in_secure_session;
    int     tor_active;
    int     vpn_active;
    char    git_branch[64];
    int     running;
    int     last_exit_code;
} ShellState;

typedef struct {
    char *name;
    char *value;
} Alias;

/* Redirection info */
typedef struct {
    char *stdin_file;      /* < file */
    char *stdout_file;     /* > file */
    char *stderr_file;     /* 2> file */
    int   stdout_append;   /* >> file */
    int   stderr_append;   /* 2>> file */
} Redirect;

/* Single command in a pipeline */
typedef struct {
    char     *argv[MAX_ARGS];
    int       argc;
    Redirect  redir;
    int       background;   /* & */
} Command;

/* Pipeline of commands */
typedef struct {
    Command  commands[MAX_PIPE_SEGMENTS];
    int      count;
} Pipeline;

#endif /* SECUREZ_SHELL_H */
