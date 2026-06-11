/*
 * SecureZ+ OS — SecureZ Shell
 * parser.c — Command line parser with pipes, redirects, and quoting
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Tokenizer ───────────────────────────────────────────────── */

static char **tokenize(const char *line, int *count)
{
    char **tokens = malloc(MAX_ARGS * sizeof(char *));
    *count = 0;

    if (!tokens) return NULL;

    const char *p = line;

    while (*p && *count < MAX_ARGS - 1) {
        /* Skip whitespace */
        while (*p && isspace(*p)) p++;
        if (!*p) break;

        char token[MAX_LINE_LENGTH];
        int ti = 0;

        if (*p == '\'' ) {
            /* Single-quoted string — no expansion */
            p++;
            while (*p && *p != '\'') {
                if (ti < MAX_LINE_LENGTH - 1) token[ti++] = *p;
                p++;
            }
            if (*p == '\'') p++;
        }
        else if (*p == '"') {
            /* Double-quoted string — allows variable expansion */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && *(p + 1)) {
                    p++;
                    if (ti < MAX_LINE_LENGTH - 1) token[ti++] = *p;
                } else {
                    if (ti < MAX_LINE_LENGTH - 1) token[ti++] = *p;
                }
                p++;
            }
            if (*p == '"') p++;
        }
        else {
            /* Unquoted token — split on whitespace and special chars */
            /* Special single-char tokens */
            if (*p == '|' || *p == '&' || *p == ';') {
                token[ti++] = *p;
                p++;
                /* Handle >> and 2> */
            } else if (*p == '>' && *(p+1) == '>') {
                token[ti++] = '>'; token[ti++] = '>';
                p += 2;
            } else if (*p == '2' && *(p+1) == '>') {
                token[ti++] = '2'; token[ti++] = '>';
                p += 2;
            } else if (*p == '>' || *p == '<') {
                token[ti++] = *p;
                p++;
            } else {
                /* Normal word */
                while (*p && !isspace(*p) &&
                       *p != '|' && *p != '&' && *p != ';' &&
                       *p != '>' && *p != '<') {
                    if (*p == '\\' && *(p + 1)) {
                        p++;
                    }
                    if (ti < MAX_LINE_LENGTH - 1) token[ti++] = *p;
                    p++;
                }
            }
        }

        token[ti] = '\0';
        if (ti > 0) {
            tokens[*count] = strdup(token);
            (*count)++;
        }
    }

    tokens[*count] = NULL;
    return tokens;
}

/* ── Variable expansion ──────────────────────────────────────── */

static char *expand_variables(const char *token)
{
    if (!strchr(token, '$')) return strdup(token);

    char result[MAX_LINE_LENGTH];
    int ri = 0;
    const char *p = token;

    while (*p && ri < MAX_LINE_LENGTH - 1) {
        if (*p == '$') {
            p++;
            char varname[256];
            int vi = 0;

            /* Handle ${VAR} */
            if (*p == '{') {
                p++;
                while (*p && *p != '}' && vi < 255) {
                    varname[vi++] = *p++;
                }
                if (*p == '}') p++;
            }
            /* Handle $? (last exit code) */
            else if (*p == '?') {
                varname[0] = '?';
                vi = 1;
                p++;
            }
            /* Handle $VAR */
            else {
                while (*p && (isalnum(*p) || *p == '_') && vi < 255) {
                    varname[vi++] = *p++;
                }
            }

            varname[vi] = '\0';

            const char *value = getenv(varname);
            if (value) {
                size_t vlen = strlen(value);
                if (ri + (int)vlen < MAX_LINE_LENGTH - 1) {
                    memcpy(result + ri, value, vlen);
                    ri += vlen;
                }
            }
        }
        else if (*p == '~' && (ri == 0)) {
            /* Expand ~ at start of token */
            const char *home = getenv("HOME");
            if (home) {
                size_t hlen = strlen(home);
                memcpy(result + ri, home, hlen);
                ri += hlen;
            }
            p++;
        }
        else {
            result[ri++] = *p++;
        }
    }

    result[ri] = '\0';
    return strdup(result);
}

/* ── Main parser ─────────────────────────────────────────────── */

Pipeline parse_line(const char *line)
{
    Pipeline pipeline;
    memset(&pipeline, 0, sizeof(pipeline));

    if (!line || !*line) return pipeline;

    /* Skip comments */
    if (line[0] == '#') return pipeline;

    /* Tokenize */
    int token_count = 0;
    char **tokens = tokenize(line, &token_count);
    if (!tokens || token_count == 0) {
        free(tokens);
        return pipeline;
    }

    /* Build pipeline: split on | and handle redirects */
    int cmd_idx = 0;
    Command *cmd = &pipeline.commands[cmd_idx];
    memset(cmd, 0, sizeof(Command));

    for (int i = 0; i < token_count; i++) {
        char *tok = tokens[i];

        if (strcmp(tok, "|") == 0) {
            /* Start next command in pipeline */
            cmd->argv[cmd->argc] = NULL;
            cmd_idx++;
            if (cmd_idx >= MAX_PIPE_SEGMENTS) break;
            cmd = &pipeline.commands[cmd_idx];
            memset(cmd, 0, sizeof(Command));
            free(tok);
            continue;
        }

        if (strcmp(tok, "&") == 0) {
            cmd->background = 1;
            free(tok);
            continue;
        }

        if (strcmp(tok, "<") == 0) {
            free(tok);
            if (i + 1 < token_count) {
                cmd->redir.stdin_file = expand_variables(tokens[++i]);
                free(tokens[i]);
            }
            continue;
        }

        if (strcmp(tok, ">") == 0) {
            free(tok);
            if (i + 1 < token_count) {
                cmd->redir.stdout_file = expand_variables(tokens[++i]);
                cmd->redir.stdout_append = 0;
                free(tokens[i]);
            }
            continue;
        }

        if (strcmp(tok, ">>") == 0) {
            free(tok);
            if (i + 1 < token_count) {
                cmd->redir.stdout_file = expand_variables(tokens[++i]);
                cmd->redir.stdout_append = 1;
                free(tokens[i]);
            }
            continue;
        }

        if (strcmp(tok, "2>") == 0) {
            free(tok);
            if (i + 1 < token_count) {
                cmd->redir.stderr_file = expand_variables(tokens[++i]);
                cmd->redir.stderr_append = 0;
                free(tokens[i]);
            }
            continue;
        }

        /* Regular argument — expand variables */
        char *expanded = expand_variables(tok);
        free(tok);
        cmd->argv[cmd->argc++] = expanded;
    }

    cmd->argv[cmd->argc] = NULL;
    pipeline.count = cmd_idx + 1;

    free(tokens);
    return pipeline;
}
