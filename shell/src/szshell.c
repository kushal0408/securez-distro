/*
 * SecureZ+ OS — SecureZ Shell
 * szshell.c — Main shell REPL
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#define _GNU_SOURCE
#include "shell.h"
#include "commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sodium.h>

static ShellState state;

/* ── Forward declarations ────────────────────────────────────── */
extern char *render_prompt(ShellState *state);
extern Pipeline parse_line(const char *line);
extern void detect_environment(ShellState *state);

/* ── Signal handling ─────────────────────────────────────────── */

static void sigint_handler(int sig)
{
    (void)sig;
    printf("\n");
    rl_on_new_line();
    rl_replace_line("", 0);
    rl_redisplay();
}

static void sigchld_handler(int sig)
{
    (void)sig;
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0);
}

/* ── Tab completion ──────────────────────────────────────────── */

static char *command_generator(const char *text, int gen_state)
{
    static int index, len;
    int total;
    const CommandEntry *commands;

    if (!gen_state) {
        index = 0;
        len = strlen(text);
    }

    commands = cmd_get_all(&total);

    while (index < total) {
        const char *name = commands[index].name;
        index++;
        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }

    return NULL;
}

static char **shell_completion(const char *text, int start, int end)
{
    (void)end;

    /* Complete commands at start of line */
    if (start == 0) {
        return rl_completion_matches(text, command_generator);
    }

    /* Otherwise default to filename completion */
    return NULL;
}

/* ── Pipeline execution ──────────────────────────────────────── */

static int execute_pipeline(Pipeline *pipeline)
{
    if (pipeline->count == 0) return 0;

    /* Single command — check for builtins first */
    if (pipeline->count == 1) {
        Command *cmd = &pipeline->commands[0];
        if (cmd->argc == 0) return 0;

        const CommandEntry *entry = cmd_find(cmd->argv[0]);
        if (entry) {
            return entry->handler(cmd->argc, cmd->argv, &state);
        }
    }

    /* External commands and pipelines */
    int prev_fd = -1;
    pid_t pids[MAX_PIPE_SEGMENTS];
    int n_pids = 0;

    for (int i = 0; i < pipeline->count; i++) {
        Command *cmd = &pipeline->commands[i];
        if (cmd->argc == 0) continue;

        int pipefd[2] = {-1, -1};
        if (i < pipeline->count - 1) {
            if (pipe(pipefd) != 0) {
                perror("pipe");
                return 1;
            }
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }

        if (pid == 0) {
            /* Child process */

            /* Input redirection */
            if (prev_fd != -1) {
                dup2(prev_fd, STDIN_FILENO);
                close(prev_fd);
            } else if (cmd->redir.stdin_file) {
                FILE *f = fopen(cmd->redir.stdin_file, "r");
                if (!f) { perror(cmd->redir.stdin_file); _exit(1); }
                dup2(fileno(f), STDIN_FILENO);
                fclose(f);
            }

            /* Output redirection */
            if (pipefd[1] != -1) {
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[0]);
                close(pipefd[1]);
            } else if (cmd->redir.stdout_file) {
                FILE *f = fopen(cmd->redir.stdout_file,
                                cmd->redir.stdout_append ? "a" : "w");
                if (!f) { perror(cmd->redir.stdout_file); _exit(1); }
                dup2(fileno(f), STDOUT_FILENO);
                fclose(f);
            }

            /* Stderr redirection */
            if (cmd->redir.stderr_file) {
                FILE *f = fopen(cmd->redir.stderr_file,
                                cmd->redir.stderr_append ? "a" : "w");
                if (!f) { perror(cmd->redir.stderr_file); _exit(1); }
                dup2(fileno(f), STDERR_FILENO);
                fclose(f);
            }

            /* Try builtin */
            const CommandEntry *entry = cmd_find(cmd->argv[0]);
            if (entry) {
                int ret = entry->handler(cmd->argc, cmd->argv, &state);
                _exit(ret);
            }

            /* Execute external command */
            execvp(cmd->argv[0], cmd->argv);
            fprintf(stderr, "szshell: %s: command not found\n", cmd->argv[0]);
            _exit(127);
        }

        /* Parent */
        pids[n_pids++] = pid;

        if (prev_fd != -1) close(prev_fd);
        if (pipefd[1] != -1) close(pipefd[1]);
        prev_fd = pipefd[0];
    }

    /* Wait for all processes (unless background) */
    if (!pipeline->commands[0].background) {
        int last_status = 0;
        for (int i = 0; i < n_pids; i++) {
            int status;
            waitpid(pids[i], &status, 0);
            if (i == n_pids - 1) {
                last_status = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            }
        }
        state.last_exit_code = last_status;
        return last_status;
    }

    return 0;
}

/* ── Main ────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    /* Initialize shell state */
    memset(&state, 0, sizeof(state));
    state.running = 1;

    /* Get user info */
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        strncpy(state.user, pw->pw_name, sizeof(state.user) - 1);
        strncpy(state.home, pw->pw_dir, sizeof(state.home) - 1);
    } else {
        strncpy(state.user, "user", sizeof(state.user) - 1);
        strncpy(state.home, "/tmp", sizeof(state.home) - 1);
    }

    state.is_root = (getuid() == 0);
    gethostname(state.hostname, sizeof(state.hostname) - 1);
    getcwd(state.cwd, sizeof(state.cwd));

    /* Register commands */
    cmd_register_all();

    /* Set up signal handlers */
    signal(SIGINT, sigint_handler);
    signal(SIGCHLD, sigchld_handler);
    signal(SIGTSTP, SIG_IGN);

    /* Set up readline */
    rl_attempted_completion_function = shell_completion;
    rl_readline_name = "szshell";

    /* Load history */
    char hist_path[512];
    snprintf(hist_path, sizeof(hist_path), "%s/.szshell_history", state.home);
    read_history(hist_path);

    /* Print welcome banner on interactive start */
    if (isatty(STDIN_FILENO)) {
        printf("\n");
        printf("  \033[36m┌─────────────────────────────────────┐\033[0m\n");
        printf("  \033[36m│\033[0m  \033[1;36m🛡️  SecureZ+ OS v1.0 (Fortress)\033[0m   \033[36m│\033[0m\n");
        printf("  \033[36m│\033[0m  \033[2mSecurity • Privacy • Control\033[0m       \033[36m│\033[0m\n");
        printf("  \033[36m│\033[0m  \033[2mType 'help' for available commands\033[0m  \033[36m│\033[0m\n");
        printf("  \033[36m└─────────────────────────────────────┘\033[0m\n");
        printf("\n");
    }

    /* Main REPL */
    while (state.running) {
        /* Update environment detection */
        detect_environment(&state);

        /* Render prompt */
        char *prompt = render_prompt(&state);

        /* Read line */
        char *line = readline(prompt);
        free(prompt);

        if (!line) {
            /* EOF (Ctrl+D) */
            printf("\n");
            break;
        }

        /* Skip empty lines */
        if (line[0] == '\0') {
            free(line);
            continue;
        }

        /* Add to history */
        add_history(line);

        /* Parse and execute */
        Pipeline pipeline = parse_line(line);
        execute_pipeline(&pipeline);

        /* Free parsed pipeline strings */
        for (int i = 0; i < pipeline.count; i++) {
            for (int j = 0; j < pipeline.commands[i].argc; j++) {
                free(pipeline.commands[i].argv[j]);
            }
            free(pipeline.commands[i].redir.stdin_file);
            free(pipeline.commands[i].redir.stdout_file);
            free(pipeline.commands[i].redir.stderr_file);
        }

        free(line);
    }

    /* Save history */
    write_history(hist_path);

    return state.last_exit_code;
}
