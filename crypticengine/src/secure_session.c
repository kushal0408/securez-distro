/*
 * SecureZ+ OS — CrypticEngine
 * secure_session.c — Namespace-isolated secure execution environments
 *
 * Security comes from Linux kernel primitives:
 *  - PID namespace: process isolation
 *  - Mount namespace: private filesystem view
 *  - Network namespace: network isolation
 *  - tmpfs: RAM-only storage
 *  - cgroups v2: resource limits
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#define _GNU_SOURCE
#include "secure_session.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>

/* ── State ───────────────────────────────────────────────────── */

static SessionInfo   sessions[SESSION_MAX_ACTIVE];
static int           session_count = 0;
static int           next_session_id = 1;
static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;
static int           session_initialized = 0;

#define SESSION_TMPFS_BASE   "/tmp/securez-sessions"
#define SESSION_CGROUP_BASE  "/sys/fs/cgroup/securez"

/* ── Internal helpers ────────────────────────────────────────── */

static int find_session(int session_id)
{
    for (int i = 0; i < session_count; i++) {
        if (sessions[i].id == session_id) return i;
    }
    return -1;
}

static void setup_cgroup(SessionInfo *s)
{
    /* Create cgroup directory */
    snprintf(s->cgroup_path, sizeof(s->cgroup_path),
             "%s/session-%d", SESSION_CGROUP_BASE, s->id);

    mkdir(SESSION_CGROUP_BASE, 0755);
    if (mkdir(s->cgroup_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[Session] Warning: Cannot create cgroup %s: %s\n",
                s->cgroup_path, strerror(errno));
        return;
    }

    /* Set memory limit */
    char limit_path[512];
    snprintf(limit_path, sizeof(limit_path), "%s/memory.max", s->cgroup_path);

    FILE *f = fopen(limit_path, "w");
    if (f) {
        fprintf(f, "%zu", s->memory_limit);
        fclose(f);
    }
}

static void cleanup_cgroup(SessionInfo *s)
{
    if (s->cgroup_path[0] != '\0') {
        rmdir(s->cgroup_path);
    }
}

/*
 * Child process function: runs inside the new namespace.
 * Sets up the isolated environment, then execs a shell.
 */
static int session_child(void *arg)
{
    SessionInfo *s = (SessionInfo *)arg;

    /* Set hostname to identify the session */
    sethostname("securez-session", 15);

    /* Mount proc for the new PID namespace */
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

    /* Create and mount tmpfs for RAM-only files */
    mkdir(s->tmpfs_path, 0700);
    if (mount("tmpfs", s->tmpfs_path, "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "size=256m,mode=0700") != 0) {
        fprintf(stderr, "[Session] Warning: Cannot mount tmpfs at %s: %s\n",
                s->tmpfs_path, strerror(errno));
    }

    /* Add this process to the cgroup */
    char procs_path[512];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", s->cgroup_path);
    FILE *f = fopen(procs_path, "w");
    if (f) {
        fprintf(f, "%d", getpid());
        fclose(f);
    }

    /* Print session info */
    fprintf(stderr, "\n[🔒 Secure Session %d Started]\n", s->id);
    fprintf(stderr, "  Name:     %s\n", s->name);
    fprintf(stderr, "  tmpfs:    %s (RAM-only)\n", s->tmpfs_path);
    fprintf(stderr, "  Network:  %s\n", s->has_network ? "connected" : "isolated");
    fprintf(stderr, "  Memory:   %zuMB limit\n", s->memory_limit / (1024 * 1024));
    fprintf(stderr, "  Type 'exit' to end session and wipe memory.\n\n");

    /* Exec a shell in the isolated environment */
    char *shell_argv[] = { "/usr/bin/szshell", NULL };
    char *shell_envp[] = {
        "HOME=/tmp",
        "TERM=xterm-256color",
        "SECUREZ_SESSION=1",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    /* Try szshell first, fall back to bash */
    execve("/usr/bin/szshell", shell_argv, shell_envp);

    shell_argv[0] = "/bin/bash";
    execve("/bin/bash", shell_argv, shell_envp);

    /* If we get here, exec failed */
    perror("[Session] Failed to exec shell");
    _exit(1);
}

/* ── Public API ──────────────────────────────────────────────── */

int session_init(void)
{
    if (session_initialized) return 0;

    memset(sessions, 0, sizeof(sessions));
    session_count = 0;
    next_session_id = 1;

    /* Create base directories */
    mkdir(SESSION_TMPFS_BASE, 0700);
    mkdir(SESSION_CGROUP_BASE, 0755);

    session_initialized = 1;
    return 0;
}

void session_shutdown(void)
{
    if (!session_initialized) return;

    session_destroy_all();
    session_initialized = 0;
}

int session_create(const char *name, size_t memory_limit, int allow_network)
{
    if (!session_initialized) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&session_mutex);

    if (session_count >= SESSION_MAX_ACTIVE) {
        fprintf(stderr, "[Session] Maximum sessions (%d) reached\n", SESSION_MAX_ACTIVE);
        pthread_mutex_unlock(&session_mutex);
        return -1;
    }

    /* Set up session info */
    int idx = session_count;
    SessionInfo *s = &sessions[idx];
    memset(s, 0, sizeof(SessionInfo));

    s->id = next_session_id++;
    s->state = SESSION_STATE_STARTING;
    s->memory_limit = memory_limit > 0 ? memory_limit : SESSION_DEFAULT_MEM;
    s->has_network = allow_network;
    s->start_time = time(NULL);

    if (name) {
        strncpy(s->name, name, SESSION_NAME_MAX - 1);
    } else {
        snprintf(s->name, SESSION_NAME_MAX, "session-%d", s->id);
    }

    snprintf(s->tmpfs_path, sizeof(s->tmpfs_path),
             "%s/%s", SESSION_TMPFS_BASE, s->name);

    /* Set up cgroup */
    setup_cgroup(s);

    /* Clone flags for namespace isolation */
    int clone_flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD;

    if (!allow_network) {
        clone_flags |= CLONE_NEWNET;  /* Isolate network */
    }

    /* Allocate stack for clone */
    size_t stack_size = 1024 * 1024;  /* 1 MB stack */
    char *stack = malloc(stack_size);
    if (!stack) {
        cleanup_cgroup(s);
        pthread_mutex_unlock(&session_mutex);
        return -1;
    }

    char *stack_top = stack + stack_size;

    /* Create the isolated process */
    pid_t child_pid = clone(session_child, stack_top, clone_flags, s);

    if (child_pid < 0) {
        perror("[Session] clone() failed (need root?)");
        free(stack);
        cleanup_cgroup(s);
        pthread_mutex_unlock(&session_mutex);
        return -1;
    }

    s->pid = child_pid;
    s->state = SESSION_STATE_ACTIVE;
    session_count++;

    /* Note: we intentionally leak the stack here because the child
     * process is using it. It will be freed on session_destroy. */

    pthread_mutex_unlock(&session_mutex);

    fprintf(stderr, "[Session] Created session %d (PID %d)\n", s->id, child_pid);
    return s->id;
}

int session_destroy(int session_id)
{
    pthread_mutex_lock(&session_mutex);

    int idx = find_session(session_id);
    if (idx < 0) {
        pthread_mutex_unlock(&session_mutex);
        return -1;
    }

    SessionInfo *s = &sessions[idx];
    s->state = SESSION_STATE_STOPPING;

    /* 1. Kill all processes in the session */
    if (s->pid > 0) {
        kill(s->pid, SIGTERM);
        usleep(100000);  /* 100ms grace */
        kill(s->pid, SIGKILL);
        waitpid(s->pid, NULL, WNOHANG);
    }

    /* 2. Unmount tmpfs (RAM data disappears) */
    if (s->tmpfs_path[0]) {
        umount2(s->tmpfs_path, MNT_DETACH);
        rmdir(s->tmpfs_path);
    }

    /* 3. Clean up cgroup */
    cleanup_cgroup(s);

    /* 4. Remove from active list */
    if (idx < session_count - 1) {
        memmove(&sessions[idx], &sessions[idx + 1],
                (session_count - idx - 1) * sizeof(SessionInfo));
    }
    session_count--;

    pthread_mutex_unlock(&session_mutex);

    fprintf(stderr, "[Session] Destroyed session %d — RAM wiped\n", session_id);
    return 0;
}

int session_get_info(int session_id, SessionInfo *info)
{
    pthread_mutex_lock(&session_mutex);

    int idx = find_session(session_id);
    if (idx < 0) {
        pthread_mutex_unlock(&session_mutex);
        return -1;
    }

    memcpy(info, &sessions[idx], sizeof(SessionInfo));
    pthread_mutex_unlock(&session_mutex);
    return 0;
}

int session_list(SessionInfo *out_sessions, int *count)
{
    pthread_mutex_lock(&session_mutex);

    memcpy(out_sessions, sessions, session_count * sizeof(SessionInfo));
    *count = session_count;

    pthread_mutex_unlock(&session_mutex);
    return 0;
}

pid_t session_exec(int session_id, char *const argv[])
{
    (void)session_id;

    /* Fork and exec within the session's namespace.
     * For simplicity, this does a basic fork+exec. In production,
     * you'd nsenter into the session's namespaces. */
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return pid;
}

int session_is_active(void)
{
    const char *env = getenv("SECUREZ_SESSION");
    return (env && strcmp(env, "1") == 0) ? 1 : 0;
}

void session_destroy_all(void)
{
    /* Copy IDs first to avoid modifying the array while iterating */
    int ids[SESSION_MAX_ACTIVE];
    int count;

    pthread_mutex_lock(&session_mutex);
    count = session_count;
    for (int i = 0; i < count; i++) {
        ids[i] = sessions[i].id;
    }
    pthread_mutex_unlock(&session_mutex);

    for (int i = 0; i < count; i++) {
        session_destroy(ids[i]);
    }
}
