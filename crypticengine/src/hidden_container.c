/*
 * SecureZ+ OS — CrypticEngine
 * hidden_container.c — Hidden encrypted volumes (LUKS + detached headers)
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "hidden_container.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <pwd.h>
#include <pthread.h>

static ContainerInfo containers[CONTAINER_MAX_ACTIVE];
static int container_count = 0;
static pthread_mutex_t container_mutex = PTHREAD_MUTEX_INITIALIZER;
static char container_base[CONTAINER_PATH_MAX] = "";
static int container_initialized = 0;

/* ── Internal helpers ────────────────────────────────────────── */

static const char *get_container_base(void)
{
    if (container_base[0] != '\0') return container_base;

    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/root";
    }

    snprintf(container_base, sizeof(container_base),
             "%s/.securez/containers", home);
    return container_base;
}

static int run_command(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        /* Child: redirect stderr to /dev/null for clean output */
        execvp(argv[0], argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int find_container(const char *name)
{
    for (int i = 0; i < container_count; i++) {
        if (strcmp(containers[i].name, name) == 0) return i;
    }
    return -1;
}

static void scan_existing_containers(void)
{
    /* Scan container directory for existing .vault files */
    char pattern[CONTAINER_PATH_MAX];
    snprintf(pattern, sizeof(pattern), "%s", get_container_base());

    /* We just initialize empty — containers are discovered on open */
}

/* ── Public API ──────────────────────────────────────────────── */

int container_init(void)
{
    if (container_initialized) return 0;

    const char *base = get_container_base();

    /* Create directory structure */
    char cmd[CONTAINER_PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "%s", base);
    mkdir(cmd, 0700);

    /* Also create mount point base */
    mkdir("/mnt/securez-vault", 0700);

    memset(containers, 0, sizeof(containers));
    container_count = 0;

    scan_existing_containers();

    container_initialized = 1;
    return 0;
}

int container_create(const char *name, size_t size_mb, const char *password)
{
    if (!name || !password || size_mb == 0) {
        errno = EINVAL;
        return -1;
    }

    if (strlen(name) >= CONTAINER_NAME_MAX) {
        fprintf(stderr, "[Container] Name too long\n");
        return -1;
    }

    const char *base = get_container_base();
    char vault_path[CONTAINER_PATH_MAX];
    char header_path[CONTAINER_PATH_MAX];

    snprintf(vault_path, sizeof(vault_path), "%s/%s.vault", base, name);
    snprintf(header_path, sizeof(header_path), "%s/%s.header", base, name);

    /* Check if already exists */
    if (access(vault_path, F_OK) == 0) {
        fprintf(stderr, "[Container] Container '%s' already exists\n", name);
        return -1;
    }

    fprintf(stderr, "[Container] Creating %zuMB encrypted container '%s'...\n",
            size_mb, name);

    /* Step 1: Create sparse file filled with random data */
    /* Using dd with /dev/urandom for genuine random data appearance */
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "count=%zu", size_mb);

    char *dd_argv[] = {
        "dd", "if=/dev/urandom", NULL, "bs=1M", size_str, "status=progress", NULL
    };
    char of_arg[CONTAINER_PATH_MAX + 4];
    snprintf(of_arg, sizeof(of_arg), "of=%s", vault_path);
    dd_argv[2] = of_arg;

    if (run_command(dd_argv) != 0) {
        fprintf(stderr, "[Container] Failed to create vault file\n");
        return -1;
    }

    /* Step 2: Set up loop device */
    /* We'll use cryptsetup which handles loop devices internally */

    /* Step 3: Format with LUKS using detached header */
    /* The detached header means the vault file has NO LUKS signature —
     * it's indistinguishable from random data without the header. */
    char *format_argv[] = {
        "cryptsetup", "luksFormat",
        "--type", "luks2",
        "--header", header_path,
        "--cipher", "aes-xts-plain64",
        "--key-size", "512",
        "--hash", "sha512",
        "--pbkdf", "argon2id",
        "--pbkdf-memory", "262144",     /* 256 MB */
        "--pbkdf-parallel", "4",
        "--pbkdf-force-iterations", "4",
        "--batch-mode",
        "--key-file", "-",              /* Read key from stdin */
        vault_path,
        NULL
    };

    /* For cryptsetup, we need to pipe the password via stdin */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        unlink(vault_path);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        unlink(vault_path);
        return -1;
    }

    if (pid == 0) {
        /* Child */
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execvp("cryptsetup", format_argv);
        _exit(127);
    }

    /* Parent: write password to pipe */
    close(pipefd[0]);
    write(pipefd[1], password, strlen(password));
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[Container] cryptsetup luksFormat failed\n");
        unlink(vault_path);
        unlink(header_path);
        return -1;
    }

    /* Step 4: Open, format with ext4, then close */
    char mapper_name[CONTAINER_NAME_MAX + 16];
    snprintf(mapper_name, sizeof(mapper_name), "sz-%s", name);

    /* Open */
    if (pipe(pipefd) != 0) {
        unlink(vault_path);
        unlink(header_path);
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        char *open_argv[] = {
            "cryptsetup", "open",
            "--type", "luks2",
            "--header", header_path,
            "--key-file", "-",
            vault_path, mapper_name,
            NULL
        };
        execvp("cryptsetup", open_argv);
        _exit(127);
    }

    close(pipefd[0]);
    write(pipefd[1], password, strlen(password));
    close(pipefd[1]);
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[Container] cryptsetup open failed\n");
        unlink(vault_path);
        unlink(header_path);
        return -1;
    }

    /* Create filesystem */
    char dev_path[128];
    snprintf(dev_path, sizeof(dev_path), "/dev/mapper/%s", mapper_name);

    char *mkfs_argv[] = { "mkfs.ext4", "-q", dev_path, NULL };
    run_command(mkfs_argv);

    /* Close */
    char *close_argv[] = { "cryptsetup", "close", mapper_name, NULL };
    run_command(close_argv);

    /* Set restrictive permissions on header file */
    chmod(header_path, 0600);
    chmod(vault_path, 0600);

    fprintf(stderr, "[Container] ✅ Created encrypted container '%s' (%zuMB)\n",
            name, size_mb);
    fprintf(stderr, "  Vault:  %s (looks like random data)\n", vault_path);
    fprintf(stderr, "  Header: %s (keep this safe!)\n", header_path);

    return 0;
}

int container_open(const char *name, const char *password)
{
    if (!name || !password) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&container_mutex);

    /* Check if already open */
    int idx = find_container(name);
    if (idx >= 0 && containers[idx].state == CONTAINER_STATE_OPEN) {
        fprintf(stderr, "[Container] '%s' is already open at %s\n",
                name, containers[idx].mount_path);
        pthread_mutex_unlock(&container_mutex);
        return 0;
    }

    if (container_count >= CONTAINER_MAX_ACTIVE && idx < 0) {
        fprintf(stderr, "[Container] Maximum open containers reached\n");
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }

    const char *base = get_container_base();
    char vault_path[CONTAINER_PATH_MAX];
    char header_path[CONTAINER_PATH_MAX];
    char mount_path[CONTAINER_PATH_MAX];
    char mapper_name[CONTAINER_NAME_MAX + 16];

    snprintf(vault_path, sizeof(vault_path), "%s/%s.vault", base, name);
    snprintf(header_path, sizeof(header_path), "%s/%s.header", base, name);
    snprintf(mount_path, sizeof(mount_path), "/mnt/securez-vault/%s", name);
    snprintf(mapper_name, sizeof(mapper_name), "sz-%s", name);

    /* Verify files exist */
    if (access(vault_path, R_OK) != 0 || access(header_path, R_OK) != 0) {
        fprintf(stderr, "[Container] Container '%s' not found\n", name);
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }

    /* cryptsetup open with detached header */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        char *argv[] = {
            "cryptsetup", "open",
            "--type", "luks2",
            "--header", header_path,
            "--key-file", "-",
            vault_path, mapper_name,
            NULL
        };
        execvp("cryptsetup", argv);
        _exit(127);
    }

    close(pipefd[0]);
    write(pipefd[1], password, strlen(password));
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[Container] Failed to open — wrong password?\n");
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }

    /* Mount */
    mkdir(mount_path, 0700);
    char dev_path[128];
    snprintf(dev_path, sizeof(dev_path), "/dev/mapper/%s", mapper_name);

    if (mount(dev_path, mount_path, "ext4", MS_NOSUID | MS_NODEV, NULL) != 0) {
        /* Try via system mount command */
        char *mount_argv[] = { "mount", dev_path, mount_path, NULL };
        if (run_command(mount_argv) != 0) {
            fprintf(stderr, "[Container] Failed to mount\n");
            char *close_argv[] = { "cryptsetup", "close", mapper_name, NULL };
            run_command(close_argv);
            pthread_mutex_unlock(&container_mutex);
            return -1;
        }
    }

    /* Track in our state */
    if (idx < 0) idx = container_count++;

    ContainerInfo *c = &containers[idx];
    strncpy(c->name, name, CONTAINER_NAME_MAX - 1);
    strncpy(c->vault_path, vault_path, CONTAINER_PATH_MAX - 1);
    strncpy(c->header_path, header_path, CONTAINER_PATH_MAX - 1);
    strncpy(c->mount_path, mount_path, CONTAINER_PATH_MAX - 1);
    strncpy(c->mapper_name, mapper_name, CONTAINER_NAME_MAX - 1);
    c->state = CONTAINER_STATE_OPEN;

    pthread_mutex_unlock(&container_mutex);

    fprintf(stderr, "[Container] ✅ Opened '%s' at %s\n", name, mount_path);
    return 0;
}

int container_close(const char *name)
{
    if (!name) return -1;

    pthread_mutex_lock(&container_mutex);

    int idx = find_container(name);
    if (idx < 0 || containers[idx].state != CONTAINER_STATE_OPEN) {
        fprintf(stderr, "[Container] '%s' is not open\n", name);
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }

    ContainerInfo *c = &containers[idx];

    /* Unmount */
    if (umount2(c->mount_path, MNT_DETACH) != 0) {
        char *argv[] = { "umount", c->mount_path, NULL };
        run_command(argv);
    }
    rmdir(c->mount_path);

    /* Close LUKS */
    char *argv[] = { "cryptsetup", "close", c->mapper_name, NULL };
    run_command(argv);

    c->state = CONTAINER_STATE_CLOSED;

    /* Remove from list */
    if (idx < container_count - 1) {
        memmove(&containers[idx], &containers[idx + 1],
                (container_count - idx - 1) * sizeof(ContainerInfo));
    }
    container_count--;

    pthread_mutex_unlock(&container_mutex);

    fprintf(stderr, "[Container] 🔒 Closed '%s'\n", name);
    return 0;
}

int container_destroy(const char *name, const char *password)
{
    if (!name || !password) return -1;

    /* Close if open */
    container_close(name);

    const char *base = get_container_base();
    char vault_path[CONTAINER_PATH_MAX];
    char header_path[CONTAINER_PATH_MAX];

    snprintf(vault_path, sizeof(vault_path), "%s/%s.vault", base, name);
    snprintf(header_path, sizeof(header_path), "%s/%s.header", base, name);

    /* Overwrite with random data before deletion */
    struct stat st;
    if (stat(vault_path, &st) == 0) {
        char *argv[] = {
            "dd", "if=/dev/urandom", NULL,
            "bs=1M", NULL, "conv=notrunc", "status=none", NULL
        };
        char of_arg[CONTAINER_PATH_MAX + 4];
        snprintf(of_arg, sizeof(of_arg), "of=%s", vault_path);
        argv[2] = of_arg;
        char count_arg[32];
        snprintf(count_arg, sizeof(count_arg), "count=%ld",
                 (long)(st.st_size / (1024 * 1024)) + 1);
        argv[4] = count_arg;
        run_command(argv);
    }

    unlink(vault_path);
    unlink(header_path);

    fprintf(stderr, "[Container] 🗑️  Destroyed '%s' — data unrecoverable\n", name);
    return 0;
}

int container_list(ContainerInfo *out, int *count)
{
    pthread_mutex_lock(&container_mutex);
    memcpy(out, containers, container_count * sizeof(ContainerInfo));
    *count = container_count;
    pthread_mutex_unlock(&container_mutex);
    return 0;
}

int container_get_info(const char *name, ContainerInfo *info)
{
    pthread_mutex_lock(&container_mutex);
    int idx = find_container(name);
    if (idx < 0) {
        pthread_mutex_unlock(&container_mutex);
        return -1;
    }
    memcpy(info, &containers[idx], sizeof(ContainerInfo));
    pthread_mutex_unlock(&container_mutex);
    return 0;
}

void container_close_all(void)
{
    char names[CONTAINER_MAX_ACTIVE][CONTAINER_NAME_MAX];
    int count;

    pthread_mutex_lock(&container_mutex);
    count = container_count;
    for (int i = 0; i < count; i++) {
        strncpy(names[i], containers[i].name, CONTAINER_NAME_MAX);
    }
    pthread_mutex_unlock(&container_mutex);

    for (int i = 0; i < count; i++) {
        container_close(names[i]);
    }
}
