/*
 * SecureZ+ OS — CrypticEngine Daemon
 * crypticd.c — Security orchestration daemon
 *
 * Listens on Unix socket, manages sessions/containers/keys,
 * caches derived keys in locked memory with TTL.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#define _GNU_SOURCE
#include "cryptic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>

#define MAX_CLIENTS    8
#define CMD_BUF_SIZE   4096
#define RESP_BUF_SIZE  4096

static volatile int daemon_running = 1;

/* ── Signal handlers ─────────────────────────────────────────── */

static void handle_signal(int sig)
{
    syslog(LOG_INFO, "Received signal %d — shutting down", sig);
    daemon_running = 0;
}

/* ── Command dispatcher ──────────────────────────────────────── */

/*
 * Simple JSON-like command parsing. In production you'd use a real
 * JSON parser (cJSON, etc). For now we do basic string matching.
 *
 * Commands:
 *   {"cmd":"status"}
 *   {"cmd":"encrypt","path":"...","password":"..."}
 *   {"cmd":"decrypt","path":"...","password":"..."}
 *   {"cmd":"lock","path":"..."}
 *   {"cmd":"unlock","path":"..."}
 *   {"cmd":"hash","path":"..."}
 *   {"cmd":"wipe","path":"..."}
 *   {"cmd":"session_start"}
 *   {"cmd":"session_end","id":N}
 *   {"cmd":"session_list"}
 *   {"cmd":"container_create","name":"...","size":N,"password":"..."}
 *   {"cmd":"container_open","name":"...","password":"..."}
 *   {"cmd":"container_close","name":"..."}
 *   {"cmd":"container_list"}
 *   {"cmd":"emergency_wipe"}
 */

static char *extract_field(const char *json, const char *field)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", field);

    const char *start = strstr(json, search);
    if (!start) return NULL;

    start += strlen(search);
    const char *end = strchr(start, '"');
    if (!end) return NULL;

    size_t len = (size_t)(end - start);
    char *value = malloc(len + 1);
    if (!value) return NULL;

    memcpy(value, start, len);
    value[len] = '\0';
    return value;
}

static int extract_int(const char *json, const char *field)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", field);

    const char *start = strstr(json, search);
    if (!start) return -1;

    start += strlen(search);
    return atoi(start);
}

static void handle_command(const char *cmd_json, char *response, size_t resp_size)
{
    char *cmd = extract_field(cmd_json, "cmd");
    if (!cmd) {
        snprintf(response, resp_size,
                 "{\"status\":\"error\",\"msg\":\"missing cmd field\"}");
        return;
    }

    if (strcmp(cmd, "status") == 0) {
        size_t mem_count, mem_bytes;
        secure_memory_stats(&mem_count, &mem_bytes);

        SessionInfo sessions[SESSION_MAX_ACTIVE];
        int session_count = 0;
        session_list(sessions, &session_count);

        snprintf(response, resp_size,
                 "{\"status\":\"ok\",\"version\":\"%s\","
                 "\"secure_allocs\":%zu,\"secure_bytes\":%zu,"
                 "\"active_sessions\":%d,"
                 "\"daemon_pid\":%d}",
                 CRYPTIC_VERSION_STRING,
                 mem_count, mem_bytes,
                 session_count,
                 getpid());
    }
    else if (strcmp(cmd, "encrypt") == 0) {
        char *path = extract_field(cmd_json, "path");
        char *pw = extract_field(cmd_json, "password");
        if (!path || !pw) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path or password\"}");
        } else {
            int ret = cryptic_encrypt_file(path, pw);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(path);
        if (pw) { sodium_memzero(pw, strlen(pw)); free(pw); }
    }
    else if (strcmp(cmd, "decrypt") == 0) {
        char *path = extract_field(cmd_json, "path");
        char *pw = extract_field(cmd_json, "password");
        if (!path || !pw) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path or password\"}");
        } else {
            int ret = cryptic_decrypt_file(path, pw);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(path);
        if (pw) { sodium_memzero(pw, strlen(pw)); free(pw); }
    }
    else if (strcmp(cmd, "hash") == 0) {
        char *path = extract_field(cmd_json, "path");
        if (!path) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path\"}");
        } else {
            char hex[CRYPTIC_HASH_LEN * 2 + 1];
            if (cryptic_hash_file(path, hex) == 0) {
                snprintf(response, resp_size,
                         "{\"status\":\"ok\",\"hash\":\"%s\"}", hex);
            } else {
                snprintf(response, resp_size,
                         "{\"status\":\"error\",\"msg\":\"hash failed\"}");
            }
        }
        free(path);
    }
    else if (strcmp(cmd, "wipe") == 0) {
        char *path = extract_field(cmd_json, "path");
        if (!path) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path\"}");
        } else {
            int ret = cryptic_secure_delete(path);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(path);
    }
    else if (strcmp(cmd, "lock") == 0) {
        char *path = extract_field(cmd_json, "path");
        if (!path) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path\"}");
        } else {
            int ret = cryptic_lock_folder(path, "dummy");
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(path);
    }
    else if (strcmp(cmd, "unlock") == 0) {
        char *path = extract_field(cmd_json, "path");
        char *pw = extract_field(cmd_json, "password");
        if (!path || !pw) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing path or password\"}");
        } else {
            int ret = cryptic_unlock_folder(path, pw);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(path);
        if (pw) { sodium_memzero(pw, strlen(pw)); free(pw); }
    }
    else if (strcmp(cmd, "session_start") == 0) {
        int id = session_create(NULL, 0, 0);
        if (id > 0) {
            snprintf(response, resp_size,
                     "{\"status\":\"ok\",\"session_id\":%d}", id);
        } else {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"session creation failed\"}");
        }
    }
    else if (strcmp(cmd, "session_end") == 0) {
        int id = extract_int(cmd_json, "id");
        int ret = session_destroy(id);
        snprintf(response, resp_size,
                 "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
    }
    else if (strcmp(cmd, "session_list") == 0) {
        SessionInfo sessions[SESSION_MAX_ACTIVE];
        int count = 0;
        session_list(sessions, &count);

        int offset = snprintf(response, resp_size,
                              "{\"status\":\"ok\",\"count\":%d,\"sessions\":[", count);
        for (int i = 0; i < count && offset < (int)resp_size - 100; i++) {
            offset += snprintf(response + offset, resp_size - offset,
                               "%s{\"id\":%d,\"name\":\"%s\",\"pid\":%d}",
                               i > 0 ? "," : "",
                               sessions[i].id, sessions[i].name, sessions[i].pid);
        }
        snprintf(response + offset, resp_size - offset, "]}");
    }
    else if (strcmp(cmd, "container_create") == 0) {
        char *name = extract_field(cmd_json, "name");
        char *pw = extract_field(cmd_json, "password");
        int size = extract_int(cmd_json, "size");
        if (!name || !pw || size <= 0) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing name, size, or password\"}");
        } else {
            int ret = container_create(name, (size_t)size, pw);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(name);
        if (pw) { sodium_memzero(pw, strlen(pw)); free(pw); }
    }
    else if (strcmp(cmd, "container_open") == 0) {
        char *name = extract_field(cmd_json, "name");
        char *pw = extract_field(cmd_json, "password");
        if (!name || !pw) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing name or password\"}");
        } else {
            int ret = container_open(name, pw);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(name);
        if (pw) { sodium_memzero(pw, strlen(pw)); free(pw); }
    }
    else if (strcmp(cmd, "container_close") == 0) {
        char *name = extract_field(cmd_json, "name");
        if (!name) {
            snprintf(response, resp_size,
                     "{\"status\":\"error\",\"msg\":\"missing name\"}");
        } else {
            int ret = container_close(name);
            snprintf(response, resp_size,
                     "{\"status\":\"%s\"}", ret == 0 ? "ok" : "error");
        }
        free(name);
    }
    else if (strcmp(cmd, "container_list") == 0) {
        ContainerInfo containers[CONTAINER_MAX_ACTIVE];
        int count = 0;
        container_list(containers, &count);

        int offset = snprintf(response, resp_size,
                              "{\"status\":\"ok\",\"count\":%d,\"containers\":[", count);
        for (int i = 0; i < count && offset < (int)resp_size - 100; i++) {
            offset += snprintf(response + offset, resp_size - offset,
                               "%s{\"name\":\"%s\",\"state\":%d}",
                               i > 0 ? "," : "",
                               containers[i].name, containers[i].state);
        }
        snprintf(response + offset, resp_size - offset, "]}");
    }
    else if (strcmp(cmd, "emergency_wipe") == 0) {
        syslog(LOG_CRIT, "⚠ EMERGENCY WIPE triggered!");
        session_destroy_all();
        container_close_all();
        keystore_emergency_wipe();
        secure_emergency_wipe();
        snprintf(response, resp_size,
                 "{\"status\":\"ok\",\"msg\":\"all data wiped\"}");
    }
    else {
        snprintf(response, resp_size,
                 "{\"status\":\"error\",\"msg\":\"unknown command: %s\"}", cmd);
    }

    free(cmd);
}

/* ── Client handler ──────────────────────────────────────────── */

static void *client_handler(void *arg)
{
    int client_fd = *(int *)arg;
    free(arg);

    char cmd_buf[CMD_BUF_SIZE];
    ssize_t nread = read(client_fd, cmd_buf, sizeof(cmd_buf) - 1);

    if (nread > 0) {
        cmd_buf[nread] = '\0';

        char response[RESP_BUF_SIZE];
        handle_command(cmd_buf, response, sizeof(response));

        write(client_fd, response, strlen(response));
    }

    close(client_fd);
    return NULL;
}

/* ── Main ────────────────────────────────────────────────────── */

int main(void)
{
    openlog("crypticd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "CrypticEngine daemon starting...");

    /* Initialize engine */
    if (cryptic_init() != 0) {
        syslog(LOG_ERR, "Failed to initialize CrypticEngine");
        return 1;
    }

    /* Set up signal handlers */
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Remove stale socket */
    unlink(CRYPTICD_SOCKET_PATH);

    /* Create Unix socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CRYPTICD_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        syslog(LOG_ERR, "bind() failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }

    /* Only root and securez group can access */
    chmod(CRYPTICD_SOCKET_PATH, 0660);

    if (listen(server_fd, MAX_CLIENTS) != 0) {
        syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }

    syslog(LOG_INFO, "CrypticEngine daemon v%s listening on %s",
           CRYPTIC_VERSION_STRING, CRYPTICD_SOCKET_PATH);

    /* Notify systemd we're ready (sd_notify) */
    const char *notify_socket = getenv("NOTIFY_SOCKET");
    if (notify_socket) {
        int nfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (nfd >= 0) {
            struct sockaddr_un naddr;
            memset(&naddr, 0, sizeof(naddr));
            naddr.sun_family = AF_UNIX;
            strncpy(naddr.sun_path, notify_socket, sizeof(naddr.sun_path) - 1);
            if (naddr.sun_path[0] == '@') naddr.sun_path[0] = '\0';
            sendto(nfd, "READY=1", 7, 0,
                   (struct sockaddr *)&naddr, sizeof(naddr));
            close(nfd);
        }
    }

    /* Accept loop */
    while (daemon_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
            continue;
        }

        /* Handle each client in a thread */
        pthread_t thread;
        int *fd_arg = malloc(sizeof(int));
        if (!fd_arg) {
            close(client_fd);
            continue;
        }
        *fd_arg = client_fd;

        if (pthread_create(&thread, NULL, client_handler, fd_arg) != 0) {
            close(client_fd);
            free(fd_arg);
        } else {
            pthread_detach(thread);
        }
    }

    /* Clean shutdown */
    syslog(LOG_INFO, "Shutting down — wiping all keys...");
    close(server_fd);
    unlink(CRYPTICD_SOCKET_PATH);
    cryptic_shutdown();

    syslog(LOG_INFO, "CrypticEngine daemon stopped");
    closelog();

    return 0;
}
