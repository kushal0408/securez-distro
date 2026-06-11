/*
 * SecureZ+ OS — CrypticEngine
 * secure_session.h — Isolated secure execution environments
 *
 * Secure sessions use REAL Linux security primitives:
 *  - PID namespace (process isolation)
 *  - Mount namespace (private filesystem view)
 *  - Network namespace (isolated networking)
 *  - UTS namespace (separate hostname)
 *  - tmpfs (RAM-only storage — data never touches disk)
 *  - cgroups v2 (resource limits)
 *
 * These are the REAL security boundaries.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_SECURE_SESSION_H
#define SECUREZ_SECURE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define SESSION_MAX_ACTIVE    16
#define SESSION_NAME_MAX      64
#define SESSION_DEFAULT_MEM   (512 * 1024 * 1024)  /* 512 MB default limit */

typedef enum {
    SESSION_STATE_INACTIVE = 0,
    SESSION_STATE_STARTING,
    SESSION_STATE_ACTIVE,
    SESSION_STATE_STOPPING,
    SESSION_STATE_ERROR
} SessionState;

typedef struct {
    int             id;                         /* Session ID (1-based) */
    char            name[SESSION_NAME_MAX];     /* Human-readable name */
    pid_t           pid;                        /* PID of session init process */
    SessionState    state;                      /* Current state */
    time_t          start_time;                 /* When session was created */
    size_t          memory_limit;               /* cgroup memory limit */
    char            tmpfs_path[256];            /* RAM-only mount point */
    char            cgroup_path[256];           /* cgroup directory */
    int             has_network;                /* 0 = isolated, 1 = connected */
} SessionInfo;

/*
 * Initialize the secure session subsystem.
 * Sets up cgroup hierarchy and tmpfs base directory.
 *
 * @return 0 on success, -1 on failure
 */
int session_init(void);

/*
 * Shut down the session subsystem.
 * Destroys ALL active sessions (wipes tmpfs, kills processes).
 */
void session_shutdown(void);

/*
 * Create a new secure session.
 *
 * The session runs in isolated namespaces with its own:
 *  - Process tree (PID namespace)
 *  - Filesystem view (mount namespace with tmpfs)
 *  - Network (isolated by default — no connectivity)
 *  - Hostname (set to "securez-session")
 *
 * @param name          Human-readable session name (or NULL for auto)
 * @param memory_limit  Memory limit in bytes (0 for default 512MB)
 * @param allow_network If non-zero, session gets network access
 * @return Session ID (>0) on success, -1 on failure
 */
int session_create(const char *name, size_t memory_limit, int allow_network);

/*
 * Destroy a secure session.
 *
 * This:
 *  1. Kills all processes in the session's PID namespace
 *  2. Unmounts tmpfs (RAM-only data disappears)
 *  3. Removes cgroup
 *  4. Wipes all session metadata from memory
 *
 * @param session_id  Session ID from session_create
 * @return 0 on success, -1 on failure
 */
int session_destroy(int session_id);

/*
 * Get information about a session.
 *
 * @param session_id  Session ID
 * @param info        Output: SessionInfo struct
 * @return 0 on success, -1 if session not found
 */
int session_get_info(int session_id, SessionInfo *info);

/*
 * List all active sessions.
 *
 * @param sessions  Output array (must hold SESSION_MAX_ACTIVE entries)
 * @param count     Output: number of active sessions
 * @return 0 on success, -1 on failure
 */
int session_list(SessionInfo *sessions, int *count);

/*
 * Execute a command inside a secure session.
 *
 * @param session_id  Session to execute in
 * @param argv        Command and arguments (NULL-terminated)
 * @return PID of the command process, or -1 on failure
 */
pid_t session_exec(int session_id, char *const argv[]);

/*
 * Check if the current process is running inside a secure session.
 *
 * @return 1 if in session, 0 if not
 */
int session_is_active(void);

/*
 * Destroy ALL active sessions immediately.
 * Used for emergency wipe.
 */
void session_destroy_all(void);

#endif /* SECUREZ_SECURE_SESSION_H */
