/*
 * SecureZ+ OS — CrypticEngine
 * secure_memory.c — Hardened memory management
 *
 * Uses libsodium's secure memory primitives (sodium_malloc, sodium_memzero)
 * plus Linux-specific madvise for core dump prevention.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "secure_memory.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

/* ── Allocation Tracker ──────────────────────────────────────── */

typedef struct alloc_node {
    void              *ptr;
    size_t             size;
    struct alloc_node *next;
} AllocNode;

static AllocNode     *alloc_list = NULL;
static pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t          alloc_count = 0;
static size_t          alloc_total_bytes = 0;
static int             initialized = 0;

/* ── Internal helpers ────────────────────────────────────────── */

static void tracker_add(void *ptr, size_t size)
{
    /* Allocate tracker node with standard malloc (not secure — it's metadata) */
    AllocNode *node = malloc(sizeof(AllocNode));
    if (!node) return;

    node->ptr  = ptr;
    node->size = size;

    pthread_mutex_lock(&alloc_mutex);
    node->next = alloc_list;
    alloc_list = node;
    alloc_count++;
    alloc_total_bytes += size;
    pthread_mutex_unlock(&alloc_mutex);
}

static void tracker_remove(void *ptr, size_t size)
{
    pthread_mutex_lock(&alloc_mutex);

    AllocNode **current = &alloc_list;
    while (*current) {
        if ((*current)->ptr == ptr) {
            AllocNode *to_free = *current;
            *current = to_free->next;
            alloc_count--;
            alloc_total_bytes -= size;
            free(to_free);
            pthread_mutex_unlock(&alloc_mutex);
            return;
        }
        current = &(*current)->next;
    }

    pthread_mutex_unlock(&alloc_mutex);
}

/* ── Public API ──────────────────────────────────────────────── */

int secure_memory_init(void)
{
    if (initialized) return 0;

    if (sodium_init() < 0) {
        fprintf(stderr, "[SecureMemory] Failed to initialize libsodium\n");
        return -1;
    }

    initialized = 1;
    return 0;
}

void secure_memory_shutdown(void)
{
    if (!initialized) return;

    /* Wipe and free all tracked allocations */
    secure_emergency_wipe();
    initialized = 0;
}

void *secure_alloc(size_t size)
{
    if (!initialized || size == 0) {
        errno = EINVAL;
        return NULL;
    }

    /*
     * sodium_malloc provides:
     *  - Guard pages before and after the allocation
     *  - Memory is zeroed on allocation
     *  - Memory is locked (mlock) — won't be swapped to disk
     *  - Canary values for overflow detection
     */
    void *ptr = sodium_malloc(size);
    if (!ptr) {
        fprintf(stderr, "[SecureMemory] Failed to allocate %zu secure bytes\n", size);
        return NULL;
    }

    /*
     * Also tell the kernel not to include this memory in core dumps.
     * sodium_malloc already does mlock, but we add MADV_DONTDUMP explicitly.
     */
    madvise(ptr, size, MADV_DONTDUMP);

    /* Track for emergency wipe */
    tracker_add(ptr, size);

    return ptr;
}

void secure_free(void *ptr, size_t size)
{
    if (!ptr) return;

    /* Remove from tracker first */
    tracker_remove(ptr, size);

    /*
     * sodium_free provides:
     *  - Guaranteed zeroing of the memory
     *  - Unlock (munlock)
     *  - Actual deallocation
     */
    sodium_free(ptr);
}

void secure_wipe(void *ptr, size_t size)
{
    if (!ptr || size == 0) return;

    /*
     * sodium_memzero is guaranteed not to be optimized away
     * by the compiler. It uses volatile operations or compiler
     * barriers internally.
     */
    sodium_memzero(ptr, size);
}

void secure_emergency_wipe(void)
{
    pthread_mutex_lock(&alloc_mutex);

    AllocNode *current = alloc_list;
    while (current) {
        AllocNode *next = current->next;

        /* Wipe and free the secure allocation */
        sodium_free(current->ptr);

        /* Free the tracker node */
        free(current);

        current = next;
    }

    alloc_list = NULL;
    alloc_count = 0;
    alloc_total_bytes = 0;

    pthread_mutex_unlock(&alloc_mutex);

    fprintf(stderr, "[SecureMemory] ⚠ EMERGENCY WIPE COMPLETE — all secure memory destroyed\n");
}

void secure_memory_stats(size_t *count, size_t *total_bytes)
{
    pthread_mutex_lock(&alloc_mutex);
    if (count)       *count = alloc_count;
    if (total_bytes) *total_bytes = alloc_total_bytes;
    pthread_mutex_unlock(&alloc_mutex);
}

int secure_memory_protect_readonly(void *ptr)
{
    if (!ptr) return -1;
    return sodium_mprotect_readonly(ptr);
}

int secure_memory_protect_readwrite(void *ptr)
{
    if (!ptr) return -1;
    return sodium_mprotect_readwrite(ptr);
}
