/*
 * SecureZ+ OS — CrypticEngine
 * secure_memory.h — Hardened memory management
 *
 * Provides secure memory allocations that:
 *  - Cannot be swapped to disk (mlock)
 *  - Cannot appear in core dumps (MADV_DONTDUMP)
 *  - Are guaranteed zeroed on free (not optimized away)
 *  - Are tracked for emergency bulk-wipe
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#ifndef SECUREZ_SECURE_MEMORY_H
#define SECUREZ_SECURE_MEMORY_H

#include <stddef.h>

/*
 * Initialize the secure memory subsystem.
 * Must be called once at startup (after sodium_init).
 * Sets up the allocation tracker.
 *
 * @return 0 on success, -1 on failure
 */
int secure_memory_init(void);

/*
 * Shut down the secure memory subsystem.
 * Wipes and frees ALL tracked secure allocations.
 */
void secure_memory_shutdown(void);

/*
 * Allocate secure memory.
 *
 * The returned memory is:
 *  - Zeroed on allocation
 *  - Locked in RAM (mlock — will not be swapped)
 *  - Excluded from core dumps (madvise MADV_DONTDUMP)
 *  - Guarded with canary pages (sodium_malloc)
 *  - Tracked for bulk emergency wipe
 *
 * @param size  Number of bytes to allocate
 * @return Pointer to secure memory, or NULL on failure
 */
void *secure_alloc(size_t size);

/*
 * Free secure memory.
 *
 * The memory is:
 *  - Zeroed before freeing (guaranteed, not optimizable)
 *  - Unlocked from RAM
 *  - Removed from the allocation tracker
 *
 * @param ptr   Pointer from secure_alloc
 * @param size  Size of the allocation (must match)
 */
void secure_free(void *ptr, size_t size);

/*
 * Wipe memory securely (guaranteed not to be optimized away).
 *
 * Uses sodium_memzero internally — resistant to compiler dead-store
 * elimination. Use this for ANY sensitive data on the stack or in
 * non-secure allocations.
 *
 * @param ptr   Memory to wipe
 * @param size  Number of bytes to wipe
 */
void secure_wipe(void *ptr, size_t size);

/*
 * Emergency wipe: zero and free ALL tracked secure allocations.
 *
 * Called by CrypticEngine daemon on tamper detection.
 * After this call, all secure memory is gone. The engine must
 * be re-initialized.
 */
void secure_emergency_wipe(void);

/*
 * Get statistics about secure memory usage.
 *
 * @param count       Output: number of active secure allocations
 * @param total_bytes Output: total bytes in secure allocations
 */
void secure_memory_stats(size_t *count, size_t *total_bytes);

/*
 * Mark memory as read-only (cannot be written to).
 * Useful for storing verified keys.
 *
 * @param ptr  Pointer from secure_alloc
 * @return 0 on success, -1 on failure
 */
int secure_memory_protect_readonly(void *ptr);

/*
 * Restore write access to read-only secure memory.
 *
 * @param ptr  Pointer from secure_alloc
 * @return 0 on success, -1 on failure
 */
int secure_memory_protect_readwrite(void *ptr);

#endif /* SECUREZ_SECURE_MEMORY_H */
