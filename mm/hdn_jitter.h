/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _MM_HDN_JITTER_H
#define _MM_HDN_JITTER_H
#include <linux/hdn_jitter.h>

#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER
void hdn_jitter_reject_generic(struct kmem_cache *cache);
/* Both ends are internal to MM. The backing pointer never reaches its owner. */
void hdn_jitter_release_backing(struct kmem_cache *cache, void *backing);
void hdn_jitter_abort_backing(struct kmem_cache *cache, void *backing);
bool hdn_jitter_release_allowed(struct kmem_cache *cache, void *backing);
size_t hdn_jitter_usable_size(const void *payload);
void hdn_jitter_dump(const void *pointer);
#else
static inline void hdn_jitter_reject_generic(struct kmem_cache *cache) { }
static inline void hdn_jitter_dump(const void *pointer) { }
#endif
#endif
