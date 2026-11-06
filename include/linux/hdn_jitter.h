/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_JITTER_H
#define _LINUX_HDN_JITTER_H
#include <linux/slab.h>
#include <linux/hdn_alloc.h>

struct cred;
struct file;
enum hdn_jitter_class {
	HDN_JITTER_NONE,
	HDN_JITTER_CRED,
	HDN_JITTER_FILE,
	HDN_JITTER_BACKING_FILE,
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	HDN_JITTER_TEST,
#endif
	HDN_JITTER_CLASS_MAX,
};
struct hdn_jitter_stats {
	u64 allocations, allocation_failures, retired, released, pressure;
	u64 integrity_failures, early_live;
	u32 quarantined;
	bool entropy_ready;
	struct {
		u64 allocations, allocation_failures, retired, released, pressure;
		u32 quarantined;
	} classes[HDN_JITTER_CLASS_MAX];
};

#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER
struct kmem_cache * __init hdn_jitter_create(enum hdn_jitter_class id,
		const char *name, unsigned int size, unsigned int align,
		enum hdn_alloc_domain domain);
void *hdn_jitter_alloc(struct kmem_cache *cache, gfp_t flags);
void hdn_jitter_free(struct kmem_cache *cache, void *payload);
void hdn_jitter_check_cred(const struct cred *cred);
void hdn_jitter_check_file(const struct file *file);
void hdn_jitter_get_stats(struct hdn_jitter_stats *stats);
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
int hdn_jitter_test_run(unsigned int mode);
#endif
/* A source-declared, immutable identity for static credentials only. */
#define HDN_STATIC_CRED(name) \
	static const struct cred *const __hdn_static_cred_##name \
	__used __section("__hdn_static_creds") __aligned(sizeof(void *)) = &(name)
#else
static inline void *hdn_jitter_alloc(struct kmem_cache *cache, gfp_t flags)
{
	return kmem_cache_alloc(cache, flags);
}
static inline void hdn_jitter_free(struct kmem_cache *cache, void *payload)
{
	kmem_cache_free(cache, payload);
}
static inline void hdn_jitter_check_cred(const struct cred *cred) { }
static inline void hdn_jitter_check_file(const struct file *file) { }
#define HDN_STATIC_CRED(name)
#endif
#endif
