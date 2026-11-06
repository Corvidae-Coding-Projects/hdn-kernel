/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _HDN_SEAL_H
#define _HDN_SEAL_H

#include <linux/err.h>
#include <linux/types.h>

struct hdn_seal;

enum hdn_seal_reader_discipline {
	HDN_SEAL_READER_IMMORTAL,
	HDN_SEAL_READER_RCU_REFCOUNT,
};

enum hdn_seal_replacement {
	HDN_SEAL_REPLACE_NONE,
	HDN_SEAL_REPLACE_COPY_RCU,
};

struct hdn_seal_type {
	u32 id;
	size_t minimum_size;
	size_t maximum_size;
	size_t alignment;
	enum hdn_seal_reader_discipline readers;
	enum hdn_seal_replacement replacement;
	int (*validate)(const void *data, size_t size);
	struct hdn_seal *(*handle)(const void *data);
};

struct hdn_seal_stats {
	u64 allocations;
	u64 live_objects;
	u64 live_pages;
	u64 live_payload_bytes;
	u64 live_granule_bytes;
	u64 seal_operations;
	u64 publications;
	u64 replacements;
	u64 retirements;
	u64 discards;
	u64 rejections;
	u64 allocation_failures;
	u64 replacement_total_ns;
	u64 replacement_max_ns;
};

/* Called under the consumer's publication serialization. It must atomically
 * publish @next and return the complete payload evicted from all publication
 * slots, or NULL when no object became unreachable. */
typedef const void *(*hdn_seal_publish_fn)(void *context, const void *next);

/* Closed set of in-tree types; descriptors and payloads are never exported. */
extern const struct hdn_seal_type hdn_policy_seal_type;
extern const struct hdn_seal_type hdn_mitigation_seal_type;
#ifdef CONFIG_SECURITY_HARDENING_KERNSEAL_TEST
extern const struct hdn_seal_type hdn_test_seal_type;
#endif

#ifdef CONFIG_SECURITY_HARDENING_KERNSEAL
struct hdn_seal *hdn_seal_create(const struct hdn_seal_type *type, size_t size, int node);
/* The constructing task owns the sole unpublished reference. A successful
 * publish transfers that reference to publication. Replace performs publish,
 * the consumer's atomic pointer update, and retirement as one typed operation.
 * A direct retire requires all published pointers to have been removed under
 * consumer serialization. Read requires the publication reference, an
 * acquired reference, or the RCU read lock that protects publication. */
void *hdn_seal_write(struct hdn_seal *object, const struct hdn_seal_type *type);
const void *hdn_seal_read(const struct hdn_seal *object, const struct hdn_seal_type *type);
int hdn_seal_finish(struct hdn_seal *object, const struct hdn_seal_type *type);
int hdn_seal_publish(struct hdn_seal *object, const struct hdn_seal_type *type);
int hdn_seal_replace(struct hdn_seal *object, const struct hdn_seal_type *type,
		hdn_seal_publish_fn publish, void *context);
int hdn_seal_destroy(struct hdn_seal *object, const struct hdn_seal_type *type);
int hdn_seal_retire(struct hdn_seal *object, const struct hdn_seal_type *type);
/* get requires a live reference or the RCU read lock protecting publication. */
bool __must_check hdn_seal_get(struct hdn_seal *object, const struct hdn_seal_type *type);
void hdn_seal_put(struct hdn_seal *object);
void hdn_seal_get_stats(struct hdn_seal_stats *stats);
#else
static inline struct hdn_seal *hdn_seal_create(const struct hdn_seal_type *type,
		size_t size, int node) { return ERR_PTR(-EOPNOTSUPP); }
static inline void *hdn_seal_write(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return NULL; }
static inline int hdn_seal_finish(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return -EOPNOTSUPP; }
static inline int hdn_seal_publish(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return -EOPNOTSUPP; }
static inline int hdn_seal_replace(struct hdn_seal *object,
		const struct hdn_seal_type *type, hdn_seal_publish_fn publish,
		void *context) { return -EOPNOTSUPP; }
static inline int hdn_seal_destroy(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return -EOPNOTSUPP; }
static inline int hdn_seal_retire(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return -EOPNOTSUPP; }
static inline const void *hdn_seal_read(const struct hdn_seal *object,
		const struct hdn_seal_type *type) { return NULL; }
static inline bool hdn_seal_get(struct hdn_seal *object,
		const struct hdn_seal_type *type) { return false; }
static inline void hdn_seal_put(struct hdn_seal *object) { }
static inline void hdn_seal_get_stats(struct hdn_seal_stats *stats)
{
	*stats = (struct hdn_seal_stats){};
}
#endif
#endif
