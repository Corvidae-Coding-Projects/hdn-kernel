// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/hdn_capabilities.h>
#include <linux/hdn_slab.h>
#include <linux/hdn_alloc.h>
#include <linux/hdn_jitter.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>

static const char *const capability_names[] = {
#define HDN_CAP_NAME(symbol, name) [HDN_CAP_##symbol] = #name,
	HDN_CAPABILITY_LIST(HDN_CAP_NAME)
#undef HDN_CAP_NAME
};
static_assert(ARRAY_SIZE(capability_names) == HDN_CAP__MAX);
static_assert(HDN_CAP__MAX < 32);

#ifndef CONFIG_HDN_ARCH_CONTRACT
static struct hdn_capability_record unsupported(enum hdn_capability_id id)
{
	return hdn_cap_record(id, HDN_CAP_UNSUPPORTED, HDN_CAP_BACKING_NONE);
}
const struct hdn_arch_contract hdn_arch_contract = {
	.name = "unsupported", .query = unsupported,
};
#endif

bool hdn_capability_record_valid(enum hdn_capability_id id,
				 const struct hdn_capability_record *record)
{
	return (unsigned int)id < HDN_CAP__MAX && record && record->id == id &&
	       record->state <= HDN_CAP_NOT_APPLICABLE &&
	       record->backing <= HDN_CAP_BACKING_HYBRID;
}

bool hdn_capability_state_satisfies_requirement(enum hdn_capability_state state)
{
	return state == HDN_CAP_ENFORCED || state == HDN_CAP_NOT_APPLICABLE;
}

struct hdn_capability_record hdn_capability(enum hdn_capability_id id)
{
	struct hdn_capability_record cap;

	switch (id) {
	case HDN_CAP_IMMUTABLE_POLICY:
		return hdn_cap_option(id, IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL));
	case HDN_CAP_SYSFS_VIEW:
		return hdn_cap_option(id, IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSFS_VIEW));
	case HDN_CAP_TYPED_SLAB:
#ifdef CONFIG_SECURITY_HARDENING_AUTOSLAB
	{
		struct hdn_alloc_stats stats;

		hdn_alloc_get_stats(&stats);
		return hdn_cap_record(id, stats.ready ? HDN_CAP_ENFORCED :
				     HDN_CAP_INITIALIZING, HDN_CAP_BACKING_SOFTWARE);
	}
#else
		return hdn_cap_option(id, false);
#endif
	case HDN_CAP_CRITICAL_JITTER:
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER
	{
		struct hdn_jitter_stats stats;

		hdn_jitter_get_stats(&stats);
		return hdn_cap_record(id, !stats.entropy_ready ? HDN_CAP_INITIALIZING :
				     stats.early_live ? HDN_CAP_DEGRADED :
				     HDN_CAP_ENFORCED, HDN_CAP_BACKING_SOFTWARE);
	}
#else
		return hdn_cap_option(id, false);
#endif
	case HDN_CAP_SLAB_LAYOUT:
#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT
	{
		struct hdn_slab_layout_stats stats;

		hdn_slab_layout_stats(&stats);
		return hdn_cap_record(id, stats.active ? HDN_CAP_ENFORCED :
				     HDN_CAP_INITIALIZING, HDN_CAP_BACKING_SOFTWARE);
	}
#else
		return hdn_cap_option(id, false);
#endif
	default:
		cap = hdn_arch_contract.query(id);
		if (!hdn_capability_record_valid(id, &cap))
			return hdn_cap_record(id, HDN_CAP_UNDECLARED, HDN_CAP_BACKING_NONE);
		return cap;
	}
}

int hdn_capabilities_require(u32 required)
{
	unsigned int id;

	if (required & ~HDN_CAP_KNOWN_MASK)
		return -EINVAL;
	for (id = 0; id < HDN_CAP__MAX; id++) {
		struct hdn_capability_record cap;

		if (!(required & HDN_CAP_REQUIRED(id)))
			continue;
		cap = hdn_capability(id);
		if (!hdn_capability_state_satisfies_requirement(cap.state))
			return -EOPNOTSUPP;
	}
	return 0;
}

void hdn_capabilities_show(struct seq_file *m)
{
	static const char *const states[] = {
		"undeclared", "unsupported", "disabled", "initializing", "degraded",
		"enforced", "not-applicable",
	};
	static const char *const backing[] = { "none", "hardware", "software", "hybrid" };
	unsigned int id;

	seq_printf(m, "capability_version: %u\n", HDN_CAPABILITY_ABI_VERSION);
	seq_printf(m, "capability_architecture: %s\n", hdn_arch_contract.name);
	for (id = 0; id < HDN_CAP__MAX; id++) {
		struct hdn_capability_record cap = hdn_capability(id);

		seq_printf(m, "capability.%s: %s,%s\n", capability_names[id],
			   states[cap.state], backing[cap.backing]);
	}
}
