/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_CAPABILITIES_H
#define _LINUX_HDN_CAPABILITIES_H
#include <linux/types.h>
#include <uapi/linux/hardening.h>

struct seq_file;
struct hdn_arch_contract {
	const char *name;
	struct hdn_capability_record (*query)(enum hdn_capability_id id);
};
extern const struct hdn_arch_contract hdn_arch_contract;
struct hdn_capability_record hdn_capability(enum hdn_capability_id id);
bool hdn_capability_record_valid(enum hdn_capability_id id,
				 const struct hdn_capability_record *record);
bool hdn_capability_state_satisfies_requirement(enum hdn_capability_state state);
int hdn_capabilities_require(u32 required);
void hdn_capabilities_show(struct seq_file *m);

static inline struct hdn_capability_record
hdn_cap_record(enum hdn_capability_id id, enum hdn_capability_state state,
	       enum hdn_capability_backing backing)
{
	return (struct hdn_capability_record){ id, state, backing };
}
static inline struct hdn_capability_record
hdn_cap_option(enum hdn_capability_id id, bool enabled)
{
	return hdn_cap_record(id, enabled ? HDN_CAP_ENFORCED : HDN_CAP_DISABLED,
			     enabled ? HDN_CAP_BACKING_SOFTWARE : HDN_CAP_BACKING_NONE);
}
#endif
