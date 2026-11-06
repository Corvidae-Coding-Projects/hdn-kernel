// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hdn_capabilities.h>

static struct hdn_capability_record query(enum hdn_capability_id id)
{
	switch (id) {
	case HDN_CAP_USER_ACCESS:
		/* Native uaccess brackets access with supervisor SUM; audit is separate. */
		return hdn_cap_record(id, IS_ENABLED(CONFIG_MMU) ? HDN_CAP_ENFORCED :
			HDN_CAP_UNSUPPORTED, IS_ENABLED(CONFIG_MMU) ?
			HDN_CAP_BACKING_HARDWARE : HDN_CAP_BACKING_NONE);
	case HDN_CAP_KERNEL_WX:
	case HDN_CAP_STATIC_ALIASES:
		return hdn_cap_record(id, IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) ?
			HDN_CAP_DEGRADED : HDN_CAP_DISABLED,
			IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) ? HDN_CAP_BACKING_SOFTWARE :
			HDN_CAP_BACKING_NONE);
	case HDN_CAP_FORWARD_CFI:
		return hdn_cap_record(id, IS_ENABLED(CONFIG_CFI) ? HDN_CAP_DEGRADED :
			HDN_CAP_UNSUPPORTED, IS_ENABLED(CONFIG_CFI) ?
			HDN_CAP_BACKING_SOFTWARE : HDN_CAP_BACKING_NONE);
	case HDN_CAP_DESCRIPTOR_ALIASES:
		return hdn_cap_record(id, HDN_CAP_NOT_APPLICABLE, HDN_CAP_BACKING_NONE);
	case HDN_CAP_EXECMEM_ALIASES:
	case HDN_CAP_PAGE_TABLE_ALIASES:
	case HDN_CAP_FIRMWARE_WX:
	case HDN_CAP_INIT_RETIREMENT:
	case HDN_CAP_ACCESS_WINDOW_VALIDATION:
	case HDN_CAP_RETURN_CFI:
	case HDN_CAP_PRIVATE_STACK_ALIASES:
	case HDN_CAP_BPF_DOMAIN:
	case HDN_CAP_BPF_RETIREMENT:
	case HDN_CAP_TRANSIENT_DATAFLOW:
	case HDN_CAP_TYPED_SLAB:
	case HDN_CAP_CRITICAL_JITTER:
		return hdn_cap_record(id, HDN_CAP_UNSUPPORTED, HDN_CAP_BACKING_NONE);
	case HDN_CAP_IMMUTABLE_POLICY:
	case HDN_CAP_SLAB_LAYOUT:
	case HDN_CAP_SYSFS_VIEW:
	case HDN_CAP__MAX:
		break;
	}
	return hdn_cap_record(id, HDN_CAP_UNDECLARED, HDN_CAP_BACKING_NONE);
}

const struct hdn_arch_contract hdn_arch_contract = {
	.name = "riscv", .query = query,
};
