// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hdn_capabilities.h>
#include <asm/cpufeature.h>

static struct hdn_capability_record query(enum hdn_capability_id id)
{
	switch (id) {
	case HDN_CAP_USER_ACCESS:
		if (system_uses_hw_pan())
			return hdn_cap_record(id, HDN_CAP_ENFORCED, HDN_CAP_BACKING_HARDWARE);
		if (system_uses_ttbr0_pan())
			return hdn_cap_record(id, HDN_CAP_ENFORCED, HDN_CAP_BACKING_SOFTWARE);
		return hdn_cap_record(id, HDN_CAP_UNSUPPORTED, HDN_CAP_BACKING_NONE);
	case HDN_CAP_KERNEL_WX:
	case HDN_CAP_STATIC_ALIASES:
		return hdn_cap_record(id, IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) ?
			HDN_CAP_DEGRADED : HDN_CAP_DISABLED,
			IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) ? HDN_CAP_BACKING_SOFTWARE :
			HDN_CAP_BACKING_NONE);
	case HDN_CAP_FORWARD_CFI:
	case HDN_CAP_RETURN_CFI:
	{
		bool enabled = id == HDN_CAP_FORWARD_CFI ? IS_ENABLED(CONFIG_CFI) :
			IS_ENABLED(CONFIG_ARM64_PTR_AUTH_KERNEL);

		return hdn_cap_record(id, enabled ? HDN_CAP_DEGRADED :
			HDN_CAP_UNSUPPORTED, !enabled ? HDN_CAP_BACKING_NONE :
			id == HDN_CAP_FORWARD_CFI ? HDN_CAP_BACKING_SOFTWARE :
			HDN_CAP_BACKING_HARDWARE);
	}
	case HDN_CAP_DESCRIPTOR_ALIASES:
		return hdn_cap_record(id, HDN_CAP_NOT_APPLICABLE, HDN_CAP_BACKING_NONE);
	case HDN_CAP_EXECMEM_ALIASES:
	case HDN_CAP_PAGE_TABLE_ALIASES:
	case HDN_CAP_FIRMWARE_WX:
	case HDN_CAP_INIT_RETIREMENT:
	case HDN_CAP_ACCESS_WINDOW_VALIDATION:
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
	.name = "arm64", .query = query,
};
