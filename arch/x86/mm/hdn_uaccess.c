// SPDX-License-Identifier: GPL-2.0-only
#include <linux/buildid.h>
#include <linux/hardening.h>
#include <linux/hdn_uaccess.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include <asm/hdn_text.h>
#include <asm/sections.h>

/* A diagnostic identifier, never an authorization token. Hash fixed-width
 * build ID + domain + little-endian text offset. No KASLR address or user
 * pointer is stored. Zero explicitly means an unidentified code region. */
static u64 uderef_code_id(const unsigned char *build_id, u8 domain, u64 offset)
{
	u64 hash = 14695981039346656037ULL;
	unsigned int i;
	bool present = false;

	if (!build_id)
		return 0;
	for (i = 0; i < BUILD_ID_SIZE_MAX; i++) {
		present |= build_id[i] != 0;
		hash = (hash ^ build_id[i]) * 1099511628211ULL;
	}
	if (!present)
		return 0;
	hash = (hash ^ domain) * 1099511628211ULL;
	for (i = 0; i < sizeof(offset); i++) {
		hash = (hash ^ (offset & 0xff)) * 1099511628211ULL;
		offset >>= 8;
	}
	return hash ?: 1;
}

u64 hdn_uderef_site_id(unsigned long ip)
{
#ifdef CONFIG_MODULES
	struct module *mod;
#endif
	u64 id = 0;

	if (ip >= (unsigned long)_stext && ip < (unsigned long)_etext)
		return uderef_code_id(vmlinux_build_id, 0, ip - (unsigned long)_stext);
	if (ip >= (unsigned long)_sinittext && ip < (unsigned long)_einittext)
		return uderef_code_id(vmlinux_build_id, 1, ip - (unsigned long)_sinittext);
#ifdef CONFIG_MODULES
	rcu_read_lock();
	mod = __module_text_address(ip);
	if (mod) {
		for_class_mod_mem_type(type, text) {
			unsigned long start = (unsigned long)mod->mem[type].base;

			if (ip >= start && ip - start < mod->mem[type].size) {
				id = uderef_code_id(module_buildid(mod),
						    type == MOD_TEXT ? 2 : 3, ip - start);
				break;
			}
		}
	}
	rcu_read_unlock();
#endif
	return id;
}

void hdn_uderef_report_fault(unsigned long ip)
{
	u64 id = hdn_uderef_site_id(ip);

	hdn_x86_defer_transition(HDN_TRANS_KERNEL_UACCESS, id,
				 HDN_REASON_KERNEL_USER_ACCESS_DENIED);
	/* A panic may precede mailbox draining; keep a bounded crash marker. */
	pr_err_ratelimited("HDN_UDEREF_DENIED site=%016llx\n", id);
}
