// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/sysctl.h>
#include <linux/minmax.h>

#define HDN_MMAP_MIN_ADDR_FLOOR (64UL * 1024UL)

/* amount of vm to protect from userspace access by both DAC and the LSM*/
unsigned long mmap_min_addr;
/* amount of vm to protect from userspace using CAP_SYS_RAWIO (DAC) */
unsigned long dac_mmap_min_addr = CONFIG_DEFAULT_MMAP_MIN_ADDR;
/* amount of vm to protect from userspace using the LSM = CONFIG_LSM_MMAP_MIN_ADDR */

static unsigned long hdn_mmap_min_addr_floor = HDN_MMAP_MIN_ADDR_FLOOR;

static void hdn_clamp_mmap_min_addr(void)
{
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MMAP_MIN_ADDR) &&
	    dac_mmap_min_addr < hdn_mmap_min_addr_floor)
		dac_mmap_min_addr = hdn_mmap_min_addr_floor;
}

/*
 * Update mmap_min_addr = max(dac_mmap_min_addr, CONFIG_LSM_MMAP_MIN_ADDR)
 */
static void update_mmap_min_addr(void)
{
	hdn_clamp_mmap_min_addr();

#ifdef CONFIG_LSM_MMAP_MIN_ADDR
	mmap_min_addr = umax(dac_mmap_min_addr, CONFIG_LSM_MMAP_MIN_ADDR);
#else
	mmap_min_addr = dac_mmap_min_addr;
#endif
}

/*
 * sysctl handler which just sets dac_mmap_min_addr = the new value and then
 * calls update_mmap_min_addr() so non MAP_FIXED hints get rounded properly
 */
int mmap_min_addr_handler(const struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table hdn_table;
	unsigned long floor;
	int ret;

	if (write && !capable(CAP_SYS_RAWIO))
		return -EPERM;

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MMAP_MIN_ADDR)) {
		hdn_table = *table;
		floor = hdn_mmap_min_addr_floor;
		if (table->extra1)
			floor = umax(floor, *(unsigned long *)table->extra1);
		hdn_table.extra1 = &floor;
		table = &hdn_table;
	}

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);

	update_mmap_min_addr();

	return ret;
}

static const struct ctl_table min_addr_sysctl_table[] = {
	{
		.procname	= "mmap_min_addr",
		.data		= &dac_mmap_min_addr,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= mmap_min_addr_handler,
	},
};

static int __init mmap_min_addr_init(void)
{
	register_sysctl_init("vm", min_addr_sysctl_table);
	update_mmap_min_addr();

	return 0;
}
pure_initcall(mmap_min_addr_init);
