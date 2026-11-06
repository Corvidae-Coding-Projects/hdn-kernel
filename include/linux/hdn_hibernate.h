/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_HIBERNATE_H
#define _LINUX_HDN_HIBERNATE_H

#include <linux/suspend.h>
#include <asm/page.h>

/* Safe-page storage: these pages cannot be destinations of the image copy.
 * Each page has independent physical ownership until snapshot teardown. */
struct hdn_hibernate_copy_page {
	struct hdn_hibernate_copy_page *next;
	unsigned long count;
	struct pbe entries[(PAGE_SIZE - 2 * sizeof(unsigned long)) / sizeof(struct pbe)];
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
int hdn_rap_hibernate_copy_seal(struct hdn_hibernate_copy_page *pages,
		unsigned long count);
#endif
#endif
