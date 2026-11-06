/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_LATENT_ENTROPY_H
#define _LINUX_HDN_LATENT_ENTROPY_H

#include <linux/types.h>

/* Must match the compiler's closed site table. Never a userspace ABI. */
enum hdn_latent_site {
	HDN_LATENT_BOOT,
	HDN_LATENT_FORK,
	HDN_LATENT_INTERRUPT,
	HDN_LATENT_NR_SITES,
};

#ifdef CONFIG_SECURITY_HARDENING_LATENT_ENTROPY
void hdn_latent_mix(unsigned long trace, unsigned int site);
void hdn_random_mix_nocredit(const void *buf, size_t len);
void hdn_latent_reseed(void);
#else
static inline void hdn_latent_reseed(void) { }
#endif

#ifdef CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST
/* Built-in tests only: no export, sysctl, boot parameter, or policy control. */
int hdn_latent_test_begin(u64 seed);
u64 hdn_latent_test_end(void);
#endif

#endif
