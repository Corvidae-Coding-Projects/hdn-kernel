/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_RESUME_H
#define _ASM_X86_HDN_RAP_RESUME_H

#define HDN_RAP_RESUME_S3 1
#define HDN_RAP_RESUME_IMAGE 2
#define HDN_RAP_PM_MSRS 128

#ifndef __ASSEMBLY__
#include <asm/suspend.h>

/* Consumed by the closed hibernation assembly handoff. No live pointer is
 * reloaded from the ordinary snapshot globals after the admission call. */
struct hdn_rap_hibernate_launch {
	unsigned long entry, cr3, temporary_cr3, code, pages, cr4;
};

#if defined(CONFIG_SECURITY_HARDENING_RAP) && defined(CONFIG_PM_SLEEP)
/* Platform MSR identities are collected during initialization, then sealed.
 * Resume values are read from hardware and copied into separate sealed state. */
extern u32 hdn_rap_pm_msr_ids[HDN_RAP_PM_MSRS];
extern unsigned long hdn_rap_pm_msr_count;
void hdn_rap_processor_save(const struct saved_context *context);
const struct saved_context *hdn_rap_processor_state(void);
void hdn_rap_processor_finish(void);
void hdn_rap_resume_save(unsigned long kind, unsigned long sp);
const struct saved_context *hdn_rap_resume_restore(unsigned long kind);
#ifdef CONFIG_HIBERNATION
int hdn_rap_hibernate_header(unsigned long entry, unsigned long physical,
		unsigned long cr3);
int hdn_rap_hibernate_prepare(unsigned long temporary_cr3, unsigned long code);
int hdn_rap_hibernate_copy_publish(unsigned long pages);
const struct hdn_rap_hibernate_launch *hdn_rap_hibernate_enter(void);
void hdn_rap_hibernate_release(void);
#endif
#endif
#endif
#endif
