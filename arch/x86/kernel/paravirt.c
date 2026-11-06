// SPDX-License-Identifier: GPL-2.0-or-later
/*  Paravirtualization interfaces
    Copyright (C) 2006 Rusty Russell IBM Corporation


    2007 - x86_64 support added by Glauber de Oliveira Costa, Red Hat Inc
*/

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/efi.h>
#include <linux/bcd.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>
#include <linux/pgtable.h>
#include <linux/static_call.h>

#include <asm/bug.h>
#include <asm/paravirt.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/setup.h>
#include <asm/time.h>
#include <asm/pgalloc.h>
#include <asm/irq.h>
#include <asm/delay.h>
#include <asm/fixmap.h>
#include <asm/apic.h>
#include <asm/tlbflush.h>
#include <asm/timer.h>
#include <asm/special_insns.h>
#include <asm/tlb.h>
#include <asm/io_bitmap.h>
#include <asm/gsseg.h>
#include <asm/msr.h>

/* stub always returning 0. */
#ifdef CONFIG_SECURITY_HARDENING_RAP
noinstr unsigned long paravirt_ret0(void) { return 0; }
#else
DEFINE_ASM_FUNC(paravirt_ret0, "xor %eax,%eax", .entry.text);
#endif

void __init default_banner(void)
{
	printk(KERN_INFO "Booting paravirtualized kernel on %s\n",
	       pv_info.name);
}

#ifdef CONFIG_PARAVIRT_XXL
unsigned long pv_native_save_fl(void);
void pv_native_irq_disable(void);
void pv_native_irq_enable(void);
unsigned long pv_native_read_cr2(void);

#ifdef CONFIG_SECURITY_HARDENING_RAP
noinstr u64 _paravirt_ident_64(u64 value) { return value; }
noinstr unsigned long pv_native_save_fl(void) { return native_save_fl(); }
noinstr void pv_native_irq_disable(void) { native_irq_disable(); }
noinstr void pv_native_irq_enable(void) { native_irq_enable(); }
noinstr unsigned long pv_native_read_cr2(void) { return native_read_cr2(); }
#else
DEFINE_ASM_FUNC(_paravirt_ident_64, "mov %rdi, %rax", .text);
DEFINE_ASM_FUNC(pv_native_save_fl, "pushf; pop %rax", .noinstr.text);
DEFINE_ASM_FUNC(pv_native_irq_disable, "cli", .noinstr.text);
DEFINE_ASM_FUNC(pv_native_irq_enable, "sti", .noinstr.text);
DEFINE_ASM_FUNC(pv_native_read_cr2, "mov %cr2, %rax", .noinstr.text);
#endif
#endif

static noinstr void pv_native_safe_halt(void)
{
	native_safe_halt();
}

#ifdef CONFIG_PARAVIRT_XXL
static noinstr void pv_native_write_cr2(unsigned long val)
{
	native_write_cr2(val);
}

static noinstr unsigned long pv_native_read_cr3(void)
{
	return __native_read_cr3();
}

static noinstr void pv_native_write_cr3(unsigned long cr3)
{
	native_write_cr3(cr3);
}

static noinstr unsigned long pv_native_get_debugreg(int regno)
{
	return native_get_debugreg(regno);
}

static noinstr void pv_native_set_debugreg(int regno, unsigned long val)
{
	native_set_debugreg(regno, val);
}
#endif

struct pv_info pv_info = {
	.name = "bare hardware",
#ifdef CONFIG_PARAVIRT_XXL
	.extra_user_64bit_cs = __USER_CS,
#endif
};

/* 64-bit pagetable entries */
#ifdef CONFIG_SECURITY_HARDENING_RAP
#define PTE_MAKE_IDENT(level) __PV_IS_CALLEE_SAVE(native_make_##level)
#define PTE_VALUE_IDENT(level) __PV_IS_CALLEE_SAVE(native_##level##_val)
/* A void(void) nop is not a valid replacement for a different C signature. */
#define HDN_PV_NOP(name) name
static noinstr void pv_nop_mm(struct mm_struct *mm) { }
static noinstr void pv_nop_enc(unsigned long pfn, int pages, bool enc) { }
#ifdef CONFIG_PARAVIRT_XXL
static noinstr void pv_nop_ldt(struct desc_struct *ldt, unsigned int entries) { }
static noinstr void pv_nop_task(struct task_struct *task) { }
static noinstr void pv_nop_pgd(struct mm_struct *mm, pgd_t *pgd) { }
static noinstr void pv_nop_alloc(struct mm_struct *mm, unsigned long pfn) { }
static noinstr void pv_nop_release(unsigned long pfn) { }
#endif
#else
#define PTE_MAKE_IDENT(level) __PV_IS_CALLEE_SAVE(_paravirt_ident_64)
#define PTE_VALUE_IDENT(level) __PV_IS_CALLEE_SAVE(_paravirt_ident_64)
#define HDN_PV_NOP(name) paravirt_nop
#endif

struct paravirt_patch_template pv_ops = {
	/* Cpu ops. */
	.cpu.io_delay		= native_io_delay,

#ifdef CONFIG_PARAVIRT_XXL
	.cpu.cpuid		= native_cpuid,
	.cpu.get_debugreg	= pv_native_get_debugreg,
	.cpu.set_debugreg	= pv_native_set_debugreg,
	.cpu.read_cr0		= native_read_cr0,
	.cpu.write_cr0		= native_write_cr0,
	.cpu.write_cr4		= native_write_cr4,
	.cpu.read_msr		= native_read_msr,
	.cpu.write_msr		= native_write_msr,
	.cpu.read_msr_safe	= native_read_msr_safe,
	.cpu.write_msr_safe	= native_write_msr_safe,
	.cpu.read_pmc		= native_read_pmc,
	.cpu.load_tr_desc	= native_load_tr_desc,
	.cpu.set_ldt		= native_set_ldt,
	.cpu.load_gdt		= native_load_gdt,
	.cpu.load_idt		= native_load_idt,
	.cpu.store_tr		= native_store_tr,
	.cpu.load_tls		= native_load_tls,
	.cpu.load_gs_index	= native_load_gs_index,
	.cpu.write_ldt_entry	= native_write_ldt_entry,
	.cpu.write_gdt_entry	= native_write_gdt_entry,
	.cpu.write_idt_entry	= native_write_idt_entry,

	.cpu.alloc_ldt		= HDN_PV_NOP(pv_nop_ldt),
	.cpu.free_ldt		= HDN_PV_NOP(pv_nop_ldt),

	.cpu.load_sp0		= native_load_sp0,

#ifdef CONFIG_X86_IOPL_IOPERM
	.cpu.invalidate_io_bitmap	= native_tss_invalidate_io_bitmap,
	.cpu.update_io_bitmap		= native_tss_update_io_bitmap,
#endif

	.cpu.start_context_switch	= HDN_PV_NOP(pv_nop_task),
	.cpu.end_context_switch		= HDN_PV_NOP(pv_nop_task),

	/* Irq ops. */
	.irq.save_fl		= __PV_IS_CALLEE_SAVE(pv_native_save_fl),
	.irq.irq_disable	= __PV_IS_CALLEE_SAVE(pv_native_irq_disable),
	.irq.irq_enable		= __PV_IS_CALLEE_SAVE(pv_native_irq_enable),
#endif /* CONFIG_PARAVIRT_XXL */

	/* Irq HLT ops. */
	.irq.safe_halt		= pv_native_safe_halt,
	.irq.halt		= native_halt,

	/* Mmu ops. */
	.mmu.flush_tlb_user	= native_flush_tlb_local,
	.mmu.flush_tlb_kernel	= native_flush_tlb_global,
	.mmu.flush_tlb_one_user	= native_flush_tlb_one_user,
	.mmu.flush_tlb_multi	= native_flush_tlb_multi,

	.mmu.exit_mmap		= HDN_PV_NOP(pv_nop_mm),
	.mmu.notify_page_enc_status_changed	= HDN_PV_NOP(pv_nop_enc),

#ifdef CONFIG_PARAVIRT_XXL
	.mmu.read_cr2		= __PV_IS_CALLEE_SAVE(pv_native_read_cr2),
	.mmu.write_cr2		= pv_native_write_cr2,
	.mmu.read_cr3		= pv_native_read_cr3,
	.mmu.write_cr3		= pv_native_write_cr3,

	.mmu.pgd_alloc		= __paravirt_pgd_alloc,
	.mmu.pgd_free		= HDN_PV_NOP(pv_nop_pgd),

	.mmu.alloc_pte		= HDN_PV_NOP(pv_nop_alloc),
	.mmu.alloc_pmd		= HDN_PV_NOP(pv_nop_alloc),
	.mmu.alloc_pud		= HDN_PV_NOP(pv_nop_alloc),
	.mmu.alloc_p4d		= HDN_PV_NOP(pv_nop_alloc),
	.mmu.release_pte	= HDN_PV_NOP(pv_nop_release),
	.mmu.release_pmd	= HDN_PV_NOP(pv_nop_release),
	.mmu.release_pud	= HDN_PV_NOP(pv_nop_release),
	.mmu.release_p4d	= HDN_PV_NOP(pv_nop_release),

	.mmu.set_pte		= native_set_pte,
	.mmu.set_pmd		= native_set_pmd,

	.mmu.ptep_modify_prot_start	= __ptep_modify_prot_start,
	.mmu.ptep_modify_prot_commit	= __ptep_modify_prot_commit,

	.mmu.set_pud		= native_set_pud,

	.mmu.pmd_val		= PTE_VALUE_IDENT(pmd),
	.mmu.make_pmd		= PTE_MAKE_IDENT(pmd),

	.mmu.pud_val		= PTE_VALUE_IDENT(pud),
	.mmu.make_pud		= PTE_MAKE_IDENT(pud),

	.mmu.set_p4d		= native_set_p4d,

	.mmu.p4d_val		= PTE_VALUE_IDENT(p4d),
	.mmu.make_p4d		= PTE_MAKE_IDENT(p4d),

	.mmu.set_pgd		= native_set_pgd,

	.mmu.pte_val		= PTE_VALUE_IDENT(pte),
	.mmu.pgd_val		= PTE_VALUE_IDENT(pgd),

	.mmu.make_pte		= PTE_MAKE_IDENT(pte),
	.mmu.make_pgd		= PTE_MAKE_IDENT(pgd),

	.mmu.enter_mmap		= HDN_PV_NOP(pv_nop_mm),

	.mmu.lazy_mode = {
		.enter		= paravirt_nop,
		.leave		= paravirt_nop,
		.flush		= paravirt_nop,
	},

	.mmu.set_fixmap		= native_set_fixmap,
#endif /* CONFIG_PARAVIRT_XXL */
};

#ifdef CONFIG_PARAVIRT_XXL
NOKPROBE_SYMBOL(native_load_idt);
#endif

EXPORT_SYMBOL(pv_ops);
EXPORT_SYMBOL_GPL(pv_info);
