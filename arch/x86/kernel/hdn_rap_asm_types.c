// SPDX-License-Identifier: GPL-2.0-only
/* Real C prototypes for the separately verified assembly callback bodies. */
#include <linux/ftrace.h>
#include <linux/preempt.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/hdn_rap.h>
#include <asm/bug.h>
#include <asm/string.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/mce.h>
#include <asm/checksum.h>
#include <asm/uaccess.h>
#include <asm/gsseg.h>
#include <asm/fred.h>
#include <linux/suspend.h>
#include <asm/suspend.h>
#include <asm/tdx.h>
#include <asm/idtentry.h>
#include <asm/hdn_rap.h>

__ADDRESSABLE(rewind_stack_and_make_dead);

#ifdef CONFIG_IA32_EMULATION
__ADDRESSABLE(int80_emulation);
#endif

__ADDRESSABLE(__WARN_trap);
__ADDRESSABLE(__memcpy);
__ADDRESSABLE(__memset);
__ADDRESSABLE(__memmove);
__ADDRESSABLE(copy_page);
__ADDRESSABLE(rdmsr_safe_regs);
__ADDRESSABLE(wrmsr_safe_regs);
__ADDRESSABLE(asm_load_gs_index);
#ifdef CONFIG_INTEL_TDX_HOST
__ADDRESSABLE(__seamcall);
__ADDRESSABLE(__seamcall_ret);
__ADDRESSABLE(__seamcall_saved_ret);
#endif
#ifdef CONFIG_INTEL_TDX_GUEST
__ADDRESSABLE(__tdcall);
__ADDRESSABLE(__tdcall_ret);
__ADDRESSABLE(__tdcall_saved_ret);
#endif
#ifdef CONFIG_HIBERNATION
__ADDRESSABLE(swsusp_arch_suspend);
#endif
#ifdef CONFIG_ACPI_SLEEP
__ADDRESSABLE(do_suspend_lowlevel);
#endif
#if IS_ENABLED(CONFIG_KVM_INTEL) && defined(CONFIG_X86_FRED)
__ADDRESSABLE(asm_fred_entry_from_kvm);
#endif
#ifdef CONFIG_X86_MCE
__ADDRESSABLE(copy_mc_fragile);
#endif
extern unsigned long copy_mc_enhanced_fast_string(void *, const void *, unsigned int);
__ADDRESSABLE(copy_mc_enhanced_fast_string);
__ADDRESSABLE(copy_to_nontemporal);
#ifndef CONFIG_GENERIC_CSUM
__ADDRESSABLE(csum_partial_copy_generic);
#endif

HDN_RAP_TYPE_PROVIDER(bpf_program, bpf_func_t);
HDN_RAP_TYPE_PROVIDER(bpf_callback, bpf_callback_t);
HDN_RAP_TYPE_PROVIDER(bpf_dispatcher, bpf_dispatcher_fn);
HDN_RAP_TYPE_PROVIDER(bpf_trampoline_enter, bpf_trampoline_enter_t);
HDN_RAP_TYPE_PROVIDER(bpf_trampoline_exit, bpf_trampoline_exit_t);

#ifdef CONFIG_PREEMPTION
__ADDRESSABLE(preempt_schedule_thunk);
__ADDRESSABLE(preempt_schedule_notrace_thunk);
#endif

#ifdef CONFIG_FUNCTION_TRACER
__ADDRESSABLE(ftrace_stub);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern typeof(*(trace_func_graph_ret_t)0) ftrace_stub_graph;
__ADDRESSABLE(ftrace_stub_graph);
#endif
#endif
