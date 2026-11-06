# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_HDN_ARCH_CONTRACT) += hdn-contract.o
CFLAGS_hdn-contract.o += -Werror=switch
#
# Makefile for the linux kernel.
#

always-$(KBUILD_BUILTIN)	+= vmlinux.lds

CPPFLAGS_vmlinux.lds += -U$(UTS_MACHINE)

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_tsc.o = -pg
CFLAGS_REMOVE_paravirt-spinlocks.o = -pg
CFLAGS_REMOVE_pvclock.o = -pg
CFLAGS_REMOVE_kvmclock.o = -pg
CFLAGS_REMOVE_ftrace.o = -pg
CFLAGS_REMOVE_early_printk.o = -pg
CFLAGS_REMOVE_head64.o = -pg
CFLAGS_REMOVE_head32.o = -pg
CFLAGS_REMOVE_rethook.o = -pg
CFLAGS_REMOVE_hdn_text.o = -pg
CFLAGS_REMOVE_hdn_gdt.o = -pg
endif

KASAN_SANITIZE_head$(BITS).o				:= n
KASAN_SANITIZE_dumpstack.o				:= n
KASAN_SANITIZE_dumpstack_$(BITS).o			:= n
KASAN_SANITIZE_stacktrace.o				:= n
KASAN_SANITIZE_paravirt.o				:= n

# With some compiler versions the generated code results in boot hangs, caused
# by several compilation units. To be safe, disable all instrumentation.
KCSAN_SANITIZE := n
KMSAN_SANITIZE_head$(BITS).o				:= n
KMSAN_SANITIZE_nmi.o					:= n

# If instrumentation of the following files is enabled, boot hangs during
# first second.
KCOV_INSTRUMENT_head$(BITS).o				:= n
# These are called from save_stack_trace() on debug paths,
# and produce large amounts of uninteresting coverage.
KCOV_INSTRUMENT_stacktrace.o				:= n
KCOV_INSTRUMENT_dumpstack.o				:= n
KCOV_INSTRUMENT_dumpstack_$(BITS).o			:= n
KCOV_INSTRUMENT_unwind_orc.o				:= n
KCOV_INSTRUMENT_unwind_frame.o				:= n
KCOV_INSTRUMENT_unwind_guess.o				:= n
# Text-window bookkeeping also runs while a debugger has stopped other CPUs.
KCOV_INSTRUMENT_hdn_text.o				:= n
KCOV_INSTRUMENT_hdn_gdt.o				:= n
# GDT aliases are private translations of initialized descriptors; avoid
# instrumenting the temporary-CR3 interval or requiring shadow aliases.
KASAN_SANITIZE_hdn_gdt.o					:= n
KMSAN_SANITIZE_hdn_gdt.o					:= n

# Disable KCOV to prevent crashes during kexec: load_segments() invalidates
# the GS base, which KCOV relies on for per-CPU data.
#
# As KCOV and KEXEC compatibility should be preserved (e.g. syzkaller is
# using it to collect crash dumps during kernel fuzzing), disabling
# KCOV for KEXEC kernels is not an option. Selectively disabling KCOV
# instrumentation for individual affected functions can be fragile, while
# adding more checks to KCOV would slow it down.
#
# As a compromise solution, disable KCOV instrumentation for the whole
# source code file. If its coverage is ever needed, other approaches
# should be considered.
KCOV_INSTRUMENT_machine_kexec_64.o			:= n

CFLAGS_head32.o := -fno-stack-protector
CFLAGS_head64.o := -fno-stack-protector
CFLAGS_irq.o := -I $(src)/../include/asm/trace

obj-y			+= head_$(BITS).o
obj-y			+= head$(BITS).o
obj-y			+= ebda.o
obj-y			+= platform-quirks.o
obj-y			+= process_$(BITS).o signal.o signal_$(BITS).o
obj-y			+= traps.o idt.o irq.o irq_$(BITS).o dumpstack_$(BITS).o
obj-y			+= time.o ioport.o dumpstack.o nmi.o
obj-$(CONFIG_X86_FRED)	+= fred.o
obj-$(CONFIG_SECURITY_HARDENING_GDT) += hdn_gdt.o
ifneq ($(filter y,$(CONFIG_SECURITY_HARDENING_GDT) $(CONFIG_SECURITY_HARDENING_PGTABLE)),)
obj-y += hdn_entry_window.o
endif
CFLAGS_REMOVE_hdn_entry_window.o = $(CC_FLAGS_FTRACE) $(GCC_PLUGINS_CFLAGS)
CFLAGS_hdn_entry_window.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_entry_window.o := n
KMSAN_SANITIZE_hdn_entry_window.o := n
KCSAN_SANITIZE_hdn_entry_window.o := n
KCOV_INSTRUMENT_hdn_entry_window.o := n
UBSAN_SANITIZE_hdn_entry_window.o := n
GCOV_PROFILE_hdn_entry_window.o := n
obj-$(CONFIG_MODIFY_LDT_SYSCALL)	+= ldt.o
obj-$(CONFIG_X86_KERNEL_IBT)		+= ibt_selftest.o
obj-y			+= setup.o x86_init.o i8259.o irqinit.o
obj-$(CONFIG_JUMP_LABEL)	+= jump_label.o
obj-$(CONFIG_IRQ_WORK)  += irq_work.o
obj-y			+= probe_roms.o
obj-$(CONFIG_X86_32)	+= sys_ia32.o
obj-$(CONFIG_IA32_EMULATION)	+= sys_ia32.o signal_32.o
obj-$(CONFIG_X86_64)	+= sys_x86_64.o
obj-$(CONFIG_X86_ESPFIX64)	+= espfix_64.o
obj-$(CONFIG_SYSFS)	+= ksysfs.o
obj-y			+= bootflag.o e820.o
obj-y			+= pci-dma.o quirks.o kdebugfs.o
obj-y			+= alternative.o i8253.o hw_breakpoint.o
obj-y			+= tsc.o tsc_msr.o io_delay.o rtc.o
obj-y			+= resource.o
obj-y			+= irqflags.o
obj-y			+= static_call.o

obj-y				+= process.o
obj-y				+= fpu/
obj-y				+= ptrace.o
obj-$(CONFIG_X86_32)		+= tls.o
obj-$(CONFIG_IA32_EMULATION)	+= tls.o
obj-y				+= step.o
obj-$(CONFIG_INTEL_TXT)		+= tboot.o
obj-$(CONFIG_ISA_DMA_API)	+= i8237.o
obj-y				+= stacktrace.o
obj-y				+= cpu/
obj-y				+= acpi/
obj-y				+= reboot.o
obj-$(CONFIG_X86_MSR)		+= msr.o
obj-$(CONFIG_X86_CPUID)		+= cpuid.o
obj-$(CONFIG_PCI)		+= early-quirks.o
apm-y				:= apm_32.o
obj-$(CONFIG_APM)		+= apm.o
obj-$(CONFIG_SMP)		+= smp.o
obj-$(CONFIG_SMP)		+= smpboot.o
obj-$(CONFIG_X86_TSC)		+= tsc_sync.o
obj-$(CONFIG_SMP)		+= setup_percpu.o
obj-$(CONFIG_X86_MPPARSE)	+= mpparse.o
obj-y				+= apic/
obj-$(CONFIG_X86_REBOOTFIXUPS)	+= reboot_fixups_32.o
obj-$(CONFIG_DYNAMIC_FTRACE)	+= ftrace.o
obj-$(CONFIG_FUNCTION_TRACER)	+= ftrace_$(BITS).o
ifeq ($(CONFIG_SECURITY_HARDENING_RAP),y)
obj-$(CONFIG_FUNCTION_TRACER)	+= ftrace.o
endif
obj-$(CONFIG_FUNCTION_GRAPH_TRACER) += ftrace.o
obj-$(CONFIG_FTRACE_SYSCALLS)	+= ftrace.o
obj-$(CONFIG_X86_TSC)		+= trace_clock.o
obj-$(CONFIG_TRACING)		+= trace.o
obj-$(CONFIG_RETHOOK)		+= rethook.o
obj-$(CONFIG_VMCORE_INFO)	+= vmcore_info_$(BITS).o
obj-$(CONFIG_KEXEC_CORE)	+= machine_kexec_$(BITS).o
obj-$(CONFIG_KEXEC_CORE)	+= relocate_kernel_$(BITS).o
obj-$(CONFIG_KEXEC_FILE)	+= kexec-bzimage64.o
obj-$(CONFIG_CRASH_DUMP)	+= crash_dump_$(BITS).o crash.o
obj-y				+= kprobes/
obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_X86_32)		+= doublefault_32.o
obj-$(CONFIG_KGDB)		+= kgdb.o
obj-$(CONFIG_VM86)		+= vm86_32.o
obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o

obj-$(CONFIG_HPET_TIMER) 	+= hpet.o

obj-$(CONFIG_AMD_NB)		+= amd_nb.o
obj-$(CONFIG_AMD_NODE)		+= amd_node.o
obj-$(CONFIG_DEBUG_NMI_SELFTEST) += nmi_selftest.o

obj-$(CONFIG_KVM_GUEST)		+= kvm.o kvmclock.o
obj-$(CONFIG_PARAVIRT)		+= paravirt.o
obj-$(CONFIG_PARAVIRT)		+= paravirt-spinlocks.o
obj-$(CONFIG_PARAVIRT_CLOCK)	+= pvclock.o
obj-$(CONFIG_X86_PMEM_LEGACY_DEVICE) += pmem.o

obj-$(CONFIG_JAILHOUSE_GUEST)	+= jailhouse.o

obj-$(CONFIG_EISA)		+= eisa.o
obj-$(CONFIG_PCSPKR_PLATFORM)	+= pcspeaker.o

obj-$(CONFIG_X86_CHECK_BIOS_CORRUPTION) += check.o

obj-$(CONFIG_OF)			+= devicetree.o
obj-$(CONFIG_UPROBES)			+= uprobes.o

obj-$(CONFIG_PERF_EVENTS)		+= perf_regs.o
obj-$(CONFIG_SCHED_MC_PRIO)		+= itmt.o
obj-$(CONFIG_X86_UMIP)			+= umip.o

obj-$(CONFIG_UNWINDER_ORC)		+= unwind_orc.o
obj-$(CONFIG_UNWINDER_FRAME_POINTER)	+= unwind_frame.o
obj-$(CONFIG_UNWINDER_GUESS)		+= unwind_guess.o

obj-$(CONFIG_CFI)			+= cfi.o

obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap.o hdn_rap_validate.o hdn_rap_context.o hdn_rap_context_lifecycle.o hdn_rap_thunks.o hdn_rap_failure.o
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_asm_types.o
obj-$(CONFIG_SECURITY_HARDENING_PGTABLE) += hdn_livepatch.o
ifneq ($(CONFIG_KVM_AMD),)
ifeq ($(CONFIG_MSHV_ROOT)$(CONFIG_CRASH_DUMP),yy)
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_hv_crash.o
endif
CFLAGS_REMOVE_hdn_rap_hv_crash.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_rap_hv_crash.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_rap_hv_crash.o := n
KCSAN_SANITIZE_hdn_rap_hv_crash.o := n
KMSAN_SANITIZE_hdn_rap_hv_crash.o := n
KCOV_INSTRUMENT_hdn_rap_hv_crash.o := n
UBSAN_SANITIZE_hdn_rap_hv_crash.o := n
GCOV_PROFILE_hdn_rap_hv_crash.o := n
obj-$(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) += hdn_svm.o
endif
ifneq ($(CONFIG_KVM_INTEL),)
obj-$(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) += hdn_vmcs.o
endif
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_bhb.o
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_dynamic.o hdn_rap_bpf.o
ifeq ($(CONFIG_EFI),y)
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_efi.o
endif
ifeq ($(CONFIG_KEXEC_CORE),y)
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_kexec.o hdn_rap_kexec_asm.o
endif
ifeq ($(CONFIG_PM_SLEEP),y)
obj-$(CONFIG_SECURITY_HARDENING_RAP) += hdn_rap_resume.o
endif
obj-$(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) += hdn_stack.o hdn_stack_access.o hdn_stack_entry.o

CFLAGS_REMOVE_hdn_stack_access.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_stack_access.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_stack_access.o := n
KCSAN_SANITIZE_hdn_stack_access.o := n
KMSAN_SANITIZE_hdn_stack_access.o := n
KCOV_INSTRUMENT_hdn_stack_access.o := n
UBSAN_SANITIZE_hdn_stack_access.o := n
GCOV_PROFILE_hdn_stack_access.o := n
# The validation engine is the root of the compiler's transfer protocol.
# It must never recursively instrument its own validation or diagnostics.
CFLAGS_REMOVE_hdn_rap_validate.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
KASAN_SANITIZE_hdn_rap_validate.o := n
KCSAN_SANITIZE_hdn_rap_validate.o := n
KMSAN_SANITIZE_hdn_rap_validate.o := n
KCOV_INSTRUMENT_hdn_rap_validate.o := n
UBSAN_SANITIZE_hdn_rap_validate.o := n
GCOV_PROFILE_hdn_rap_validate.o := n
CFLAGS_REMOVE_hdn_rap_context.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_rap_validate.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
CFLAGS_hdn_rap_context.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
CFLAGS_REMOVE_hdn_rap_resume.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_rap_resume.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_rap_resume.o := n
KCSAN_SANITIZE_hdn_rap_resume.o := n
KMSAN_SANITIZE_hdn_rap_resume.o := n
KCOV_INSTRUMENT_hdn_rap_resume.o := n
UBSAN_SANITIZE_hdn_rap_resume.o := n
GCOV_PROFILE_hdn_rap_resume.o := n
CFLAGS_REMOVE_hdn_rap_efi.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_rap_efi.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_rap_efi.o := n
KCSAN_SANITIZE_hdn_rap_efi.o := n
KMSAN_SANITIZE_hdn_rap_efi.o := n
KCOV_INSTRUMENT_hdn_rap_efi.o := n
UBSAN_SANITIZE_hdn_rap_efi.o := n
GCOV_PROFILE_hdn_rap_efi.o := n
CFLAGS_REMOVE_hdn_rap_kexec.o += $(GCC_PLUGINS_CFLAGS) $(CC_FLAGS_FTRACE)
CFLAGS_hdn_rap_kexec.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
KASAN_SANITIZE_hdn_rap_kexec.o := n
KCSAN_SANITIZE_hdn_rap_kexec.o := n
KMSAN_SANITIZE_hdn_rap_kexec.o := n
KCOV_INSTRUMENT_hdn_rap_kexec.o := n
UBSAN_SANITIZE_hdn_rap_kexec.o := n
GCOV_PROFILE_hdn_rap_kexec.o := n
KASAN_SANITIZE_hdn_rap_context.o := n
KCSAN_SANITIZE_hdn_rap_context.o := n
KMSAN_SANITIZE_hdn_rap_context.o := n
KCOV_INSTRUMENT_hdn_rap_context.o := n
UBSAN_SANITIZE_hdn_rap_context.o := n
GCOV_PROFILE_hdn_rap_context.o := n
ifdef CONFIG_SECURITY_HARDENING_RAP
# Runtime roots still emit type/call-site metadata and tag outgoing calls.
# They omit their own return adapters to terminate recursive validation.
hdn_rap_runtime_flags = $(filter -fplugin=%/hdn_rap_plugin.so -fplugin-arg-hdn_rap_plugin-%,$(GCC_PLUGINS_CFLAGS)) -fplugin-arg-hdn_rap_plugin-runtime=1
CFLAGS_hdn_rap_validate.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_rap_context.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_rap_resume.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_rap_kexec.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_rap_hv_crash.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_rap_efi.o += $(hdn_rap_runtime_flags)
CFLAGS_hdn_stack_access.o += $(hdn_rap_runtime_flags)
endif

obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o
obj-$(CONFIG_SECURITY_HARDENING_KERNEL_WX) += hdn_text.o

obj-$(CONFIG_X86_CET)			+= cet.o

obj-$(CONFIG_X86_USER_SHADOW_STACK)	+= shstk.o

###
# 64 bit specific files
ifeq ($(CONFIG_X86_64),y)
	obj-$(CONFIG_AUDIT)		+= audit_64.o

	obj-$(CONFIG_GART_IOMMU)	+= amd_gart_64.o aperture_64.o

	obj-$(CONFIG_MMCONF_FAM10H)	+= mmconf-fam10h_64.o
	obj-y				+= vsmp_64.o
endif
