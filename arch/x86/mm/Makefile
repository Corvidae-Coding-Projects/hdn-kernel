# SPDX-License-Identifier: GPL-2.0
# Kernel does not boot with instrumentation of tlb.c and mem_encrypt*.c
KCOV_INSTRUMENT_tlb.o			:= n
KCOV_INSTRUMENT_mem_encrypt.o		:= n
KCOV_INSTRUMENT_mem_encrypt_amd.o	:= n
KCOV_INSTRUMENT_pgprot.o		:= n
# See the "Disable KCOV" comment in arch/x86/kernel/Makefile.
KCOV_INSTRUMENT_physaddr.o		:= n

KASAN_SANITIZE_mem_encrypt.o		:= n
KASAN_SANITIZE_mem_encrypt_amd.o	:= n
KASAN_SANITIZE_pgprot.o		:= n

# Disable KCSAN entirely, because otherwise we get warnings that some functions
# reference __initdata sections.
KCSAN_SANITIZE := n
# Avoid recursion by not calling KMSAN hooks for CEA code.
KMSAN_SANITIZE_cpu_entry_area.o := n

# The private CR3 interval must not acquire tracing/sanitizer/compiler hooks.
# Objtool remains enabled; source-bound hardening gates review this exclusion.
KASAN_SANITIZE_hdn_pgtable_window.o := n
KMSAN_SANITIZE_hdn_pgtable_window.o := n
KCSAN_SANITIZE_hdn_pgtable_window.o := n
KCOV_INSTRUMENT_hdn_pgtable_window.o := n
UBSAN_SANITIZE_hdn_pgtable_window.o := n
CFLAGS_REMOVE_hdn_pgtable_window.o = $(CC_FLAGS_FTRACE) $(GCC_PLUGINS_CFLAGS)
CFLAGS_hdn_pgtable_window.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
ifdef CONFIG_SECURITY_HARDENING_RAP
CFLAGS_hdn_pgtable_window.o += $(filter -fplugin=%/hdn_rap_plugin.so -fplugin-arg-hdn_rap_plugin-%,$(GCC_PLUGINS_CFLAGS)) -fplugin-arg-hdn_rap_plugin-runtime=1
endif

ifdef CONFIG_FUNCTION_TRACER
CFLAGS_REMOVE_mem_encrypt.o		= -pg
CFLAGS_REMOVE_mem_encrypt_amd.o		= -pg
CFLAGS_REMOVE_pgprot.o			= -pg
endif

obj-y				:=  init.o init_$(BITS).o fault.o ioremap.o extable.o mmap.o \
				    pgtable.o physaddr.o tlb.o cpu_entry_area.o maccess.o pgprot.o

obj-$(CONFIG_SECURITY_HARDENING_PGTABLE) += hdn_pgtable.o hdn_pgtable_window.o hdn_pgtable_window_init.o
obj-$(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) += hdn_stack_mm.o hdn_stack_mm_init.o

KASAN_SANITIZE_hdn_stack_mm.o := n
KMSAN_SANITIZE_hdn_stack_mm.o := n
KCSAN_SANITIZE_hdn_stack_mm.o := n
KCOV_INSTRUMENT_hdn_stack_mm.o := n
UBSAN_SANITIZE_hdn_stack_mm.o := n
GCOV_PROFILE_hdn_stack_mm.o := n
CFLAGS_REMOVE_hdn_stack_mm.o = $(CC_FLAGS_FTRACE) $(GCC_PLUGINS_CFLAGS)
CFLAGS_hdn_stack_mm.o += $(DISABLE_KSTACK_ERASE) -fno-stack-protector
ifdef CONFIG_SECURITY_HARDENING_RAP
CFLAGS_hdn_stack_mm.o += $(filter -fplugin=%/hdn_rap_plugin.so -fplugin-arg-hdn_rap_plugin-%,$(GCC_PLUGINS_CFLAGS)) -fplugin-arg-hdn_rap_plugin-runtime=1
endif

obj-y				+= pat/

# Make sure __phys_addr has no stackprotector
CFLAGS_physaddr.o		:= -fno-stack-protector

obj-$(CONFIG_X86_32)		+= pgtable_32.o iomap_32.o

obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
obj-$(CONFIG_PTDUMP)		+= dump_pagetables.o
obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o

KASAN_SANITIZE_kasan_init_$(BITS).o := n
obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o

KMSAN_SANITIZE_kmsan_shadow.o	:= n
obj-$(CONFIG_KMSAN)		+= kmsan_shadow.o

obj-$(CONFIG_MMIOTRACE)		+= mmiotrace.o
mmiotrace-y			:= kmmio.o pf_in.o mmio-mod.o
obj-$(CONFIG_MMIOTRACE_TEST)	+= testmmiotrace.o

obj-$(CONFIG_NUMA)		+= numa.o
obj-$(CONFIG_AMD_NUMA)		+= amdtopology.o
obj-$(CONFIG_ACPI_NUMA)		+= srat.o

obj-$(CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS)	+= pkeys.o
obj-$(CONFIG_RANDOMIZE_MEMORY)			+= kaslr.o
obj-$(CONFIG_MITIGATION_PAGE_TABLE_ISOLATION)	+= pti.o

obj-$(CONFIG_X86_MEM_ENCRYPT)	+= mem_encrypt.o
obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= mem_encrypt_amd.o

obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= mem_encrypt_boot.o
obj-$(CONFIG_SECURITY_HARDENING_UDEREF) += hdn_uaccess.o
