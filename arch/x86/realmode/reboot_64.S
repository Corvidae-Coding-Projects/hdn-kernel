/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/hdn_rap.h>
#include <asm/unwind_hints.h>
#include <asm/processor-flags.h>

	.text
/* All arguments have been consumed before changing roots. The far target is
 * the immutable 32-bit reboot stub, not a caller-controlled function pointer. */
SYM_FUNC_START(hdn_realmode_restart)
	HDN_KEXEC_FUNC hdn_realmode_restart, 26
	HDN_FUNC_ENTER
	movq %cr4, %rax
	andq $~(X86_CR4_PCIDE | X86_CR4_PGE), %rax
	movq %rax, %cr4
	movq hdn_realmode_reboot(%rip), %rax
	movq %rax, %cr3
	ljmpl *hdn_realmode_reboot+8(%rip)
	ud2
SYM_FUNC_END(hdn_realmode_restart)
STACK_FRAME_NON_STANDARD hdn_realmode_restart
_ASM_NOKPROBE(hdn_realmode_restart)
