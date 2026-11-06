// SPDX-License-Identifier: GPL-2.0-only
/* Compilation succeeds; the binary coverage gate must reject this naked edge. */
void rap_bad_asm(void)
{
	asm volatile("call rap_unbound_destination" ::: "rax", "rcx", "rdx",
		     "rsi", "rdi", "r8", "r9", "r10", "r11", "memory");
}
