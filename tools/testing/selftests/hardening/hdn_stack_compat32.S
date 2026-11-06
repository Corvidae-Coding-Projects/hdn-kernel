/* SPDX-License-Identifier: GPL-2.0-only */
/* Freestanding i386 guest probe: TLS/GDT, mmap/mprotect, COW, fork and wait.
 * Build: gcc -m32 -nostdlib -static -no-pie -Wl,-z,noexecstack FILE.S -o PROBE
 * Run only in the disposable hardening guest. Exit 0 means all invariants held;
 * exit 1 means a syscall, TLS value, child status or parent COW value failed.
 */
	.section .text
	.code32
	.globl _start
_start:
	movl $128, iterations
.Literation:
	/* mmap2(NULL, 4096, RW, PRIVATE|ANONYMOUS, -1, 0) */
	movl $192, %eax
	xorl %ebx, %ebx
	movl $4096, %ecx
	movl $3, %edx
	movl $0x22, %esi
	movl $-1, %edi
	xorl %ebp, %ebp
	int $0x80
	cmpl $-4095, %eax
	jae .Lfailed
	movl %eax, mapping
	movl $0x16273849, (%eax)
	movl %eax, descriptor + 4
	movl $243, %eax /* set_thread_area; reuses the same slot after round one */
	movl $descriptor, %ebx
	int $0x80
	testl %eax, %eax
	jnz .Lfailed
	movl descriptor, %eax
	shll $3, %eax
	orl $3, %eax
	movw %ax, %gs
	cmpl $0x16273849, %gs:0
	jne .Lfailed
	/* Both protection directions exercise page-table mutation from ADDR32. */
	movl $125, %eax
	movl mapping, %ebx
	movl $4096, %ecx
	movl $1, %edx
	int $0x80
	testl %eax, %eax
	jnz .Lfailed
	cmpl $0x16273849, %gs:0
	jne .Lfailed
	movl $125, %eax
	movl $3, %edx
	int $0x80
	testl %eax, %eax
	jnz .Lfailed
	movl $2, %eax /* fork */
	int $0x80
	testl %eax, %eax
	js .Lfailed
	jz .Lchild
	movl %eax, child
.Lwait:
	movl $7, %eax /* waitpid */
	movl child, %ebx
	movl $status, %ecx
	xorl %edx, %edx
	int $0x80
	cmpl $-4, %eax /* retry EINTR */
	je .Lwait
	cmpl child, %eax
	jne .Lfailed
	cmpl $0, status
	jne .Lfailed
	cmpl $0x16273849, %gs:0 /* child's write must not reach the parent */
	jne .Lfailed
	xorl %eax, %eax
	movw %ax, %gs
	movl $91, %eax
	movl mapping, %ebx
	movl $4096, %ecx
	int $0x80
	testl %eax, %eax
	jnz .Lfailed
	decl iterations
	jnz .Literation
	xorl %ebx, %ebx
	jmp .Lexit
.Lchild:
	cmpl $0x16273849, %gs:0
	jne .Lfailed
	movl $0x5a6b7c8d, %gs:0
	movl $158, %eax /* sched_yield, then check the restored TLS view */
	int $0x80
	testl %eax, %eax
	jnz .Lfailed
	cmpl $0x5a6b7c8d, %gs:0
	jne .Lfailed
	xorl %ebx, %ebx
	jmp .Lexit
.Lfailed:
	movl $1, %ebx
.Lexit:
	movl $1, %eax
	int $0x80
	ud2

	.section .data
	.balign 4
descriptor:
	.long -1, 0, 0xfffff, 0x51
mapping: .long 0
iterations: .long 0
child: .long 0
status: .long 0
	.section .note.GNU-stack,"",@progbits
