/* SPDX-License-Identifier: GPL-2.0-only */
/* Deliberately invalid objtool inputs. Never linked into a kernel. */
	.text
#ifdef HDN_UACCESS_NESTED
	.globl hdn_uaccess_bad_nested
	.type hdn_uaccess_bad_nested, @function
hdn_uaccess_bad_nested:
	stac
	stac
	clac
	ret
	.size hdn_uaccess_bad_nested, .-hdn_uaccess_bad_nested
#endif

#ifdef HDN_UACCESS_CALLBACK
	.globl hdn_uaccess_bad_callback
	.type hdn_uaccess_bad_callback, @function
hdn_uaccess_bad_callback:
	stac
	call *%rax
	clac
	ret
	.size hdn_uaccess_bad_callback, .-hdn_uaccess_bad_callback
#endif

#ifdef HDN_UACCESS_RETURN
	.globl hdn_uaccess_bad_return
	.type hdn_uaccess_bad_return, @function
hdn_uaccess_bad_return:
	stac
	ret
	.size hdn_uaccess_bad_return, .-hdn_uaccess_bad_return
#endif

#ifdef HDN_UACCESS_SLEEP
	.globl hdn_uaccess_bad_sleep
	.type hdn_uaccess_bad_sleep, @function
hdn_uaccess_bad_sleep:
	stac
	call schedule
	clac
	ret
	.size hdn_uaccess_bad_sleep, .-hdn_uaccess_bad_sleep
#endif

#ifdef HDN_UACCESS_GOOD
	.globl hdn_uaccess_good_pair
	.type hdn_uaccess_good_pair, @function
hdn_uaccess_good_pair:
	stac
	mov (%rdi), %eax
	clac
	ret
	.size hdn_uaccess_good_pair, .-hdn_uaccess_good_pair
#endif
	.section .note.GNU-stack,"",@progbits
