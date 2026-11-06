/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/asm.h>
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/hdn_rap.h>

/*
 * unsigned long native_save_fl(void)
 */
.pushsection .noinstr.text, "ax"
SYM_FUNC_START(native_save_fl)
	ENDBR
	HDN_TYPED_FUNC_ENTER native_save_fl
	pushf
	pop %_ASM_AX
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(native_save_fl)
.popsection
EXPORT_SYMBOL(native_save_fl)
