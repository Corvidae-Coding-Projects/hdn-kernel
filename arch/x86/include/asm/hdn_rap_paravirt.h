/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_PARAVIRT_H
#define _ASM_X86_HDN_RAP_PARAVIRT_H

/* Keep native alternatives, but expose every fallback call's actual C type to
 * RAP. An alternative chooses a local branch; it never patches a typed call
 * into an untyped indirect edge. Before alternatives, the initialized PV ops
 * remain the source of the call, exactly as in the normal PV implementation. */
#define __HDN_PV_ALT_VALUE(type, code, feature, fallback, ...) \
({ \
	__label__ __pv_call, __pv_done; \
	type __pv_value; \
	asm goto(ALTERNATIVE("jmp %l[__pv_call]", "", feature) \
		 : : : : __pv_call); \
	asm volatile(code : "=a" (__pv_value) : __VA_ARGS__ : "memory", "cc"); \
	goto __pv_done; \
__pv_call: \
	__pv_value = (fallback); \
__pv_done: \
	__pv_value; \
})

#define __HDN_PV_ALT_VOID(code, feature, fallback, ...) \
do { \
	__label__ __pv_call, __pv_done; \
	asm goto(ALTERNATIVE("jmp %l[__pv_call]", "", feature) \
		 : : : : __pv_call); \
	asm volatile(code : : __VA_ARGS__ : "rax", "memory", "cc"); \
	goto __pv_done; \
__pv_call: \
	(fallback); \
__pv_done:; \
} while (0)

#undef PVOP_CALL0
#undef PVOP_CALL1
#undef PVOP_CALL2
#undef PVOP_CALL3
#undef PVOP_CALL4
#undef PVOP_VCALL0
#undef PVOP_VCALL1
#undef PVOP_VCALL2
#undef PVOP_VCALL3
#undef PVOP_VCALL4
#define PVOP_CALL0(type, array, op) READ_ONCE((array).op)()
#define PVOP_CALL1(type, array, op, a) READ_ONCE((array).op)(a)
#define PVOP_CALL2(type, array, op, a, b) READ_ONCE((array).op)(a, b)
#define PVOP_CALL3(type, array, op, a, b, c) READ_ONCE((array).op)(a, b, c)
#define PVOP_CALL4(type, array, op, a, b, c, d) READ_ONCE((array).op)(a, b, c, d)
#define PVOP_VCALL0(array, op) PVOP_CALL0(void, array, op)
#define PVOP_VCALL1(array, op, a) PVOP_CALL1(void, array, op, a)
#define PVOP_VCALL2(array, op, a, b) PVOP_CALL2(void, array, op, a, b)
#define PVOP_VCALL3(array, op, a, b, c) PVOP_CALL3(void, array, op, a, b, c)
#define PVOP_VCALL4(array, op, a, b, c, d) PVOP_CALL4(void, array, op, a, b, c, d)

#undef PVOP_CALLEE0
#undef PVOP_VCALLEE0
#undef PVOP_CALLEE1
#undef PVOP_VCALLEE1
#define PVOP_CALLEE0(type, array, op) \
	((type (*)(void))READ_ONCE((array).op.func))()
#define PVOP_VCALLEE0(array, op) PVOP_CALLEE0(void, array, op)
#define PVOP_CALLEE1(type, array, op, a) \
	((type (*)(__typeof__(a)))READ_ONCE((array).op.func))(a)
#define PVOP_VCALLEE1(array, op, a) PVOP_CALLEE1(void, array, op, a)

#undef PVOP_ALT_CALL0
#undef PVOP_ALT_VCALL0
#undef PVOP_ALT_VCALL1
#undef PVOP_ALT_CALLEE0
#undef PVOP_ALT_VCALLEE0
#undef PVOP_ALT_CALLEE1
#undef PVOP_ALT_VCALLEE1
#define PVOP_ALT_CALL0(type, array, op, alt, cond) \
	__HDN_PV_ALT_VALUE(type, alt, cond, PVOP_CALL0(type, array, op))
#define PVOP_ALT_VCALL0(array, op, alt, cond) \
	__HDN_PV_ALT_VOID(alt, cond, PVOP_VCALL0(array, op))
#define PVOP_ALT_VCALL1(array, op, a, alt, cond) \
do { \
	__typeof__(a) __pv_arg = (a); \
	__HDN_PV_ALT_VOID(alt, cond, PVOP_VCALL1(array, op, __pv_arg), "D" (__pv_arg)); \
} while (0)
#define PVOP_ALT_CALLEE0(type, array, op, alt, cond) \
	__HDN_PV_ALT_VALUE(type, alt, cond, PVOP_CALLEE0(type, array, op))
#define PVOP_ALT_VCALLEE0(array, op, alt, cond) \
	__HDN_PV_ALT_VOID(alt, cond, PVOP_VCALLEE0(array, op))
#define PVOP_ALT_CALLEE1(type, array, op, a, alt, cond) \
({ \
	__typeof__(a) __pv_arg = (a); \
	__HDN_PV_ALT_VALUE(type, alt, cond, PVOP_CALLEE1(type, array, op, __pv_arg), "D" (__pv_arg)); \
})
#define PVOP_ALT_VCALLEE1(array, op, a, alt, cond) \
do { \
	__typeof__(a) __pv_arg = (a); \
	__HDN_PV_ALT_VOID(alt, cond, PVOP_VCALLEE1(array, op, __pv_arg), "D" (__pv_arg)); \
} while (0)

/* Page-table constructors/accessors have structure-valued C signatures. The
 * old register ABI flattened them into words; that is not a canonical type. */
#define HDN_PV_MAKE(level, value) \
	((level##_t) { __HDN_PV_ALT_VALUE(level##val_t, "mov %%rdi, %%rax", ALT_NOT_XEN, \
		((level##_t (*)(level##val_t))READ_ONCE(pv_ops.mmu.make_##level.func))(value).level, \
		"D" (value)) })
#define HDN_PV_VALUE(level, value) \
	__HDN_PV_ALT_VALUE(level##val_t, "mov %%rdi, %%rax", ALT_NOT_XEN, \
		((level##val_t (*)(level##_t))READ_ONCE(pv_ops.mmu.level##_val.func))(value), \
		"D" ((value).level))

#endif
