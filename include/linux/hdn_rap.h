/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_RAP_H
#define _LINUX_HDN_RAP_H

#include <linux/types.h>

#define HDN_RAP_VERSION 1
#define HDN_RAP_ABI 4
#define HDN_RAP_FAILURE_CLASSES 6
#define HDN_RAP_TYPE_MAX 16384
#define HDN_RAP_METADATA_MAX (16UL << 20)

enum hdn_rap_failure_class {
	HDN_RAP_FAIL_TARGET = 1,
	HDN_RAP_FAIL_RETURN,
	HDN_RAP_FAIL_ASYNC,
	HDN_RAP_FAIL_SWITCH,
	HDN_RAP_FAIL_STACK,
	HDN_RAP_FAIL_WINDOW,
};

enum hdn_rap_return_hook {
	HDN_RAP_HOOK_GRAPH = 1,
	HDN_RAP_HOOK_RETHOOK = 2,
};

struct module;
struct ftrace_ops;
struct task_struct;
struct pt_regs;
struct hdn_rap_type {
	u32 version;
	u32 length;
	u8 digest[32];
	char canonical[];
};
struct hdn_rap_target {
	unsigned long address;
	const struct hdn_rap_type *type;
};
/* Function identity is distinct from permission to call it indirectly. Local
 * direct-only functions also need a typed tracing/redirection contract. */
struct hdn_rap_function {
	unsigned long address;
	const struct hdn_rap_type *type;
	unsigned long body, trace_return;
};
/* A patchable direct-call contract is distinct from indirect target admission.
 * flags bit 0 authorizes the native scalar-RAX zero-return shortcut. */
struct hdn_rap_static_call {
	unsigned long address, key;
	const struct hdn_rap_type *type;
	unsigned long flags;
};
struct hdn_rap_static_site {
	unsigned long return_site, trampoline;
};
struct hdn_rap_build {
	u32 version;
	u32 abi;
	char identity[65];
	char compiler[128];
	u8 padding[7];
};

/* ELF inputs are validated before any runtime pointer is published. */
struct hdn_rap_section {
	const void *data;
	size_t size;
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
/* Derive a generated-code ABI from an actual C function-pointer typedef.
 * This discarded null object supplies only a type, never a callable target. */
#define HDN_RAP_TYPE_PROVIDER(name, type) \
	static type const __hdn_rap_prototype_##name __used \
	__section(".discard.hdn_rap.type_providers") = NULL
int hdn_rap_check_build(struct hdn_rap_section build);
int hdn_rap_module_prepare(struct module *mod, struct hdn_rap_section targets,
		struct hdn_rap_section types, struct hdn_rap_section sites,
		struct hdn_rap_section functions, struct hdn_rap_section static_calls,
		struct hdn_rap_section static_sites);
void hdn_rap_module_release(struct module *mod);
void hdn_rap_module_init_retire(struct module *mod);
void hdn_rap_builtin_init_retire(void);
unsigned long hdn_rap_validate(unsigned long address, const struct hdn_rap_type *expected);
unsigned long hdn_rap_validate_call(unsigned long address, unsigned long return_site);
bool hdn_rap_return_site(unsigned long address);
int hdn_rap_task_prepare(struct task_struct *task, int node);
int hdn_rap_boot_stack_prepare(unsigned long base, int node);
int hdn_rap_task_seed(struct task_struct *task);
void hdn_rap_task_release(struct task_struct *task);
int hdn_rap_cpu_stack_prepare(unsigned long base, size_t size, int node, unsigned int cpu);
void hdn_rap_stack_enter(unsigned long slot, unsigned long function);
unsigned long hdn_rap_stack_exit(unsigned long slot);
void hdn_rap_context_seal(void);
void hdn_rap_cpu_contexts_init(void);
void hdn_rap_failure_init(void);
const char *hdn_rap_state(void);
const char *hdn_rap_build_identity(void);
bool hdn_rap_failure_stack(unsigned long address, unsigned long *begin, unsigned long *end);
void __noreturn __hdn_rap_fail(unsigned long kind);
void __noreturn __hdn_rap_halt(void);
void hdn_rap_cpu_restart(void);
void hdn_rap_boot_contexts_init(void);
u64 hdn_rap_fixup_begin(struct pt_regs *regs, int trapnr);
void hdn_rap_fixup_end(struct pt_regs *regs, u64 sequence, int trapnr, bool fixed);
void hdn_rap_bug_end(struct pt_regs *regs, u64 sequence, bool handled);
void hdn_rap_cp_end(struct pt_regs *regs, u64 sequence, bool selftest);
void hdn_rap_push(unsigned long slot, unsigned long expected);
unsigned long hdn_rap_pop(unsigned long slot);
unsigned long hdn_rap_hook_arm(unsigned long slot, unsigned long kind);
unsigned long hdn_rap_hook_finish(unsigned long slot, unsigned long kind,
		unsigned long candidate);
unsigned long hdn_rap_trace_redirect(unsigned long resume, unsigned long requested);
unsigned long hdn_rap_trace_retarget(unsigned long slot, unsigned long requested);
bool hdn_rap_livepatch_match(unsigned long original, unsigned long replacement);
bool hdn_rap_target_matches(unsigned long address, unsigned long reference);
bool hdn_rap_target_type_matches(unsigned long address, const struct hdn_rap_type *expected);
void hdn_rap_static_update(unsigned long key, unsigned long trampoline,
		unsigned long target);
void hdn_rap_static_transform(unsigned long site, unsigned long trampoline,
		unsigned long target, bool tail);
int hdn_rap_ftrace_prepare(void *image, size_t size, bool regs,
		const struct ftrace_ops *ops, unsigned long callback);
void hdn_rap_ftrace_release(void *image);
bool hdn_rap_ftrace_patch(unsigned long site, unsigned long target);
#else
#define HDN_RAP_TYPE_PROVIDER(name, type)
static inline int hdn_rap_check_build(struct hdn_rap_section build) { return 0; }
static inline int hdn_rap_module_prepare(struct module *mod,
		struct hdn_rap_section targets, struct hdn_rap_section types,
		struct hdn_rap_section sites, struct hdn_rap_section functions,
		struct hdn_rap_section static_calls,
		struct hdn_rap_section static_sites) { return 0; }
static inline void hdn_rap_module_release(struct module *mod) { }
static inline void hdn_rap_module_init_retire(struct module *mod) { }
static inline void hdn_rap_builtin_init_retire(void) { }
static inline int hdn_rap_task_prepare(struct task_struct *task, int node) { return 0; }
static inline int hdn_rap_boot_stack_prepare(unsigned long base, int node) { return 0; }
static inline int hdn_rap_task_seed(struct task_struct *task) { return 0; }
static inline void hdn_rap_task_release(struct task_struct *task) { }
static inline int hdn_rap_cpu_stack_prepare(unsigned long base, size_t size,
		int node, unsigned int cpu) { return 0; }
static inline void hdn_rap_context_seal(void) { }
static inline void hdn_rap_cpu_contexts_init(void) { }
static inline void hdn_rap_failure_init(void) { }
static inline const char *hdn_rap_state(void) { return "disabled"; }
static inline const char *hdn_rap_build_identity(void) { return "unavailable"; }
static inline bool hdn_rap_failure_stack(unsigned long address,
		unsigned long *begin, unsigned long *end) { return false; }
static inline void hdn_rap_boot_contexts_init(void) { }
static inline u64 hdn_rap_fixup_begin(struct pt_regs *regs, int trapnr) { return 0; }
static inline void hdn_rap_fixup_end(struct pt_regs *regs, u64 sequence,
		int trapnr, bool fixed) { }
static inline void hdn_rap_bug_end(struct pt_regs *regs, u64 sequence,
		bool handled) { }
static inline void hdn_rap_cp_end(struct pt_regs *regs, u64 sequence,
		bool selftest) { }
static inline bool hdn_rap_target_matches(unsigned long address,
		unsigned long reference) { return true; }
static inline bool hdn_rap_target_type_matches(unsigned long address,
		const struct hdn_rap_type *expected) { return true; }
static inline void hdn_rap_static_update(unsigned long key,
		unsigned long trampoline, unsigned long target) { }
static inline void hdn_rap_static_transform(unsigned long site,
		unsigned long trampoline, unsigned long target, bool tail) { }
static inline int hdn_rap_ftrace_prepare(void *image, size_t size, bool regs,
		const struct ftrace_ops *ops, unsigned long callback) { return 0; }
static inline void hdn_rap_ftrace_release(void *image) { }
static inline bool hdn_rap_ftrace_patch(unsigned long site, unsigned long target) { return true; }
static inline bool hdn_rap_livepatch_match(unsigned long original,
		unsigned long replacement) { return true; }
#endif

#endif
