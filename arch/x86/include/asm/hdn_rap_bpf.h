/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_BPF_H
#define _ASM_X86_HDN_RAP_BPF_H

#ifdef CONFIG_SECURITY_HARDENING_RAP
#define HDN_BPF_RAP_ENTRY_SIZE 12
#define HDN_BPF_RAP_BIND_SIZE 7
#else
#define HDN_BPF_RAP_ENTRY_SIZE 0
#define HDN_BPF_RAP_BIND_SIZE 0
#endif

#ifndef __ASSEMBLY__
#include <linux/hdn_rap.h>

struct bpf_prog;
struct bpf_tramp_unlink;
struct hdn_rap_bpf_layout {
	unsigned int entry, tail, boundary, bhb;
};
struct hdn_rap_bpf_tramp_layout {
	unsigned int entry, original, skip, after_call, epilogue, size;
	unsigned int nr_unlink;
	const struct bpf_tramp_unlink *unlink;
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_program;
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_trampoline_enter;
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_trampoline_exit;
int hdn_rap_bpf_prepare(const struct bpf_prog *prog, void *code, size_t size,
		const int *offsets, const struct hdn_rap_bpf_layout *layout);
void hdn_rap_bpf_release(void *code);
unsigned long hdn_rap_bpf_throw_info(unsigned long *sp, unsigned long *bp);
bool hdn_rap_bpf_tail_patch(unsigned long site, unsigned long target);
unsigned long hdn_rap_bpf_patch_address(unsigned long address);
int hdn_rap_bpf_text_patch(unsigned long site, int kind, unsigned long *target);
bool hdn_rap_bpf_unlink_check(unsigned long image, unsigned long link,
		unsigned long start, unsigned long end);
int hdn_rap_bpf_dispatcher_prepare(void *code, const s64 *funcs, unsigned int count);
int hdn_rap_bpf_trampoline_stage(void *code, const void *bytes, size_t size,
		u32 flags, unsigned long reference, const struct hdn_rap_bpf_tramp_layout *layout);
int hdn_rap_bpf_trampoline_publish(void *code, size_t size);
void hdn_rap_bpf_release_range(void *code, size_t size);
void __hdn_rap_enter(void);
void __hdn_rap_return(void);
void __hdn_rap_bpf_jump(void);
void __hdn_rap_bpf_boundary(void);
void __hdn_rap_bpf_exception(void);
void __hdn_rap_bpf_dispatch(void);
void __hdn_rap_bpf_tramp_enter(void);
void __hdn_rap_bpf_original(void);
void __hdn_rap_bpf_skip(void);
#else
static inline int hdn_rap_bpf_prepare(const struct bpf_prog *prog, void *code,
		size_t size, const int *offsets, const struct hdn_rap_bpf_layout *layout)
{
	return 0;
}
static inline void hdn_rap_bpf_release(void *code) { }
static inline bool hdn_rap_bpf_tail_patch(unsigned long site, unsigned long target) { return true; }
static inline bool hdn_rap_bpf_unlink_check(unsigned long image, unsigned long link,
		unsigned long start, unsigned long end) { return true; }
static inline int hdn_rap_bpf_trampoline_stage(void *code, const void *bytes, size_t size,
		u32 flags, unsigned long reference, const struct hdn_rap_bpf_tramp_layout *layout) { return 0; }
static inline int hdn_rap_bpf_trampoline_publish(void *code, size_t size) { return 0; }
static inline void hdn_rap_bpf_release_range(void *code, size_t size) { }
#endif
#endif
#endif
