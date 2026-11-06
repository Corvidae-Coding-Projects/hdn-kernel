/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_RAP_INTERNAL_H
#define _X86_HDN_RAP_INTERNAL_H

#include <linux/hdn_rap.h>

struct hdn_rap_module {
	const struct module *owner;
	struct hdn_rap_module *next;
	unsigned long header_pfn;
	unsigned long text, text_size, init_text, init_size, init_live;
	/* Compiler pointers are translated by offset into our sealed copy. */
	struct hdn_rap_section original_types, types, functions;
	struct hdn_rap_section static_calls, static_sites;
	size_t count, site_count;
	struct hdn_rap_target targets[];
};

/* Sealed identities for the finite ftrace template producer. They grant only
 * exact return-site admission, never permission to call arbitrary JIT text. */
struct hdn_rap_image {
	struct hdn_rap_image *next;
	unsigned long header_pfn, address, size, callback_site;
	size_t site_count;
	struct hdn_rap_target sites[];
};

extern struct hdn_rap_image *hdn_rap_images;
void hdn_rap_registry_synchronize(void);

enum hdn_rap_bpf_edge_kind {
	HDN_RAP_BPF_LOCAL = 1, HDN_RAP_BPF_TAIL, HDN_RAP_BPF_THROW,
	HDN_RAP_BPF_PATCH_TAIL, HDN_RAP_BPF_PATCH_BYPASS,
};
struct hdn_rap_bpf_edge {
	unsigned long site, kind, target;
};
struct hdn_rap_bpf_unlink {
	unsigned long link, start, end;
};
/* A program's identity and jump permissions survive independently of mutable
 * bpf_prog/aux and instruction-array storage. All pointers refer to this sealed
 * allocation, immutable builtin types, or opaque owner identities. */
struct hdn_rap_bpf_image {
	struct hdn_rap_bpf_image *next;
	unsigned long header_pfn, address, size, owner, active, trampoline;
	struct hdn_rap_target target;
	struct hdn_rap_function function;
	struct hdn_rap_function reference;
	struct hdn_rap_section types, template;
	unsigned long tramp_flags, original, skip, after_call, epilogue;
	struct hdn_rap_section unlink;
	unsigned long tail, boundary, frame_depth, exception, subprog;
	size_t edge_count, label_count, site_count;
	/* Edges, then label addresses, then bound CALL return-site records. */
	struct hdn_rap_bpf_edge edges[];
};
static inline const unsigned long *hdn_rap_bpf_labels(const struct hdn_rap_bpf_image *image)
{
	return (const void *)(image->edges + image->edge_count);
}
static inline const struct hdn_rap_target *hdn_rap_bpf_sites(const struct hdn_rap_bpf_image *image)
{
	return (const void *)(hdn_rap_bpf_labels(image) + image->label_count);
}
extern struct hdn_rap_bpf_image *hdn_rap_bpf_images;
const struct hdn_rap_bpf_image *hdn_rap_bpf_find(unsigned long address);
unsigned long hdn_rap_bpf_validate_jump(unsigned long target, unsigned long site);
unsigned long hdn_rap_bpf_dispatch_target(unsigned long target);
int hdn_rap_function_copy(unsigned long address, struct hdn_rap_function *function,
		struct hdn_rap_type *type, size_t capacity);
unsigned long hdn_rap_bpf_original_target(unsigned long site, unsigned long resume);
bool hdn_rap_trace_compatible(unsigned long resume, const struct hdn_rap_type *expected);

extern struct hdn_rap_module *hdn_rap_modules;
extern unsigned long hdn_rap_builtin_init_live;
extern const struct hdn_rap_build __hdn_rap_build_start[], __hdn_rap_build_end[];
extern const struct hdn_rap_target __hdn_rap_targets_start[], __hdn_rap_targets_end[];
extern const struct hdn_rap_target __hdn_rap_sites_start[], __hdn_rap_sites_end[];
extern const struct hdn_rap_function __hdn_rap_entries_start[], __hdn_rap_entries_end[];
extern const struct hdn_rap_static_call __hdn_rap_static_calls_start[], __hdn_rap_static_calls_end[];
extern const struct hdn_rap_static_site __hdn_rap_static_sites_start[], __hdn_rap_static_sites_end[];
extern const char __hdn_rap_types_start[], __hdn_rap_types_end[];

#endif
