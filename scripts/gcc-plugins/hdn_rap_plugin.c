// SPDX-License-Identifier: GPL-2.0-only
/* HDN type identities and late indirect-call transfer adapters. */
#include "gcc-common.h"
#undef gimple
#include "insn-constants.h"
#include "insn-codes.h"
#include "df.h"
#include <openssl/sha.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;
static const char *build_id, *source_root, *profile;
static int report_fd = -1;
static unsigned long sequence;
static bool runtime_unit;
static bool bootstrap_unit;
static unsigned long report_records;
static std::set<tree> named_type_seen;
static std::vector<tree> named_types;
struct identity {
	std::string canonical, label;
	unsigned char digest[SHA256_DIGEST_LENGTH];
};
struct call_site { tree function; identity *type; bool consumed; };
static std::map<std::string, identity> identities;
static std::map<unsigned long, call_site> sites;
struct jump_target { std::string label; identity *type; };
static std::vector<jump_target> jump_targets;
static std::vector<jump_target> return_sites;
struct jump_edge { std::string site, target; };
static std::vector<jump_edge> jump_edges;
static std::vector<jump_edge> static_sites;
static std::map<std::string, identity *> typed_thunks;
struct function_coverage { tree decl; unsigned int returns; bool runtime; };
static std::vector<function_coverage> coverage;
struct function_entry { tree decl; identity *type; std::string body, trace_return; };
static std::vector<function_entry> function_entries;

static const char *decl_name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "<anonymous>";
}

static const char *tag_name(tree type)
{
	tree name = TYPE_NAME(TYPE_MAIN_VARIANT(type));
	if (!name)
		return NULL;
	return TREE_CODE(name) == IDENTIFIER_NODE ? IDENTIFIER_POINTER(name) : decl_name(name);
}

static void remember_tag(tree type)
{
	type = TYPE_MAIN_VARIANT(type);
	if ((TREE_CODE(type) == RECORD_TYPE || TREE_CODE(type) == UNION_TYPE ||
	     TREE_CODE(type) == ENUMERAL_TYPE) && tag_name(type) && named_type_seen.insert(type).second)
		named_types.push_back(type);
}

static bool enum_values(std::string &out, tree type)
{
	out += '{';
	for (tree value = TYPE_VALUES(type); value; value = TREE_CHAIN(value)) {
		tree number = TREE_VALUE(value);
		if (number && TREE_CODE(number) == CONST_DECL)
			number = DECL_INITIAL(number);
		if (!number || !TREE_PURPOSE(value) || TREE_CODE(TREE_PURPOSE(value)) != IDENTIFIER_NODE ||
		    (!tree_fits_shwi_p(number) && !tree_fits_uhwi_p(number)))
			return false;
		out += std::string(IDENTIFIER_POINTER(TREE_PURPOSE(value))) + '=' +
			(tree_fits_shwi_p(number) ? std::to_string(tree_to_shwi(number)) :
			 std::to_string(tree_to_uhwi(number))) + ';';
	}
	out += '}';
	return true;
}

/* Explicit type classes, independent of GCC's numeric tree-code enumeration.
 * Named record pointer targets use the C tag; the whole-build gate must reject
 * contradictory definitions of the same tag. Complete by-value layouts retain
 * member types and offsets. Unknown and unprototyped types fail compilation.
 */
static bool canonical_type(std::string &out, tree type, unsigned int depth = 0,
		size_t limit = 16384)
{
	if (!type || depth > 64 || out.size() > limit)
		return false;
	out += "q" + std::to_string(TYPE_QUALS(type)) + ":";
	type = TYPE_MAIN_VARIANT(type);
	remember_tag(type);
	switch (TREE_CODE(type)) {
	case VOID_TYPE: out += "void"; break;
	case BOOLEAN_TYPE: out += "bool"; break;
	case INTEGER_TYPE:
		out += TYPE_UNSIGNED(type) ? "unsigned:" : "signed:";
		out += std::to_string(TYPE_PRECISION(type));
		if (type == char_type_node) out += ":char";
		else if (type == signed_char_type_node || type == unsigned_char_type_node) out += ":schar";
		else if (type == short_integer_type_node || type == short_unsigned_type_node) out += ":short";
		else if (type == integer_type_node || type == unsigned_type_node) out += ":int";
		else if (type == long_integer_type_node || type == long_unsigned_type_node) out += ":long";
		else if (type == long_long_integer_type_node || type == long_long_unsigned_type_node) out += ":llong";
		else out += ":extended";
		break;
	case ENUMERAL_TYPE:
		out += "enum:" + std::string(tag_name(type) ? tag_name(type) : "<anonymous>") + ':' +
			std::to_string(TYPE_PRECISION(type));
		out += TYPE_UNSIGNED(type) ? ":unsigned" : ":signed";
		if (!tag_name(type) && !enum_values(out, type)) return false;
		break;
	case REAL_TYPE:
		out += "real:" + std::to_string(TYPE_PRECISION(type));
		break;
	case POINTER_TYPE: {
		tree to = TREE_TYPE(type), main = TYPE_MAIN_VARIANT(to);
		out += "ptr(";
		if ((TREE_CODE(main) == RECORD_TYPE || TREE_CODE(main) == UNION_TYPE) && tag_name(main)) {
			remember_tag(main);
			out += TREE_CODE(main) == RECORD_TYPE ? "struct:" : "union:";
			out += tag_name(main);
			out += ":q" + std::to_string(TYPE_QUALS(to));
		} else if (!canonical_type(out, to, depth + 1, limit)) return false;
		out += ')';
		break;
	}
	case ARRAY_TYPE:
		if (!TYPE_SIZE(type) && TYPE_DOMAIN(type) && TYPE_MAX_VALUE(TYPE_DOMAIN(type))) return false;
		if (TYPE_SIZE(type) && !tree_fits_uhwi_p(TYPE_SIZE(type))) return false;
		out += "array:" + (TYPE_SIZE(type) ? std::to_string(tree_to_uhwi(TYPE_SIZE(type))) : "unbounded") + '(';
		if (!canonical_type(out, TREE_TYPE(type), depth + 1, limit)) return false;
		out += ')';
		break;
	case RECORD_TYPE:
	case UNION_TYPE:
		if (!COMPLETE_TYPE_P(type) || !TYPE_SIZE(type) || !tree_fits_uhwi_p(TYPE_SIZE(type))) return false;
		out += TREE_CODE(type) == RECORD_TYPE ? "struct{" : "union{";
		if (tag_name(type)) out += tag_name(type);
		out += ":bits=" + std::to_string(tree_to_uhwi(TYPE_SIZE(type))) +
			":align=" + std::to_string(TYPE_ALIGN(type));
		for (tree field = TYPE_FIELDS(type); field; field = DECL_CHAIN(field)) {
			if (TREE_CODE(field) != FIELD_DECL) continue;
			bool flexible = TREE_CODE(TREE_TYPE(field)) == ARRAY_TYPE && !TYPE_SIZE(TREE_TYPE(field));
			if (!DECL_FIELD_OFFSET(field) || !tree_fits_uhwi_p(DECL_FIELD_OFFSET(field)) ||
			    !DECL_FIELD_BIT_OFFSET(field) || !tree_fits_uhwi_p(DECL_FIELD_BIT_OFFSET(field)) ||
			    (!flexible && (!DECL_SIZE(field) || !tree_fits_uhwi_p(DECL_SIZE(field))))) return false;
			out += ';' + std::string(decl_name(field)) + '@' +
				std::to_string(tree_to_uhwi(DECL_FIELD_OFFSET(field))) + ':' +
				std::to_string(tree_to_uhwi(DECL_FIELD_BIT_OFFSET(field))) + ':' +
				(flexible ? "flex" : std::to_string(tree_to_uhwi(DECL_SIZE(field)))) + '=';
			if (!canonical_type(out, TREE_TYPE(field), depth + 1, limit)) return false;
		}
		out += '}';
		break;
	case FUNCTION_TYPE: {
		out += "fn(";
		if (!canonical_type(out, TREE_TYPE(type), depth + 1, limit)) return false;
		if (!TYPE_ARG_TYPES(type)) {
			/* Layout evidence may describe a legacy pointer field, but a
			 * callable identity with unspecified arguments remains forbidden. */
			if (limit <= 16384) return false;
			out += ";unspecified-arguments";
		}
		tree arg;
		for (arg = TYPE_ARG_TYPES(type); arg; arg = TREE_CHAIN(arg)) {
			out += ';';
			if (!canonical_type(out, TREE_VALUE(arg), depth + 1, limit)) return false;
		}
		out += ")abi:";
		out += lookup_attribute("ms_abi", TYPE_ATTRIBUTES(type)) ? "ms" : "sysv";
		if (lookup_attribute("regparm", TYPE_ATTRIBUTES(type)) ||
		    lookup_attribute("fastcall", TYPE_ATTRIBUTES(type)) ||
		    lookup_attribute("stdcall", TYPE_ATTRIBUTES(type)) ||
		    lookup_attribute("thiscall", TYPE_ATTRIBUTES(type))) return false;

		break;
	}
	default: return false;
	}
	return out.size() <= limit;
}

static identity *canonical_identity(const std::string &canonical)
{
	if (canonical.empty() || canonical.size() > 16384) {
		error(G_("HDN RAP type or local label set exceeds the metadata limit"));
		return NULL;
	}
	auto found = identities.find(canonical);
	if (found != identities.end()) return &found->second;
	identity value;
	value.canonical = canonical;
	value.label = ".Lhdn_rap_type_" + std::to_string(identities.size());
	std::string domain = "HDN-RAP-TYPE-v1;build=" + std::string(build_id) + ";type=" + canonical;
	SHA256((const unsigned char *)domain.data(), domain.size(), value.digest);
	return &identities.emplace(canonical, value).first->second;
}

static identity *get_identity(tree type, location_t loc)
{
	std::string canonical;
	if (!canonical_type(canonical, type)) {
		error_at(loc, G_("HDN RAP cannot represent this control-transfer type"));
		return NULL;
	}
	return canonical_identity(canonical);
}

static std::string quote(const std::string &value)
{
	std::string out = "\"";
	for (unsigned char c : value) {
		if (c == '"' || c == '\\') out += '\\', out += c;
		else if (c < 32) {
			char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", c); out += buf;
		} else out += c;
	}
	return out + '"';
}

static std::string relative(const char *path)
{
	if (!path) return "<unknown>";
	size_t n = strlen(source_root);
	if (!strncmp(path, source_root, n) && path[n] == '/') path += n + 1;
	while (path[0] == '.' && path[1] == '/') path += 2;
	return path;
}

static void report(const char *kind, tree fn, location_t loc, identity *type,
		unsigned long site = 0, const std::string &tag = "")
{
	expanded_location place = expand_location(loc);
	std::string hash;
	if (type) for (unsigned char c : type->digest) {
		char byte[3]; snprintf(byte, sizeof(byte), "%02x", c); hash += byte;
	}
	std::string row = "{\"schema_version\":1,\"analyzer_version\":2,\"kind\":" + quote(kind) +
		",\"unit\":" + quote(relative(main_input_filename)) + ",\"file\":" + quote(relative(place.file)) +
		",\"line\":" + std::to_string(place.line) + ",\"column\":" + std::to_string(place.column) +
		",\"profile\":" + quote(profile) + ",\"build_id\":" + quote(build_id) +
		",\"compiler\":" + quote(version_string) + ",\"function\":" + quote(decl_name(fn)) +
		",\"runtime_unit\":" + (runtime_unit ? "true" : "false") +
		",\"bootstrap_unit\":" + (bootstrap_unit ? "true" : "false") +
		",\"symbol\":" + quote(fn ? IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fn)) : "<unit>") +
		",\"site\":" + std::to_string(site) + ",\"hash\":" + quote(hash) +
		",\"canonical\":" + quote(type ? type->canonical : "") +
		",\"tag\":" + quote(tag) + ",\"records\":" + std::to_string(report_records) +
		",\"errors\":" + std::to_string(errorcount) + "}\n";
	report_records++;
	while (flock(report_fd, LOCK_EX)) if (errno != EINTR) {
		error(G_("cannot lock HDN RAP report")); return;
	}
	for (size_t done = 0; done < row.size();) {
		ssize_t count = write(report_fd, row.data() + done, row.size() - done);
		if (count > 0) done += count;
		else if (count < 0 && errno == EINTR) continue;
		else { error(G_("cannot write HDN RAP report")); break; }
	}
	if (flock(report_fd, LOCK_UN)) error(G_("cannot unlock HDN RAP report"));
}

static unsigned int hdn_rap_sites_execute(void)
{
	basic_block bb;
	FOR_EACH_BB_FN(bb, cfun) {
		for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
			gimple *stmt = gsi_stmt(it);
			if (gimple_code(stmt) == GIMPLE_GOTO &&
			    TREE_CODE(gimple_goto_dest(stmt)) != LABEL_DECL) {
				if (bootstrap_unit) {
					error_at(gimple_location(stmt), G_("HDN bootstrap cannot use computed transfers"));
					continue;
				}
				/* Final RTL supplies the function's preserved address-taken
				 * labels; the checked transfer shares the switch-table ABI. */
				report("computed-local-site", current_function_decl, gimple_location(stmt), NULL);
				continue;
			}
			if (!is_gimple_call(stmt) || gimple_call_internal_p(stmt) || gimple_call_fndecl(stmt)) continue;
			if (bootstrap_unit) {
				error_at(gimple_location(stmt), G_("HDN bootstrap cannot use indirect calls"));
				continue;
			}
			gcall *call = as_a<gcall *>(stmt);
			identity *type = get_identity(gimple_call_fntype(call), gimple_location(call));
			if (!type) continue;
			unsigned long id = ++sequence;
			sites[id] = {current_function_decl, type, false};
			std::string marker = "# HDN_RAP_SITE:" + std::to_string(id);
			vec<tree, va_gc> *inputs = NULL, *clobbers = NULL;
			tree constraint = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
			vec_safe_push(inputs, build_tree_list(constraint, gimple_call_fn(call)));
			vec_safe_push(clobbers, build_tree_list(NULL_TREE, build_const_char_string(7, "memory")));
			gasm *tag = gimple_build_asm_vec(marker.c_str(), inputs, NULL, clobbers, NULL);
			gimple_asm_set_volatile(tag, true);
			gimple_set_location(tag, gimple_location(call));
			gsi_insert_before(&it, tag, GSI_SAME_STMT);
			gimple_call_set_tail(call, false);
			report("indirect-site", current_function_decl, gimple_location(call), type, id);
		}
	}
	return TODO_update_ssa;
}
#define PASS_NAME hdn_rap_sites
#define PROPERTIES_REQUIRED PROP_ssa
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

static rtx find_code(rtx value, enum rtx_code code)
{
	if (!value) return NULL_RTX;
	if (GET_CODE(value) == code) return value;
	const char *format = GET_RTX_FORMAT(GET_CODE(value));
	for (int i = 0; i < GET_RTX_LENGTH(GET_CODE(value)); i++) {
		if (format[i] == 'e') {
			rtx found = find_code(XEXP(value, i), code);
			if (found) return found;
		} else if (format[i] == 'E') for (int j = 0; j < XVECLEN(value, i); j++) {
			rtx found = find_code(XVECEXP(value, i, j), code);
			if (found) return found;
		}
	}
	return NULL_RTX;
}

/* After register allocation, move the already evaluated target to r11.
 * The late pass binds r10 to the exact return-site label (whose immutable
 * metadata contains the type). The assembly transfer thunk preserves the ABI's
 * arguments, validates the target, and performs the transfer itself. No C check
 * followed by a reload of an unchecked indirect target is emitted here. */
static unsigned int hdn_rap_transfers_execute(void)
{
	if (bootstrap_unit) return 0;
	unsigned long pending = 0;
	for (rtx_insn *insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		if (!INSN_P(insn)) continue;
		rtx marker = find_code(PATTERN(insn), ASM_OPERANDS);
		if (marker && !strncmp(ASM_OPERANDS_TEMPLATE(marker), "# HDN_RAP_SITE:", 15)) {
			if (pending) error_at(INSN_LOCATION(insn), G_("HDN RAP ambiguous reordered call markers"));
			pending = strtoul(ASM_OPERANDS_TEMPLATE(marker) + 15, NULL, 10);
			continue;
		}
		if (!CALL_P(insn)) continue;
		rtx call = find_code(PATTERN(insn), CALL);
		if (!call || !MEM_P(XEXP(call, 0))) continue;
		rtx target = XEXP(XEXP(call, 0), 0);
		if (GET_CODE(target) == SYMBOL_REF) continue;
		auto found = sites.find(pending);
		if (!pending || found == sites.end() || found->second.function != current_function_decl ||
		    found->second.consumed || SIBLING_CALL_P(insn)) {
			error_at(INSN_LOCATION(insn), G_("HDN RAP indirect transfer has no unique typed site"));
			continue;
		}
		identity *type = found->second.type;
		rtx r10 = gen_rtx_REG(Pmode, R10_REG), r11 = gen_rtx_REG(Pmode, R11_REG);
		start_sequence();
		emit_move_insn(r11, target);
		rtx_insn *moves = get_insns();
		end_sequence();
		emit_insn_before(moves, insn);
		/* Keep the expected type in the call's RTL identity through all late
		 * scheduling, duplication and dead-code removal. Instruction UIDs do
		 * not survive those transformations. Distinct types must not become
		 * interchangeable calls to a common symbol before optimization ends. */
		std::string thunk_name = ".Lhdn_rap_call" + type->label;
		typed_thunks[thunk_name] = type;
		rtx thunk = gen_rtx_SYMBOL_REF(Pmode, ggc_strdup(thunk_name.c_str()));
		/* The runtime is linked into vmlinux (and exported for modules).
		 * Never lower this adapter through a mutable GOT entry, including
		 * when the translation unit was compiled with -fno-plt. */
		SYMBOL_REF_FLAGS(thunk) |= SYMBOL_FLAG_FUNCTION | SYMBOL_FLAG_LOCAL;
		XEXP(XEXP(call, 0), 0) = thunk;
		CALL_INSN_FUNCTION_USAGE(insn) = alloc_EXPR_LIST(0, gen_rtx_USE(VOIDmode, r10),
			alloc_EXPR_LIST(0, gen_rtx_USE(VOIDmode, r11), CALL_INSN_FUNCTION_USAGE(insn)));
		INSN_CODE(insn) = -1;
		df_insn_rescan(insn);
		found->second.consumed = true;
		report("checked-transfer", current_function_decl, INSN_LOCATION(insn), type, pending);
		pending = 0;
	}
	if (pending) error(G_("HDN RAP call marker has no indirect transfer"));
	return 0;
}
#define PASS_NAME hdn_rap_transfers
#define NO_GATE
#include "gcc-generate-rtl-pass.h"

/* Run after machine scheduling and ENDBR insertion, before instruction
 * shortening. These adapters preserve every live register and flags; unlike a
 * normal C call they cannot change leaf-function allocation or argument layout.
 * No scheduler is allowed to move work ahead of the protected entry afterwards.
 */
static unsigned int hdn_rap_returns_execute(void)
{
	if (bootstrap_unit) {
		if (crtl->profile)
			error(G_("HDN bootstrap cannot be profiled"));
		coverage.push_back({current_function_decl, 0, false});
		report("bootstrap-function", current_function_decl, DECL_SOURCE_LOCATION(current_function_decl), NULL);
		return 0;
	}
	rtx_insn *first = NULL;
	unsigned int returns = 0;
	bool trace_entry = crtl->profile;
	bool entry_endbr = false;
	identity *jump_type = NULL;
	std::set<int> labels;
	rtx_insn *forced;
	unsigned int index;

	/* GCC normally prints __fentry__ outside RTL, before this prologue.
	 * Capture the caller first, then emit the identical patchable CALL with
	 * an explicit R10 binding. Runtime recursion-boundary units cannot trace. */
	if (trace_entry) {
		if (runtime_unit || !flag_fentry || flag_nop_mcount || fentry_name || fentry_section) {
			error_at(DECL_SOURCE_LOCATION(current_function_decl),
				G_("HDN RAP requires the standard unmodified fentry ABI"));
			return 0;
		}
		crtl->profile = false;
	}

	FOR_EACH_VEC_SAFE_ELT(forced_labels, index, forced) {
		if (!LABEL_P(forced) || INSN_DELETED_P(forced)) {
			error(G_("HDN RAP address-taken label did not survive lowering"));
			continue;
		}
		LABEL_PRESERVE_P(forced) = 1;
		labels.insert(CODE_LABEL_NUMBER(forced));
	}

	for (rtx_insn *insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		if (!JUMP_TABLE_DATA_P(insn)) continue;
		rtx table = PATTERN(insn);
		int index = GET_CODE(table) == ADDR_DIFF_VEC ? 1 : 0;
		for (int n = 0; n < XVECLEN(table, index); n++) {
			rtx ref = XVECEXP(table, index, n);
			if (GET_CODE(ref) != LABEL_REF) {
				error(G_("HDN RAP unknown jump table representation")); continue;
			}
			rtx_code_label *label = as_a<rtx_code_label *>(XEXP(ref, 0));
			LABEL_PRESERVE_P(label) = 1;
			labels.insert(CODE_LABEL_NUMBER(label));
		}
	}
	if (!labels.empty()) {
		std::string canonical = "local-label-set:" + relative(main_input_filename) + ':' +
			IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(current_function_decl));
		for (int number : labels) canonical += ':' + std::to_string(number);
		jump_type = canonical_identity(canonical);
		if (!jump_type) return 0;
		for (int number : labels) {
			char label[128];
			ASM_GENERATE_INTERNAL_LABEL(label, "L", number);
			jump_targets.push_back({label, jump_type});
		}
	}

	if (lookup_attribute("naked", DECL_ATTRIBUTES(current_function_decl)) ||
	    lookup_attribute("ms_abi", TYPE_ATTRIBUTES(TREE_TYPE(current_function_decl)))) {
		error_at(DECL_SOURCE_LOCATION(current_function_decl),
			G_("HDN RAP requires an explicitly audited assembly ABI adapter"));
		return 0;
	}
	for (rtx_insn *insn = get_insns(), *next; insn; insn = next) {
		next = NEXT_INSN(insn);
		if (!INSN_P(insn)) continue;
		/* Computed-goto RTL can have no source location. GCC's final basic
		 * asm emitter expects a real file for our generated ASM_INPUT. */
		location_t location = LOCATION_LOCUS(INSN_LOCATION(insn));
		/* An ad-hoc location can wrap UNKNOWN_LOCATION while its numeric
		 * value exceeds BUILTINS_LOCATION. GCC's basic-asm printer requires
		 * an actual filename, including for these late merged call sites. */
		if (location <= BUILTINS_LOCATION || !expand_location(location).file)
			location = LOCATION_LOCUS(DECL_SOURCE_LOCATION(current_function_decl));
		if (!expand_location(location).file) {
			error(G_("HDN RAP cannot locate generated control-transfer assembly"));
			return 0;
		}
		rtx endbr = find_code(PATTERN(insn), UNSPEC_VOLATILE);
		if (!first && endbr && XINT(endbr, 1) == UNSPECV_NOP_ENDBR)
			entry_endbr = true;
		if (!first && !(endbr && XINT(endbr, 1) == UNSPECV_NOP_ENDBR))
			first = insn;
		/* These exact stack-depth and scheduler calls use register-preserving
		 * assembly ABIs, so GCC does not emit CALL_INSN RTL. Bind only these
		 * reviewed templates; arbitrary opaque calls still fail coverage. */
		rtx opaque = find_code(PATTERN(insn), ASM_OPERANDS);
		const char *opaque_text = opaque ? ASM_OPERANDS_TEMPLATE(opaque) : "";
		bool stack_depth = !strcmp(opaque_text, "call __sanitizer_cov_stack_depth");
		bool preempt_call = !strcmp(opaque_text, "call __SCT__preempt_schedule") ||
			!strcmp(opaque_text, "call __SCT__preempt_schedule_notrace") ||
			!strcmp(opaque_text, "call preempt_schedule_thunk") ||
			!strcmp(opaque_text, "call preempt_schedule_notrace_thunk");
		if (stack_depth || preempt_call) {
			if (runtime_unit || !fixed_regs[R10_REG] || !fixed_regs[R11_REG]) {
				error_at(location, G_("HDN RAP opaque adapter requires ordinary instrumentation and reserved registers"));
				continue;
			}
			std::string label = ".Lhdn_rap_opaque_" + std::to_string(++sequence);
			std::string code = "leaq " + label + "(%%rip), %%r10\n\t"
				+ opaque_text + '\n' + label + ':';
			ASM_OPERANDS_TEMPLATE(opaque) = ggc_strdup(code.c_str());
			INSN_CODE(insn) = -1;
			return_sites.push_back({label, NULL});
			if (preempt_call && !strncmp(opaque_text + 5, "__SCT__", 7))
				static_sites.push_back({label, opaque_text + 5});
			report(stack_depth ? "protected-stack-depth" : "protected-preempt",
				current_function_decl, location, NULL, sequence);
		}
		if (CALL_P(insn)) {
			rtx call = find_code(PATTERN(insn), CALL);
			rtx target = call && MEM_P(XEXP(call, 0)) ? XEXP(XEXP(call, 0), 0) : NULL_RTX;
			if (!target || GET_CODE(target) != SYMBOL_REF || SIBLING_CALL_P(insn) ||
			    !fixed_regs[R10_REG] || !fixed_regs[R11_REG]) {
				error_at(INSN_LOCATION(insn), G_("HDN RAP unclassified late call or missing reserved registers"));
				continue;
			}
			identity *type = NULL;
			auto typed = typed_thunks.find(XSTR(target, 0));
			if (typed != typed_thunks.end()) {
				type = typed->second;
			} else if (!strcmp(XSTR(target, 0), "__hdn_rap_call") ||
				   !strncmp(XSTR(target, 0), ".Lhdn_rap_call",
					    sizeof(".Lhdn_rap_call") - 1)) {
				error_at(INSN_LOCATION(insn), G_("HDN RAP lost typed call during scheduling"));
				continue;
			}
			std::string label = ".Lhdn_rap_return_" + std::to_string(++sequence);
			start_sequence();
			emit_move_insn(gen_rtx_REG(Pmode, R10_REG),
				gen_rtx_SYMBOL_REF(Pmode, ggc_strdup(label.c_str())));
			rtx_insn *binding = get_insns();
			end_sequence();
			emit_insn_before(binding, insn);
			if (first == insn) first = binding;
			emit_insn_after(gen_rtx_ASM_INPUT_loc(VOIDmode, ggc_strdup((label + ':').c_str()),
				location), insn);
			return_sites.push_back({label, type});
			const char *direct = XSTR(target, 0);
			if (*direct == '*') direct++;
			if (!strncmp(direct, "__SCT__", 7)) {
				tree decl = SYMBOL_REF_DECL(target);
				identity *prototype = decl ? get_identity(TREE_TYPE(decl), location) : NULL;
				if (!prototype)
					error_at(location, G_("HDN RAP static call lacks its declared prototype"));
				else
					report("public-type-anchor", decl, location, prototype);
				static_sites.push_back({label, direct});
			}
			report("protected-call-site", current_function_decl, INSN_LOCATION(insn), type, sequence);
		}
		if (JUMP_P(insn)) {
			rtx set = single_set(insn);
			if (set && SET_DEST(set) == pc_rtx &&
			    (REG_P(SET_SRC(set)) || MEM_P(SET_SRC(set)))) {
				if (!jump_type || !fixed_regs[R10_REG] || !fixed_regs[R11_REG]) {
					error_at(INSN_LOCATION(insn), G_("HDN RAP indirect jump lacks a closed label set or reserved transfer registers"));
					continue;
				}
				start_sequence();
				emit_move_insn(gen_rtx_REG(Pmode, R11_REG), SET_SRC(set));
				emit_move_insn(gen_rtx_REG(Pmode, R10_REG),
					gen_rtx_SYMBOL_REF(Pmode, ggc_strdup(jump_type->label.c_str())));
				rtx_insn *moves = get_insns();
				end_sequence();
				emit_insn_before(moves, insn);
				if (first == insn) first = moves;
				std::string site = ".Lhdn_rap_jump_" + std::to_string(++sequence);
				std::string code = site + ":\n\tcall __hdn_rap_jump\n\tud2";
				emit_insn_before(gen_rtx_ASM_INPUT_loc(VOIDmode,
					ggc_strdup(code.c_str()), location), insn);
				for (int number : labels) {
					char label[128];
					ASM_GENERATE_INTERNAL_LABEL(label, "L", number);
					jump_edges.push_back({site, label});
				}
				report("checked-local-jump", current_function_decl, INSN_LOCATION(insn), jump_type);
				delete_insn(insn);
				continue;
			}
		}
		if (runtime_unit || !JUMP_P(insn) || (!find_code(PATTERN(insn), RETURN) &&
				     !find_code(PATTERN(insn), SIMPLE_RETURN))) continue;
		/* A pop-return or opaque parallel return carries an additional ABI
		 * transition. Reject it instead of silently dropping that operation. */
		if (GET_CODE(PATTERN(insn)) != RETURN && GET_CODE(PATTERN(insn)) != SIMPLE_RETURN) {
			error_at(INSN_LOCATION(insn), G_("HDN RAP unsupported compound return sequence"));
			continue;
		}
		rtx_insn *transfer = emit_insn_before(gen_rtx_ASM_INPUT_loc(VOIDmode,
			ggc_strdup("jmp __hdn_rap_return"), location), insn);
		MEM_VOLATILE_P(PATTERN(transfer)) = 1;
		if (first == insn) first = transfer;
		delete_insn(insn);
		returns++;
		report("protected-return", current_function_decl, INSN_LOCATION(transfer), NULL);
	}
	if (first && !runtime_unit) {
		std::string continuation = ".Lhdn_rap_entry_" + std::to_string(++sequence);
		std::string trace_return = "0";
		std::string code = "leaq " + continuation + "(%rip), %r11\n\tcall __hdn_rap_enter\n" + continuation + ':';
		/* With -mfentry GCC prints ENDBR with its out-of-RTL profiling
		 * sequence. Disabling that sequence must retain the IBT landing pad. */
		if (trace_entry && !entry_endbr && (flag_cf_protection & CF_BRANCH))
			code = "endbr64\n\t" + code;
		if (trace_entry) {
			std::string trace = ".Lhdn_rap_fentry_" + std::to_string(sequence);
			std::string resume = trace + "_return";
			trace_return = resume;
			code += "\n\tleaq " + resume + "(%rip), %r10\n" + trace +
				":\n\tcall __fentry__\n" + resume + ':';
			if (flag_record_mcount)
				code += "\n\t.pushsection __mcount_loc,\"a\",@progbits\n\t.balign 8\n\t.quad " +
					trace + "\n\t.popsection";
			return_sites.push_back({resume, NULL});
			report("protected-fentry", current_function_decl,
				DECL_SOURCE_LOCATION(current_function_decl), NULL);
		}
		rtx_insn *entry = emit_insn_before(gen_rtx_ASM_INPUT_loc(VOIDmode,
			ggc_strdup(code.c_str()), DECL_SOURCE_LOCATION(current_function_decl)), first);
		MEM_VOLATILE_P(PATTERN(entry)) = 1;
		identity *type = get_identity(TREE_TYPE(current_function_decl),
				DECL_SOURCE_LOCATION(current_function_decl));
		if (type)
			function_entries.push_back({current_function_decl, type, continuation, trace_return});
		report("protected-entry", current_function_decl, DECL_SOURCE_LOCATION(current_function_decl), NULL, returns);
	}
	if (!runtime_unit && TREE_THIS_VOLATILE(current_function_decl)) {
		if (returns) error(G_("HDN RAP noreturn function emitted a return"));
		report("noreturn-entry", current_function_decl, DECL_SOURCE_LOCATION(current_function_decl), NULL);
	}
	coverage.push_back({current_function_decl, returns, runtime_unit});
	return 0;
}
#define PASS_NAME hdn_rap_returns
#define NO_GATE
#include "gcc-generate-rtl-pass.h"

static void bytes(const unsigned char *value, size_t size)
{
	for (size_t i = 0; i < size; i++) fprintf(asm_out_file, "\t.byte %u\n", value[i]);
}

static void report_tags(void)
{
	/* Walk a growing queue: record layouts can introduce further named
	 * pointer targets. Incomplete tags still emit a reference which the
	 * whole-build gate compares all complete definitions; tags which remain
	 * opaque everywhere are identified separately in its output. */
	for (size_t i = 0; i < named_types.size(); i++) {
		tree type = named_types[i];
		std::string tag = TREE_CODE(type) == RECORD_TYPE ? "struct:" :
			TREE_CODE(type) == UNION_TYPE ? "union:" : "enum:";
		tag += tag_name(type);
		report("tag-reference", NULL_TREE, UNKNOWN_LOCATION, NULL, 0, tag);
		if (!COMPLETE_TYPE_P(type)) continue;
		identity layout;
		if (!canonical_type(layout.canonical, type, 0, 1 << 20)) {
			error(G_("HDN RAP cannot represent referenced tag %s"), tag.c_str());
			continue;
		}
		if (TREE_CODE(type) == ENUMERAL_TYPE) {
			if (!enum_values(layout.canonical, type)) {
				error(G_("HDN RAP cannot represent enum %s"), tag.c_str());
				continue;
			}
		}
		std::string domain = "HDN-RAP-TYPE-v1;build=" + std::string(build_id) + ";type=" + layout.canonical;
		SHA256((const unsigned char *)domain.data(), domain.size(), layout.digest);
		report("tag-definition", NULL_TREE, UNKNOWN_LOCATION, &layout, 0, tag);
	}
}

static void finish_unit(void *, void *)
{
	if (errorcount) return;
	for (auto &entry : sites) if (!entry.second.consumed) {
		error(G_("HDN RAP lost an indirect call during machine lowering")); return;
	}
	/* Collapse type-specific RTL names only now. ELF still calls the single
	 * verified adapter; each surviving instruction has its own typed return
	 * record. Eliminated calls create no runtime permission. */
	for (const auto &thunk : typed_thunks)
		fprintf(asm_out_file, "\t.set %s,__hdn_rap_call\n", thunk.first.c_str());
	for (const auto &function : coverage) {
		fputs("\t.pushsection .discard.hdn_rap.functions,\"\",@progbits\n\t.balign 8\n\t.quad ", asm_out_file);
		assemble_name(asm_out_file, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(function.decl)));
		fprintf(asm_out_file, ",%u,%u\n\t.popsection\n", bootstrap_unit ? 7 : function.runtime ? 2 : 1, function.returns);
	}
	for (const auto &function : function_entries) {
		fputs("\t.pushsection .hdn.rap.entries,\"a\",@progbits\n\t.balign 8\n\t.quad ", asm_out_file);
		assemble_name(asm_out_file, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(function.decl)));
		fprintf(asm_out_file, ",%s,%s,%s\n\t.popsection\n", function.type->label.c_str(),
			function.body.c_str(), function.trace_return.c_str());
	}
	fputs("\t.pushsection .hdn.rap.entries,\"a\",@progbits\n\t.balign 8\n\t.quad 0,0,0,0\n\t.popsection\n", asm_out_file);
	cgraph_node *node;
	varpool_node *variable;
	FOR_EACH_VARIABLE(variable) {
		tree decl = variable->decl;
		const char *section = DECL_SECTION_NAME(decl);
		const char *prefix = "__hdn_rap_prototype_";
		const char *name = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl));

		if (!section || strcmp(section, ".discard.hdn_rap.type_providers"))
			continue;
		if (strncmp(name, prefix, strlen(prefix)) || !name[strlen(prefix)] ||
		    !TREE_READONLY(decl) || !TREE_STATIC(decl) ||
		    TREE_CODE(TREE_TYPE(decl)) != POINTER_TYPE ||
		    TREE_CODE(TREE_TYPE(TREE_TYPE(decl))) != FUNCTION_TYPE ||
		    !DECL_INITIAL(decl) || !integer_zerop(DECL_INITIAL(decl))) {
			error_at(DECL_SOURCE_LOCATION(decl), G_("HDN RAP type provider must be a constant null function pointer"));
			continue;
		}
		identity *type = get_identity(TREE_TYPE(TREE_TYPE(decl)), DECL_SOURCE_LOCATION(decl));
		if (!type) continue;
		std::string anchor = "__hdn_rap_type_provider_" + std::string(name + strlen(prefix));
		fputs("\t.weak ", asm_out_file);
		assemble_name(asm_out_file, anchor.c_str());
		fputs("\n\t.set ", asm_out_file);
		assemble_name(asm_out_file, anchor.c_str());
		fprintf(asm_out_file, ",%s\n", type->label.c_str());
		report("type-provider", decl, DECL_SOURCE_LOCATION(decl), type, 0, anchor);
	}
	/* Like compiler-produced KCFI identifiers, these anchors bind an assembly
	 * declaration to its real C prototype. An anchor grants no indirect-call
	 * permission: assembly must explicitly publish its target and protected
	 * entry, and objtool must verify that body. The report gate compares every
	 * public definition/reference before weak aliases can be coalesced. */
	FOR_EACH_FUNCTION(node) {
		if (bootstrap_unit) continue;
		if (!TREE_PUBLIC(node->decl) ||
		    (!TREE_ASM_WRITTEN(node->decl) && !node->address_taken &&
		     (!TREE_USED(node->decl) || fndecl_built_in_p(node->decl))))
			continue;
		identity *type = get_identity(TREE_TYPE(node->decl), DECL_SOURCE_LOCATION(node->decl));
		if (!type) continue;
		const char *symbol = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(node->decl));
		std::string anchor = "__hdn_rap_type_" + std::string(symbol + (symbol[0] == '*'));
		fputs("\t.weak ", asm_out_file);
		assemble_name(asm_out_file, anchor.c_str());
		fputs("\n\t.set ", asm_out_file);
		assemble_name(asm_out_file, anchor.c_str());
		fprintf(asm_out_file, ",%s\n", type->label.c_str());
		/* Only scalar values returned entirely in RAX may use the native
		 * static-call zero shortcut. Derive this from the actual prototype. */
		const char *plain = symbol + (symbol[0] == '*');
		if (!strncmp(plain, "__SCT__", 7)) {
			tree result = TYPE_MAIN_VARIANT(TREE_TYPE(TREE_TYPE(node->decl)));
			bool scalar = TREE_CODE(result) == INTEGER_TYPE || TREE_CODE(result) == ENUMERAL_TYPE ||
				TREE_CODE(result) == BOOLEAN_TYPE || TREE_CODE(result) == POINTER_TYPE;
			bool zero = scalar && TYPE_SIZE(result) && tree_fits_uhwi_p(TYPE_SIZE(result)) &&
				tree_to_uhwi(TYPE_SIZE(result)) <= 64;
			fprintf(asm_out_file, "\t.weak __hdn_rap_static_zero_%s\n"
				"\t.set __hdn_rap_static_zero_%s,%u\n", plain, plain, zero);
		}
		report("public-type-anchor", node->decl, DECL_SOURCE_LOCATION(node->decl), type);
	}
	FOR_EACH_DEFINED_FUNCTION(node) {
		if (!TREE_ASM_WRITTEN(node->decl)) continue;
		/* The roots of validation are direct-ABI services, never ordinary
		 * function-pointer destinations, even if they have public linkage. */
		if (runtime_unit || bootstrap_unit) continue;
		/* Direct-only local functions are not legal indirect destinations.
		 * GCC may omit ENDBR for them; do not broaden that target surface. */
		if (!TREE_PUBLIC(node->decl) && !node->address_taken) continue;
		identity *type = get_identity(TREE_TYPE(node->decl), DECL_SOURCE_LOCATION(node->decl));
		if (!type) continue;
		fprintf(asm_out_file, "\t.pushsection .hdn.rap.targets,\"a\",@progbits\n\t.balign 8\n\t.quad ");
		assemble_name(asm_out_file, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(node->decl)));
		fprintf(asm_out_file, "\n\t.quad %s\n\t.popsection\n", type->label.c_str());
		report("function-target", node->decl, DECL_SOURCE_LOCATION(node->decl), type);
	}
	for (const auto &target : jump_targets) {
		fputs("\t.pushsection .hdn.rap.targets,\"a\",@progbits\n\t.balign 8\n\t.quad ", asm_out_file);
		assemble_name(asm_out_file, target.label.c_str());
		fprintf(asm_out_file, "\n\t.quad %s\n\t.popsection\n", target.type->label.c_str());
	}
	for (const auto &site : return_sites)
		fprintf(asm_out_file, "\t.pushsection .hdn.rap.sites,\"a\",@progbits\n\t.balign 8\n"
			"\t.quad %s,%s\n\t.popsection\n", site.label.c_str(),
			site.type ? site.type->label.c_str() : "0");
	for (const auto &edge : jump_edges) {
		fprintf(asm_out_file, "\t.pushsection .discard.hdn_rap_jumps,\"\",@progbits\n"
			"\t.balign 8\n\t.quad %s,", edge.site.c_str());
		assemble_name(asm_out_file, edge.target.c_str());
		fputs("\n\t.popsection\n", asm_out_file);
	}
	for (const auto &site : static_sites)
		fprintf(asm_out_file, "\t.pushsection .hdn.rap.static_sites,\"a\",@progbits\n"
			"\t.balign 8\n\t.quad %s,%s\n\t.popsection\n", site.site.c_str(), site.target.c_str());
	fputs("\t.pushsection .hdn.rap.static_sites,\"a\",@progbits\n\t.balign 8\n\t.quad 0,0\n\t.popsection\n"
	      "\t.pushsection .hdn.rap.static_calls,\"a\",@progbits\n\t.balign 8\n\t.quad 0,0,0,0\n\t.popsection\n", asm_out_file);
	fputs("\t.pushsection .hdn.rap.sites,\"a\",@progbits\n\t.balign 8\n\t.quad 0,0\n\t.popsection\n", asm_out_file);
	for (auto &entry : identities) {
		identity &type = entry.second;
		fprintf(asm_out_file, "\t.pushsection .hdn.rap.types,\"a\",@progbits\n\t.balign 8\n%s:\n"
			"\t.long 1,%zu\n", type.label.c_str(), type.canonical.size());
		bytes(type.digest, sizeof(type.digest));
		bytes((const unsigned char *)type.canonical.c_str(), type.canonical.size() + 1);
		fputs("\t.popsection\n", asm_out_file);
	}
	fprintf(asm_out_file, "\t.pushsection .hdn.rap.build,\"a\",@progbits\n\t.balign 8\n\t.long 1,4\n");
	bytes((const unsigned char *)build_id, 65);
	bytes((const unsigned char *)version_string, strlen(version_string) + 1);
	fprintf(asm_out_file, "\t.zero %zu\n\t.balign 8\n\t.popsection\n", 127 - strlen(version_string));
	report_tags();
	if (!errorcount)
		report("completed-unit", NULL_TREE, UNKNOWN_LOCATION, NULL);
}

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	const char *report_path = NULL;
	if (!plugin_default_version_check(version, &gcc_version) || !TARGET_64BIT) {
		error(G_("HDN RAP requires a matching GCC x86-64 compiler and plugin"));
		return 1;
	}
	for (int i = 0; i < info->argc; i++) {
		const char *key = info->argv[i].key, *value = info->argv[i].value;
		if (!value || !*value) return 1;
		if (!strcmp(key, "build-id")) build_id = value;
		else if (!strcmp(key, "source-root")) source_root = value;
		else if (!strcmp(key, "profile")) profile = value;
		else if (!strcmp(key, "report")) report_path = value;
		else if (!strcmp(key, "runtime") && !strcmp(value, "1")) runtime_unit = true;
		else if (!strcmp(key, "bootstrap") && !strcmp(value, "1")) bootstrap_unit = true;
		else return 1;
	}
	if (!build_id || strlen(build_id) != 64 || strspn(build_id, "0123456789abcdef") != 64 ||
	    !source_root || !profile || !report_path || strlen(version_string) > 127) {
		error(G_("HDN RAP requires a 64-digit lowercase build identity and complete source/report configuration"));
		return 1;
	}
	if (bootstrap_unit) {
		std::string unit = relative(main_input_filename);
		if (runtime_unit || (unit != "arch/x86/boot/startup/gdt_idt.c" &&
		    unit != "arch/x86/boot/startup/map_kernel.c" &&
		    unit != "arch/x86/boot/startup/sme.c" &&
		    unit != "arch/x86/boot/startup/sev-startup.c")) {
			error(G_("HDN RAP bootstrap mode is restricted to the physical startup sources"));
			return 1;
		}
	}
	if (runtime_unit) {
		std::string unit = relative(main_input_filename);
		if (unit != "arch/x86/kernel/hdn_rap_validate.c" && unit != "arch/x86/kernel/hdn_rap_context.c" &&
		    unit != "arch/x86/kernel/hdn_rap_resume.c" &&
		    unit != "arch/x86/kernel/hdn_rap_kexec.c" &&
		    unit != "arch/x86/kernel/hdn_rap_hv_crash.c" &&
		    unit != "arch/x86/kernel/hdn_rap_efi.c" &&
		    unit != "arch/x86/kernel/hdn_stack_access.c" &&
		    unit != "arch/x86/mm/hdn_stack_mm.c" &&
		    unit != "arch/x86/mm/hdn_pgtable_window.c") {
			error(G_("HDN RAP runtime mode is restricted to the closed architecture runtime"));
			return 1;
		}
	}
	report_fd = open(report_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) return 1;
	flag_optimize_sibling_calls = 0;
	/* Kernel and module symbols bind through static relocations. A GOT load
	 * would introduce an untyped writable edge for an otherwise direct call. */
	flag_plt = 1;
	PASS_INFO(hdn_rap_sites, "optimized", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hdn_rap_transfers, "pro_and_epilogue", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hdn_rap_returns, "shorten", 1, PASS_POS_INSERT_BEFORE);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_rap_sites_pass_info);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_rap_transfers_pass_info);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_rap_returns_pass_info);
	register_callback(info->base_name, PLUGIN_FINISH_UNIT, finish_unit, NULL);
	return 0;
}
