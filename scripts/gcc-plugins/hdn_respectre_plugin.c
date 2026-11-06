// SPDX-License-Identifier: GPL-2.0-only
/* Conservative transient dataflow closure. No unknown input is trusted. */
#include "gcc-common.h"
#undef gimple
#include <map>
#include <set>
#include <string>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;
static const char *source_root, *profile;
static int report_fd = -1;
static unsigned long records;
static bool defer_reviews;
static std::set<tree> constant_functions;
static std::set<std::string> reviewed_assembly;

static const char *review_for(tree fn);

static const char *name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "<anonymous>";
}

static const char *relative(const char *path)
{
	if (!path)
		return "<unknown>";
	size_t n = strlen(source_root);
	if (!strncmp(path, source_root, n) && path[n] == '/')
		return path + n + 1;
	while (path[0] == '.' && path[1] == '/')
		path += 2;
	return path;
}

static void quoted(FILE *out, const char *s)
{
	fputc('"', out);
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(out, "\\%c", *p);
		else if (*p < 32)
			fprintf(out, "\\u%04x", *p);
		else
			fputc(*p, out);
	}
	fputc('"', out);
}

static void emit(const char *kind, location_t loc, const char *detail = "")
{
	char *buffer = NULL;
	size_t length = 0, done = 0;
	expanded_location place = expand_location(loc);
	FILE *out = open_memstream(&buffer, &length);
	if (!out) {
		error(G_("cannot allocate HDN speculation report"));
		return;
	}
	fputs("{\"schema_version\":1,\"analyzer_version\":1,\"kind\":", out); quoted(out, kind);
	fputs(",\"unit\":", out); quoted(out, relative(main_input_filename));
	fputs(",\"profile\":", out); quoted(out, profile);
	fputs(",\"file\":", out); quoted(out, relative(place.file));
	fprintf(out, ",\"line\":%d,\"column\":%d,\"function\":", place.line, place.column);
	quoted(out, current_function_decl ? name(current_function_decl) : "<unit>");
	fputs(",\"symbol\":", out);
	quoted(out, current_function_decl ? IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(current_function_decl)) : "<unit>");
	fputs(",\"detail\":", out); quoted(out, detail);
	fprintf(out, ",\"records\":%lu,\"errors\":%d}\n", records, errorcount);
	if (fclose(out)) {
		free(buffer);
		error(G_("cannot finish HDN speculation record"));
		return;
	}
	while (flock(report_fd, LOCK_EX))
		if (errno != EINTR) {
			free(buffer);
			error(G_("cannot lock HDN speculation report"));
			return;
		}
	while (done < length) {
		ssize_t n = write(report_fd, buffer + done, length - done);
		if (n > 0)
			done += n;
		else if (n < 0 && errno == EINTR)
			continue;
		else {
			error(G_("cannot write HDN speculation report"));
			break;
		}
	}
	if (flock(report_fd, LOCK_UN))
		error(G_("cannot unlock HDN speculation report"));
	free(buffer);
	records++;
}

/* Interprocedural facts are intentionally asymmetric: only literal returns
 * without memory effects or calls are trusted. External, indirect, recursive,
 * interposable, aliasing and unanalyzed callees all return attacker data.
 * Parameters remain untrusted even for direct-only functions: clones, exported
 * callbacks and separate translation units cannot erase their source class.
 */
static unsigned int hdn_spec_summary_execute(void)
{
	cgraph_node *node;
	FOR_EACH_DEFINED_FUNCTION(node) {
		if (!node->has_gimple_body_p())
			continue;
		function *fn = DECL_STRUCT_FUNCTION(node->decl);
		if (!fn)
			continue;
		bool constant = true, returns = false;
		basic_block bb;
		push_cfun(fn);
		FOR_EACH_BB_FN(bb, cfun) {
			for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
				gimple *stmt = gsi_stmt(it);
				if (is_gimple_debug(stmt))
					continue;
				if (gimple_code(stmt) == GIMPLE_RETURN) {
					tree value = gimple_return_retval(as_a<greturn *>(stmt));
					returns = true;
					if (!value || TREE_CODE(value) != INTEGER_CST)
						constant = false;
				} else if (gimple_code(stmt) != GIMPLE_LABEL &&
					   gimple_code(stmt) != GIMPLE_NOP)
					constant = false;
			}
		}
		if (constant && returns && !node->semantic_interposition) {
			constant_functions.insert(node->decl);
			emit("constant-return", DECL_SOURCE_LOCATION(node->decl));
		}
		for (cgraph_edge *edge = node->callees; edge; edge = edge->next_callee)
			emit("call-edge", edge->call_stmt ? gimple_location(edge->call_stmt) :
				DECL_SOURCE_LOCATION(node->decl), name(edge->callee->decl));
		pop_cfun();
	}
	return 0;
}

#define PASS_NAME hdn_spec_summary
#define NO_GATE
#include "gcc-generate-simple_ipa-pass.h"

static std::string assembly_key(gasm *stmt)
{
	expanded_location loc = expand_location(gimple_location(stmt));
	return std::string(relative(loc.file)) + ':' + std::to_string(loc.line) + ':' +
		std::to_string(loc.column) + ':' + gimple_asm_string(stmt);
}

/* Record the actual source body's review before inlining copies its asm into
 * callers. Caller annotations cannot implicitly authorize an unreviewed callee.
 * The coverage ledger additionally binds these exact source spans and text. */
static unsigned int hdn_spec_boundaries_execute(void)
{
	const char *review = review_for(current_function_decl);
	if (!review)
		return 0;
	tree attribute = lookup_attribute("hdn_spec_review", DECL_ATTRIBUTES(current_function_decl));
	std::string detail;
	for (tree arg = TREE_VALUE(attribute); arg; arg = TREE_CHAIN(arg)) {
		if (!detail.empty()) detail += '\n';
		detail += TREE_STRING_POINTER(TREE_VALUE(arg));
	}
	emit("review", DECL_SOURCE_LOCATION(current_function_decl), detail.c_str());
	basic_block bb;
	FOR_EACH_BB_FN(bb, cfun)
		for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it))
			if (gimple_code(gsi_stmt(it)) == GIMPLE_ASM) {
				gasm *stmt = as_a<gasm *>(gsi_stmt(it));
				reviewed_assembly.insert(assembly_key(stmt));
				emit("reviewed-assembly", gimple_location(stmt), gimple_asm_string(stmt));
			}
	return 0;
}

#define PASS_NAME hdn_spec_boundaries
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_ssa
#include "gcc-generate-gimple-pass.h"

static bool memory_ref(tree value)
{
	if (!value)
		return false;
	switch (TREE_CODE(value)) {
	case MEM_REF: case TARGET_MEM_REF: case INDIRECT_REF:
	case ARRAY_REF: case ARRAY_RANGE_REF: case COMPONENT_REF: case BIT_FIELD_REF:
		return true;
	case VAR_DECL:
		return TREE_STATIC(value) || DECL_EXTERNAL(value) || TREE_ADDRESSABLE(value);
	default:
		return false;
	}
}

static bool trusted_constant(tree value)
{
	if (!value)
		return true;
	if (CONSTANT_CLASS_P(value))
		return true;
	/* Do not trust a const-qualified pointer, mutable alias, volatile/MMIO
	 * source, escaped local, or a readonly declaration with no initializer. */
	if (TREE_CODE(value) == VAR_DECL)
		return TREE_STATIC(value) && TREE_READONLY(value) && !TREE_THIS_VOLATILE(value) &&
			DECL_INITIAL(value) && TREE_CODE(DECL_INITIAL(value)) == INTEGER_CST;
	return false;
}

static bool tainted(tree value, const std::set<tree> &values, unsigned int depth = 0)
{
	if (!value || trusted_constant(value))
		return false;
	if (depth > 48)
		return true;
	if (TREE_CODE(value) == SSA_NAME)
		return SSA_NAME_IS_DEFAULT_DEF(value) || values.count(value);
	if (memory_ref(value) || TREE_CODE(value) == PARM_DECL)
		return true;
	if (TREE_CODE(value) == ADDR_EXPR) {
		tree object = TREE_OPERAND(value, 0);
		if (DECL_P(object) || TREE_CODE(object) == STRING_CST)
			return false;
	}
	if (!EXPR_P(value))
		return true;
	for (int n = 0; n < TREE_OPERAND_LENGTH(value); n++)
		if (tainted(TREE_OPERAND(value, n), values, depth + 1))
			return true;
	return false;
}

static std::set<tree> dataflow(void)
{
	std::set<tree> values;
	bool changed;
	/* Monotone finite SSA lattice. A loop PHI converges without recursion or
	 * a depth limit that could accidentally turn a cycle into trusted data. */
	do {
		changed = false;
		basic_block bb;
		FOR_EACH_BB_FN(bb, cfun) {
			for (gphi_iterator it = gsi_start_phis(bb); !gsi_end_p(it); gsi_next(&it)) {
				gphi *phi = it.phi();
				for (unsigned int n = 0; n < gimple_phi_num_args(phi); n++)
					if (tainted(gimple_phi_arg_def(phi, n), values))
						changed |= values.insert(gimple_phi_result(phi)).second;
			}
			for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
				gimple *stmt = gsi_stmt(it);
				tree lhs = gimple_get_lhs(stmt);
				if (gimple_code(stmt) == GIMPLE_ASM) {
					gasm *as = as_a<gasm *>(stmt);
					for (unsigned int n = 0; n < gimple_asm_noutputs(as); n++)
						changed |= values.insert(TREE_VALUE(gimple_asm_output_op(as, n))).second;
				}
				if (!lhs || TREE_CODE(lhs) != SSA_NAME)
					continue;
				bool input = false;
				if (is_gimple_call(stmt))
					input = !constant_functions.count(gimple_call_fndecl(stmt));
				else if (is_gimple_assign(stmt))
					for (unsigned int n = 1; n < gimple_num_ops(stmt); n++)
						input |= tainted(gimple_op(stmt, n), values);
				else
					input = true;
				if (input)
					changed |= values.insert(lhs).second;
			}
		}
	} while (changed);
	return values;
}

static tree operand(const char *constraint, tree value)
{
	tree name = build_tree_list(NULL_TREE, build_const_char_string(strlen(constraint) + 1, constraint));
	return build_tree_list(name, value);
}

/* Same conservative CPUID serialization primitive supported by x86 sync_core.
 * CPUID exists on all x86-64 CPUs; unlike an unconditional LFENCE this needs no
 * mutable SSBD policy or AMD LFENCE-dispatch-serialization assumption. No call,
 * allocation, tracing, preemption or NMI-unmasking IRET is introduced. Memory
 * and register clobbers remain explicit to the late optimizer and scheduler.
 */
static void serialize(gimple_stmt_iterator *it, bool after, const char *kind)
{
	vec<tree, va_gc> *clobbers = NULL;
	for (const char *reg : {"ax", "bx", "cx", "dx", "cc", "memory"})
		vec_safe_push(clobbers, build_tree_list(NULL_TREE,
			build_const_char_string(strlen(reg) + 1, reg)));
	gasm *barrier = gimple_build_asm_vec("xorl %%eax, %%eax; cpuid # hdn-spec-v1", NULL, NULL, clobbers, NULL);
	gimple_asm_set_volatile(barrier, true);
	location_t loc = gsi_end_p(*it) ? DECL_SOURCE_LOCATION(current_function_decl) :
		gimple_location(gsi_stmt(*it));
	gimple_set_location(barrier, loc);
	emit(kind, loc);
	if (after)
		gsi_insert_after(it, barrier, GSI_CONTINUE_LINKING);
	else
		gsi_insert_before(it, barrier, GSI_SAME_STMT);
	update_stmt(barrier);
}

/* A mask is sufficient only for a statically allocated nonempty array and an
 * unsigned strict constant bound no larger than that array. The true edge must
 * dominate the load. Other pointer/length/PHI and alias cases get serialization.
 * This is the unsigned cmp/sbb dependency used by x86 array_index_mask_nospec;
 * the AND is inside the opaque asm so no subsequent optimizer can elide it.
 */
static bool mask_array(gimple_stmt_iterator *it)
{
	gimple *stmt = gsi_stmt(*it);
	if (!is_gimple_assign(stmt) || !gimple_assign_single_p(stmt))
		return false;
	tree ref = gimple_assign_rhs1(stmt);
	if (TREE_CODE(ref) != ARRAY_REF)
		return false;
	tree base = TREE_OPERAND(ref, 0), index = TREE_OPERAND(ref, 1);
	if (TREE_CODE(base) != VAR_DECL || !TREE_STATIC(base) ||
	    TREE_CODE(TREE_TYPE(base)) != ARRAY_TYPE || TREE_CODE(index) != SSA_NAME ||
	    !INTEGRAL_TYPE_P(TREE_TYPE(index)) || !TYPE_UNSIGNED(TREE_TYPE(index)) ||
	    TYPE_PRECISION(TREE_TYPE(index)) != 64)
		return false;
	tree domain = TYPE_DOMAIN(TREE_TYPE(base));
	if (!domain || !TYPE_MIN_VALUE(domain) || !integer_zerop(TYPE_MIN_VALUE(domain)) ||
	    !TYPE_MAX_VALUE(domain) || !tree_fits_uhwi_p(TYPE_MAX_VALUE(domain)))
		return false;
	unsigned HOST_WIDE_INT maximum = tree_to_uhwi(TYPE_MAX_VALUE(domain));
	basic_block bb;
	FOR_EACH_BB_FN(bb, cfun) {
		gimple *last = last_stmt(bb);
		if (!last || gimple_code(last) != GIMPLE_COND)
			continue;
		gcond *condition = as_a<gcond *>(last);
		tree bound = gimple_cond_rhs(condition);
		enum tree_code code = gimple_cond_code(condition);
		if ((code != LT_EXPR && code != LE_EXPR) || gimple_cond_lhs(condition) != index ||
		    !tree_fits_uhwi_p(bound))
			continue;
		unsigned HOST_WIDE_INT count = tree_to_uhwi(bound);
		if (code == LE_EXPR) {
			if (count == HOST_WIDE_INT_M1U) continue;
			count++;
		}
		if (!count || count - 1 > maximum)
			continue;
		bound = build_int_cstu(TREE_TYPE(index), count);
		edge edge;
		edge_iterator ei;
		FOR_EACH_EDGE(edge, ei, bb->succs) {
			if (!(edge->flags & EDGE_TRUE_VALUE) || !single_pred_p(edge->dest) ||
			    !dominated_by_p(CDI_DOMINATORS, gimple_bb(stmt), edge->dest))
				continue;
			tree safe = make_ssa_name(TREE_TYPE(index));
			vec<tree, va_gc> *inputs = NULL, *outputs = NULL, *clobbers = NULL;
			vec_safe_push(outputs, operand("=&r", safe));
			vec_safe_push(inputs, operand("r", index));
			vec_safe_push(inputs, operand("r", bound));
			vec_safe_push(clobbers, build_tree_list(NULL_TREE, build_const_char_string(3, "cc")));
			gasm *mask = gimple_build_asm_vec("cmpq %2,%1; sbbq %0,%0; andq %1,%0 # hdn-spec-mask-v1",
				inputs, outputs, clobbers, NULL);
			gimple_asm_set_volatile(mask, true);
			gimple_set_location(mask, gimple_location(stmt));
			SSA_NAME_DEF_STMT(safe) = mask;
			gsi_insert_before(it, mask, GSI_SAME_STMT);
			ref = copy_node(ref);
			TREE_OPERAND(ref, 1) = safe;
			gimple_assign_set_rhs1(stmt, ref);
			update_stmt(stmt);
			emit("index-mask", gimple_location(stmt));
			return true;
		}
	}
	return false;
}

static const char *review_for(tree fn)
{
	tree attribute = lookup_attribute("hdn_spec_review", DECL_ATTRIBUTES(fn));
	return attribute ? TREE_STRING_POINTER(TREE_VALUE(TREE_VALUE(attribute))) : NULL;
}

static unsigned int hdn_respectre_execute(void)
{
	std::set<tree> values = dataflow();
	bool has_store = false, masked = false;
	basic_block bb;
	calculate_dominance_info(CDI_DOMINATORS);
	emit("function", DECL_SOURCE_LOCATION(current_function_decl));
	for (tree arg = DECL_ARGUMENTS(current_function_decl); arg; arg = DECL_CHAIN(arg))
		emit("parameter-source", DECL_SOURCE_LOCATION(arg), name(arg));
	FOR_EACH_BB_FN(bb, cfun)
		for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
			gimple *stmt = gsi_stmt(it);
			/* Unknown calls and asm can hide stores; do not use a v1-only
			 * mask as the only defense in such a function. */
			has_store |= gimple_code(stmt) == GIMPLE_ASM || is_gimple_call(stmt) ||
				(is_gimple_assign(stmt) && memory_ref(gimple_assign_lhs(stmt)));
		}
	FOR_EACH_BB_FN(bb, cfun) {
		for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
			gimple *stmt = gsi_stmt(it);
			if (is_gimple_debug(stmt))
				continue;
			if (gimple_code(stmt) == GIMPLE_ASM) {
				gasm *as = as_a<gasm *>(stmt);
				/* Empty compiler barriers have no hidden CPU/dataflow effects. */
				if (!*gimple_asm_string(as) && !gimple_asm_noutputs(as) && !gimple_asm_nlabels(as))
					continue;
				emit("assembly-boundary", gimple_location(stmt), gimple_asm_string(as));
				if (!reviewed_assembly.count(assembly_key(as))) {
					emit("unreviewed-assembly", gimple_location(stmt),
					     gimple_asm_string(as));
					/* Standalone and fixture compilation is strict.  A complete
					 * kernel build may defer exact source-span review to the
					 * source/object/machine-code gate, but that build is not an
					 * accepted hardened artifact until the gate closes every
					 * emitted obligation. */
					if (!defer_reviews)
						error_at(gimple_location(stmt),
							 G_("HDN speculation assembly boundary needs a source-bound review"));
				}
				/* A reviewed asm body retains its exact original instruction
				 * sequence; the annotation never suppresses surrounding C. */
				continue;
			}
			if (gimple_code(stmt) == GIMPLE_COND) {
				gcond *cond = as_a<gcond *>(stmt);
				if (tainted(gimple_cond_lhs(cond), values) || tainted(gimple_cond_rhs(cond), values))
					emit("tainted-condition", gimple_location(stmt));
			}
			if (is_gimple_assign(stmt)) {
				bool load = false;
				for (unsigned int n = 1; n < gimple_num_ops(stmt); n++)
					load |= memory_ref(gimple_op(stmt, n)) && !trusted_constant(gimple_op(stmt, n));
				if (load) {
					emit("memory-source", gimple_location(stmt));
					if (!has_store && mask_array(&it))
						masked = true;
					else
						serialize(&it, false, "load-serialize");
				}
				if (memory_ref(gimple_assign_lhs(stmt))) {
					/* Resolve speculative control and address dependencies
					 * before the store; drain it before later selected loads.
					 * Software coverage is independent of mutable SSBD state. */
					serialize(&it, false, "store-address-serialize");
					serialize(&it, true, "store-drain");
				}
			} else if (is_gimple_call(stmt)) {
				gimple_call_set_tail(as_a<gcall *>(stmt), false);
				bool input = !gimple_call_fndecl(stmt);
				for (unsigned int n = 0; n < gimple_call_num_args(stmt); n++)
					input |= tainted(gimple_call_arg(stmt, n), values);
				if (input)
					emit("tainted-call", gimple_location(stmt), name(gimple_call_fndecl(stmt)));
				/* Even a call with constant arguments can be control-dependent
				 * on untrusted input. Only proven literal-return bodies omit
				 * this boundary; the caller's argument lattice is not enough. */
				if (!constant_functions.count(gimple_call_fndecl(stmt)))
					serialize(&it, false, "call-serialize");
				/* Builtins may become stores during expansion, and external
				 * assembly functions are outside SSA. Drain return boundaries. */
				if (!(gimple_call_flags(stmt) & ECF_NORETURN) &&
				    !gimple_call_internal_p(stmt))
					serialize(&it, true, "call-return-serialize");
			} else if (gimple_code(stmt) == GIMPLE_RETURN &&
				   memory_ref(gimple_return_retval(as_a<greturn *>(stmt)))) {
				serialize(&it, false, "return-memory-serialize");
			}
		}
	}
	if (masked) {
		/* A v1 mask alone does not drain a store made by an assembly caller.
		 * Isolate this once-per-entry v4 boundary from loop backedges. */
		basic_block entry = split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
		gimple_stmt_iterator it = gsi_after_labels(entry);
		serialize(&it, false, "mask-entry-drain");
	}
	return TODO_update_ssa;
}

#define PASS_NAME hdn_respectre
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_ssa
#include "gcc-generate-gimple-pass.h"

static tree handle_review(tree *node, tree attr, tree args, int, bool *reject)
{
	unsigned int count = 0;
	bool valid = TREE_CODE(*node) == FUNCTION_DECL;
	for (tree a = args; a; a = TREE_CHAIN(a), count++)
		if (TREE_CODE(TREE_VALUE(a)) != STRING_CST || TREE_STRING_LENGTH(TREE_VALUE(a)) < 2 ||
		    TREE_STRING_LENGTH(TREE_VALUE(a)) > 1024 ||
		    (size_t)TREE_STRING_LENGTH(TREE_VALUE(a)) != strlen(TREE_STRING_POINTER(TREE_VALUE(a))) + 1)
			valid = false;
	if (valid && count == 4) {
		const char *category = TREE_STRING_POINTER(TREE_VALUE(args));
		valid = !strcmp(category, "assembly") || !strcmp(category, "constant-time") ||
			!strcmp(category, "sanitizer") || !strcmp(category, "proven-dependency");
	}
	if (!valid || count != 4) {
		*reject = true;
		error(G_("%qE requires category, owner, justification and invalidation strings"), attr);
	}
	return NULL_TREE;
}

static void attributes(void *, void *)
{
	static struct attribute_spec attr = {};
	attr.name = "hdn_spec_review";
	attr.min_length = attr.max_length = 4;
	attr.decl_required = true;
	attr.handler = handle_review;
	register_attribute(&attr);
}

static void finish(void *, void *)
{
	emit("unit", UNKNOWN_LOCATION);
	close(report_fd);
}

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	const char *report = NULL;
	if (!plugin_default_version_check(version, &gcc_version))
		return 1;
	for (int n = 0; n < info->argc; n++) {
		const char *key = info->argv[n].key, *value = info->argv[n].value;
		if (!value || !*value) return 1;
		if (!strcmp(key, "source-root")) source_root = value;
		else if (!strcmp(key, "profile")) profile = value;
		else if (!strcmp(key, "report")) report = value;
		else if (!strcmp(key, "defer-reviews")) {
			if (strcmp(value, "1"))
				return 1;
			defer_reviews = true;
		}
		else return 1;
	}
	if (!report || !source_root || !profile || sizeof(void *) != 8)
		return 1;
	report_fd = open(report, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (report_fd < 0) return 1;
	PASS_INFO(hdn_spec_boundaries, "ssa", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hdn_spec_summary, "opt_local_passes", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(hdn_respectre, "optimized", 1, PASS_POS_INSERT_BEFORE);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_spec_summary_pass_info);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_spec_boundaries_pass_info);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_respectre_pass_info);
	register_callback(info->base_name, PLUGIN_ATTRIBUTES, attributes, NULL);
	register_callback(info->base_name, PLUGIN_FINISH, finish, NULL);
	return 0;
}
