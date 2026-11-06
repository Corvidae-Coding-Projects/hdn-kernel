// SPDX-License-Identifier: GPL-2.0-only
/*
 * HDN optimized null-dereference reporting pass.
 *
 * This pass never transforms generated code. It runs after the optimizing
 * GIMPLE passes, combines GCC's statement-sensitive ranges with explicit
 * dominance checks, and emits one bounded JSON record per finding. Policy
 * decisions, suppressions, and cross-tool correlation live outside GCC.
 */

#include "gcc-common.h"

/*
 * gcc-common.h aliases gimple to a pointer for older in-tree plugins.  GCC's
 * installed ranger headers are C++ interfaces and must see the native gimple
 * class name instead.
 */
#undef gimple
#include "gimple-range.h"
#include "tree-ssa-address.h"
#include "value-range.h"
#include "value-query.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;

#define HDN_NULL_SCHEMA_VERSION 1
#define HDN_NULL_ANALYZER_VERSION "1.0.3"
#define HDN_NULL_RECORD_MAX 8192
#define HDN_NULL_PATH_MAX 4096
#define HDN_NULL_ORIGIN_DEPTH 24
#define HDN_NULL_GUARD_EDGES_MAX 8

static char report_dir[HDN_NULL_PATH_MAX];
static char source_root[HDN_NULL_PATH_MAX];
static char analysis_profile[128] = "unknown";
static int report_fd = -1;
static range_query *active_range_query;

struct hdn_guard_set {
	edge nonnull_edges[HDN_NULL_GUARD_EDGES_MAX];
	unsigned int count;
	bool overflow;
};

static hash_map<tree, hdn_guard_set> *active_guard_cache;

struct hdn_origin {
	bool explicit_zero;
	bool parameter;
	bool nullable_call;
	bool container_conversion;
	bool user_influenced;
	bool root_locked;
	tree root;
	const char *callee;
};

struct hdn_seen {
	tree pointer;
	const char *kind;
	location_t location;
};

static tree reference_pointer(tree ref);
static bool reference_has_negative_offset(tree ref);
static bool already_seen(auto_vec<hdn_seen, 8> *seen, tree pointer,
			 const char *kind, location_t location);
static bool seen_before(const auto_vec<hdn_seen, 8> *seen, tree pointer,
			const char *kind, location_t location);

static struct plugin_info hdn_null_plugin_info = {
	.version = HDN_NULL_ANALYZER_VERSION,
	.help = "report-dir=<path>\twrite JSONL findings under path\n"
		"source-root=<path>\tnormalize source paths relative to path\n"
		"profile=<name>\trecord the verification profile\n",
};

static uint64_t fnv1a_update(uint64_t hash, const char *text)
{
	const unsigned char *p = (const unsigned char *)text;

	if (!text)
		return hash;
	while (*p) {
		hash ^= *p++;
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static bool copy_option(char *dst, size_t size, const char *value,
			const char *name)
{
	if (!value || !*value) {
		error(G_("missing value for HDN null-analysis option %qs"), name);
		return false;
	}
	if (strlen(value) >= size) {
		error(G_("value for HDN null-analysis option %qs is too long"), name);
		return false;
	}
	strcpy(dst, value);
	return true;
}

static int mkdir_parents(const char *path)
{
	char work[HDN_NULL_PATH_MAX];
	char *p;

	if (strlen(path) >= sizeof(work))
		return -ENAMETOOLONG;
	strcpy(work, path);
	for (p = work + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(work, 0700) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(work, 0700) && errno != EEXIST)
		return -errno;
	return 0;
}

static bool usable_source_location(location_t loc)
{
	const char *file;

	if (loc == UNKNOWN_LOCATION || !LOCATION_LINE(loc))
		return false;
	file = LOCATION_FILE(loc);
	return file && file[0];
}

static const char *normalized_file(location_t loc)
{
	const char *file;
	size_t root_len;

	if (!usable_source_location(loc))
		return "<unknown>";
	file = LOCATION_FILE(loc);
	root_len = strlen(source_root);
	if (root_len && !strncmp(file, source_root, root_len) &&
	    file[root_len] == '/')
		return file + root_len + 1;
	while (file[0] == '.' && file[1] == '/')
		file += 2;
	return file;
}

static size_t json_escape(char *dst, size_t cap, const char *src)
{
	size_t used = 0;

	if (!src)
		src = "";
	while (*src && used + 7 < cap) {
		unsigned char c = *src++;

		if (c == '"' || c == '\\') {
			dst[used++] = '\\';
			dst[used++] = c;
		} else if (c == '\n') {
			dst[used++] = '\\';
			dst[used++] = 'n';
		} else if (c == '\r') {
			dst[used++] = '\\';
			dst[used++] = 'r';
		} else if (c == '\t') {
			dst[used++] = '\\';
			dst[used++] = 't';
		} else if (c < 0x20) {
			used += snprintf(dst + used, cap - used, "\\u%04x", c);
		} else {
			dst[used++] = c;
		}
	}
	dst[used] = '\0';
	return used;
}

static const char *function_name(void)
{
	tree name = DECL_NAME(current_function_decl);

	return name ? IDENTIFIER_POINTER(name) : "<anonymous>";
}

static bool attacker_entry_function(void)
{
	tree attrs = DECL_ATTRIBUTES(current_function_decl);
	const char *name = function_name();
	static const char * const syscall_prefixes[] = {
		"__do_sys_", "__se_sys_",
		"__do_compat_sys_", "__se_compat_sys_",
	};
	unsigned int i;

	if (lookup_attribute("hdn_null_attacker_entry", attrs) != NULL_TREE)
		return true;
	for (i = 0; i < ARRAY_SIZE(syscall_prefixes); i++)
		if (!strncmp(name, syscall_prefixes[i],
			     strlen(syscall_prefixes[i])))
			return true;
	return false;
}

static bool intentional_probe_function(void)
{
	return lookup_attribute("hdn_null_probe",
				DECL_ATTRIBUTES(current_function_decl)) != NULL_TREE;
}

static void intentional_probe_metadata(const char **owner,
				       const char **invalidation)
{
	tree attr = lookup_attribute("hdn_null_probe",
				     DECL_ATTRIBUTES(current_function_decl));
	tree args;

	*owner = "";
	*invalidation = "";
	if (!attr)
		return;
	args = TREE_VALUE(attr);
	if (!args || !TREE_CHAIN(args))
		return;
	if (TREE_CODE(TREE_VALUE(args)) == STRING_CST)
		*owner = TREE_STRING_POINTER(TREE_VALUE(args));
	args = TREE_CHAIN(args);
	if (TREE_CODE(TREE_VALUE(args)) == STRING_CST)
		*invalidation = TREE_STRING_POINTER(TREE_VALUE(args));
}

static bool known_nullable_source(const char *name)
{
	static const char * const sources[] = {
		"alloc", "kmalloc", "kzalloc", "kcalloc", "krealloc",
		"vmalloc", "vzalloc", "memdup", "strdup", "lookup",
		"find",
	};
	unsigned int i;

	if (!name)
		return false;
	for (i = 0; i < ARRAY_SIZE(sources); i++)
		if (strstr(name, sources[i]))
			return true;
	return false;
}

static bool known_nonnull_return(const char *name)
{
	static const char * const functions[] = {
		"memdup_user", "vmemdup_user", "strndup_user",
		"memdup_user_nul",
	};
	unsigned int i;

	if (!name)
		return false;
	for (i = 0; i < ARRAY_SIZE(functions); i++)
		if (!strcmp(name, functions[i]))
			return true;
	return false;
}

static tree strip_pointer_conversions(tree value)
{
	while (value && (CONVERT_EXPR_P(value) ||
			 TREE_CODE(value) == NON_LVALUE_EXPR ||
			 TREE_CODE(value) == VIEW_CONVERT_EXPR))
		value = TREE_OPERAND(value, 0);
	return value;
}

static bool constant_is_negative(tree value)
{
	return value && TREE_CODE(value) == INTEGER_CST &&
	       wi::neg_p(wi::to_wide(value), SIGNED);
}

static void set_origin_root(struct hdn_origin *origin, tree value, bool lock)
{
	if (!origin->root)
		origin->root = value;
	if (lock)
		origin->root_locked = true;
}

static bool origin_already_visited(tree value, auto_vec<tree, 24> *visited)
{
	unsigned int i;
	tree seen;

	FOR_EACH_VEC_ELT(*visited, i, seen) {
		if (seen == value)
			return true;
	}
	visited->safe_push(value);
	return false;
}

static void trace_origin_1(tree value, struct hdn_origin *origin,
			   unsigned int depth, auto_vec<tree, 24> *visited)
{
	gimple *def;

	if (!value || depth > HDN_NULL_ORIGIN_DEPTH)
		return;
	value = strip_pointer_conversions(value);
	if (!value)
		return;

	if (TREE_CODE(value) == INTEGER_CST) {
		set_origin_root(origin, value, false);
		if (integer_zerop(value))
			origin->explicit_zero = true;
		return;
	}
	if (DECL_P(value)) {
		set_origin_root(origin, value, false);
		origin->parameter |= TREE_CODE(value) == PARM_DECL;
		return;
	}
	if (TREE_CODE(value) != SSA_NAME) {
		tree base = reference_pointer(value);

		if (base && base != value)
			trace_origin_1(base, origin, depth + 1, visited);
		return;
	}
	if (origin_already_visited(value, visited))
		return;

	if (SSA_NAME_VAR(value)) {
		origin->parameter |=
			TREE_CODE(SSA_NAME_VAR(value)) == PARM_DECL;
	}
	if (SSA_NAME_IS_DEFAULT_DEF(value)) {
		set_origin_root(origin, SSA_NAME_VAR(value) ?
				SSA_NAME_VAR(value) : value, false);
		return;
	}

	def = SSA_NAME_DEF_STMT(value);
	if (!def)
		return;
	if (gimple_code(def) == GIMPLE_PHI) {
		gphi *phi = as_a<gphi *>(def);
		unsigned int i;

		set_origin_root(origin, value, true);
		for (i = 0; i < gimple_phi_num_args(phi); i++)
			trace_origin_1(gimple_phi_arg_def(phi, i), origin,
				       depth + 1, visited);
		return;
	}
	if (is_gimple_assign(def)) {
		tree rhs1 = gimple_assign_rhs1(def);
		enum tree_code code = gimple_assign_rhs_code(def);

		if (code == POINTER_PLUS_EXPR || code == PLUS_EXPR ||
		    code == MINUS_EXPR) {
			tree rhs2 = gimple_assign_rhs2(def);

			if (constant_is_negative(rhs2) ||
			    (code == MINUS_EXPR && rhs2 &&
			     TREE_CODE(rhs2) == INTEGER_CST &&
			     !integer_zerop(rhs2)))
				origin->container_conversion = true;
		}
		trace_origin_1(rhs1, origin, depth + 1, visited);
		return;
	}
	if (is_gimple_call(def)) {
		tree fndecl = gimple_call_fndecl(def);
		const char *name = NULL;

		if (!origin->root_locked)
			set_origin_root(origin, value, false);
		if (fndecl && DECL_NAME(fndecl))
			name = IDENTIFIER_POINTER(DECL_NAME(fndecl));
		origin->callee = name;
		origin->nullable_call |= known_nullable_source(name);
	}
}

static void trace_origin(tree value, struct hdn_origin *origin)
{
	auto_vec<tree, 24> visited;

	trace_origin_1(value, origin, 0, &visited);
}

enum hdn_null_state {
	HDN_NULL_NONZERO,
	HDN_NULL_ZERO,
	HDN_NULL_MAYBE,
	HDN_NULL_VARYING,
	HDN_NULL_UNKNOWN,
};

static enum hdn_null_state pointer_state(tree pointer, gimple *stmt)
{
	value_range range(TREE_TYPE(pointer));

	if (!value_range::supports_type_p(TREE_TYPE(pointer)))
		return HDN_NULL_UNKNOWN;
	if (!active_range_query->range_of_expr(range, pointer, stmt))
		return HDN_NULL_UNKNOWN;
	if (range.undefined_p())
		return HDN_NULL_NONZERO;
	if (range.zero_p())
		return HDN_NULL_ZERO;
	if (range.nonzero_p())
		return HDN_NULL_NONZERO;
	if (range.varying_p())
		return HDN_NULL_VARYING;
	return range_includes_zero_p(range) ? HDN_NULL_MAYBE :
		HDN_NULL_NONZERO;
}

static bool condition_proves_nonnull(tree value, gimple *stmt)
{
	basic_block use_bb = gimple_bb(stmt);
	struct hdn_guard_set *cached;

	if (!use_bb || TREE_CODE(value) != SSA_NAME || !active_guard_cache)
		return false;
	cached = active_guard_cache->get(value);
	if (!cached) {
		struct hdn_guard_set found = { };
		imm_use_iterator iterator;
		gimple *condition;

		FOR_EACH_IMM_USE_STMT(condition, iterator, value) {
			basic_block guard_bb;
		tree lhs;
		tree rhs;
		enum tree_code code;
		edge true_edge;
		edge false_edge;
		edge nonnull_edge;

			if (!condition || gimple_code(condition) != GIMPLE_COND)
				continue;
			guard_bb = gimple_bb(condition);
			if (!guard_bb)
				continue;
		lhs = strip_pointer_conversions(gimple_cond_lhs(condition));
		rhs = strip_pointer_conversions(gimple_cond_rhs(condition));
		if (lhs != value && rhs == value) {
			tree swap = lhs;

			lhs = rhs;
			rhs = swap;
		}
		if (lhs != value || TREE_CODE(rhs) != INTEGER_CST ||
		    !integer_zerop(rhs))
			continue;
		code = gimple_cond_code(condition);
		if (code != EQ_EXPR && code != NE_EXPR)
			continue;
		extract_true_false_edges_from_block(guard_bb, &true_edge,
					    &false_edge);
		nonnull_edge = code == NE_EXPR ? true_edge : false_edge;
			if (!nonnull_edge)
				continue;
			if (found.count == HDN_NULL_GUARD_EDGES_MAX) {
				found.overflow = true;
				continue;
			}
			found.nonnull_edges[found.count++] = nonnull_edge;
		}
		active_guard_cache->put(value, found);
		cached = active_guard_cache->get(value);
	}
	for (unsigned int i = 0; i < cached->count; i++)
		if (dominated_by_p(CDI_DOMINATORS, use_bb,
				   cached->nonnull_edges[i]->dest))
			return true;
	return false;
}

static bool proven_nonnull_base_1(tree value, gimple *stmt,
				  unsigned int depth,
				  auto_vec<tree, 24> *visited,
				  bool allow_pointer_integer)
{
	value_range range;
	gimple *def;
	tree type;
	unsigned int i;

	if (!value || depth > HDN_NULL_ORIGIN_DEPTH)
		return false;
	value = strip_pointer_conversions(value);
	if (!value)
		return false;
	type = TREE_TYPE(value);
	if (!POINTER_TYPE_P(type) &&
	    !(allow_pointer_integer && INTEGRAL_TYPE_P(type) &&
	      TYPE_PRECISION(type) >= TYPE_PRECISION(sizetype)))
		return false;
	for (i = 0; i < visited->length(); i++)
		if ((*visited)[i] == value)
			return true;
	visited->safe_push(value);
	if (condition_proves_nonnull(value, stmt))
		return true;
	range.set_type(TREE_TYPE(value));
	if (value_range::supports_type_p(TREE_TYPE(value)) &&
	    active_range_query->range_of_expr(range, value, stmt) &&
	    !range.undefined_p() && range.nonzero_p())
		return true;
	if (TREE_CODE(value) == INTEGER_CST)
		return POINTER_TYPE_P(type) && !integer_zerop(value);
	if (TREE_CODE(value) != SSA_NAME || SSA_NAME_IS_DEFAULT_DEF(value))
		return false;
	def = SSA_NAME_DEF_STMT(value);
	if (!def)
		return false;
	if (gimple_code(def) == GIMPLE_PHI) {
		gphi *phi = as_a<gphi *>(def);

		if (!gimple_phi_num_args(phi))
			return false;
		for (i = 0; i < gimple_phi_num_args(phi); i++)
			if (!proven_nonnull_base_1(gimple_phi_arg_def(phi, i),
						   stmt, depth + 1, visited,
						   allow_pointer_integer))
				return false;
		return true;
	}
	if (is_gimple_assign(def)) {
		enum tree_code code = gimple_assign_rhs_code(def);
		tree rhs1 = gimple_assign_rhs1(def);
		bool next_allow_integer = allow_pointer_integer;

		if (CONVERT_EXPR_CODE_P(code) && rhs1 &&
		    (INTEGRAL_TYPE_P(type) ||
		     INTEGRAL_TYPE_P(TREE_TYPE(rhs1))))
			next_allow_integer = true;
		if (code == POINTER_PLUS_EXPR || code == PLUS_EXPR ||
		    code == MINUS_EXPR || CONVERT_EXPR_CODE_P(code))
			return proven_nonnull_base_1(rhs1, stmt, depth + 1,
						     visited,
						     next_allow_integer);
	}
	if (is_gimple_call(def)) {
		tree fndecl = gimple_call_fndecl(def);
		const char *name = NULL;

		if (fndecl && DECL_NAME(fndecl))
			name = IDENTIFIER_POINTER(DECL_NAME(fndecl));
		return known_nonnull_return(name) ||
		       (fndecl && lookup_attribute("returns_nonnull",
						 DECL_ATTRIBUTES(fndecl)));
	}
	return false;
}

static bool proven_nonnull_base(tree value, gimple *stmt)
{
	auto_vec<tree, 24> visited;

	return proven_nonnull_base_1(value, stmt, 0, &visited, false);
}

static const char *state_name(enum hdn_null_state state)
{
	switch (state) {
	case HDN_NULL_ZERO:
		return "zero";
	case HDN_NULL_MAYBE:
		return "includes_zero";
	case HDN_NULL_UNKNOWN:
		return "unknown";
	case HDN_NULL_VARYING:
		return "varying";
	default:
		return "nonzero";
	}
}

static const char *category_for(enum hdn_null_state state,
				const struct hdn_origin *origin,
				location_t loc, bool must_execute)
{
	if (intentional_probe_function())
		return "intentional_probe";
	if (!usable_source_location(loc))
		return "compiler_artifact";
	if (state == HDN_NULL_ZERO && must_execute)
		return "definite_fault";
	if (origin->user_influenced ||
	    (origin->parameter && attacker_entry_function()))
		return "attacker_influenced_potential";
	return "invariant_dependent";
}

static const char *taint_for(const struct hdn_origin *origin)
{
	if (origin->user_influenced ||
	    (origin->parameter && attacker_entry_function()))
		return "attacker_influenced";
	if (origin->parameter)
		return "parameter_unknown";
	if (origin->nullable_call)
		return "nullable_return";
	return "not_observed";
}

static bool reportable_state(enum hdn_null_state state,
			     const struct hdn_origin *origin)
{
	if (state == HDN_NULL_ZERO || state == HDN_NULL_MAYBE)
		return true;
	if (state != HDN_NULL_VARYING && state != HDN_NULL_UNKNOWN)
		return false;
	return intentional_probe_function() || origin->explicit_zero ||
	       origin->nullable_call ||
	       (origin->parameter && attacker_entry_function());
}

static void emit_finding(tree pointer, gimple *stmt, tree ref,
			 const char *kind, auto_vec<hdn_seen, 8> *seen)
{
	struct hdn_origin origin = { };
	enum hdn_null_state state;
	location_t loc = EXPR_LOCATION(ref);
	const char *file;
	const char *function;
	const char *category;
	const char *taint;
	const char *probe_owner;
	const char *probe_invalidation;
	basic_block entry_successor;
	bool must_execute;
	char esc_file[HDN_NULL_PATH_MAX];
	char esc_function[1024];
	char esc_callee[1024];
	char esc_probe_owner[1024];
	char esc_probe_invalidation[2048];
	char record[HDN_NULL_RECORD_MAX];
	char position[64];
	char id[64];
	uint64_t hash = UINT64_C(14695981039346656037);
	int len;

	if (!pointer || !POINTER_TYPE_P(TREE_TYPE(pointer)))
		return;
	if (loc == UNKNOWN_LOCATION)
		loc = gimple_location(stmt);
	state = pointer_state(pointer, stmt);
	if (state == HDN_NULL_NONZERO)
		return;
	trace_origin(pointer, &origin);
	origin.container_conversion |= reference_has_negative_offset(ref);
	if (!reportable_state(state, &origin))
		return;
	if (seen_before(seen, origin.root ? origin.root : pointer, kind, loc))
		return;
	if (proven_nonnull_base(pointer, stmt))
		return;
	if (already_seen(seen, origin.root ? origin.root : pointer, kind, loc))
		return;

	file = normalized_file(loc);
	function = function_name();
	entry_successor = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
	must_execute = entry_successor &&
		dominated_by_p(CDI_POST_DOMINATORS, entry_successor,
			       gimple_bb(stmt));
	category = category_for(state, &origin, loc, must_execute);
	taint = taint_for(&origin);
	intentional_probe_metadata(&probe_owner, &probe_invalidation);
	if (origin.container_conversion)
		kind = "container_conversion";

	hash = fnv1a_update(hash, HDN_NULL_ANALYZER_VERSION);
	hash = fnv1a_update(hash, "|");
	hash = fnv1a_update(hash, kind);
	hash = fnv1a_update(hash, "|");
	hash = fnv1a_update(hash, function);
	hash = fnv1a_update(hash, "|");
	hash = fnv1a_update(hash, file);
	snprintf(position, sizeof(position), "|%u|%u",
		 LOCATION_LINE(loc), LOCATION_COLUMN(loc));
	hash = fnv1a_update(hash, position);
	snprintf(id, sizeof(id), "HDN-NULL-v1-%016" PRIx64, hash);

	json_escape(esc_file, sizeof(esc_file), file);
	json_escape(esc_function, sizeof(esc_function), function);
	json_escape(esc_callee, sizeof(esc_callee),
		    origin.callee ? origin.callee : "");
	json_escape(esc_probe_owner, sizeof(esc_probe_owner), probe_owner);
	json_escape(esc_probe_invalidation, sizeof(esc_probe_invalidation),
		    probe_invalidation);
	len = snprintf(record, sizeof(record),
		"{\"schema_version\":%d,\"analyzer_version\":\"%s\","
		"\"id\":\"%s\",\"tool\":\"gcc-hdn-null\","
		"\"profile\":\"%s\",\"category\":\"%s\","
		"\"kind\":\"%s\",\"file\":\"%s\",\"line\":%u,"
		"\"column\":%u,\"function\":\"%s\",\"reachable\":true,"
		"\"reachability_evidence\":\"optimized-statement-range-dominance-and-postdominance\","
		"\"taint\":\"%s\",\"optimization_context\":\"optimized-gimple\","
		"\"range\":\"%s\",\"path_scope\":\"%s\",\"origin\":\"%s\","
		"\"probe_owner\":\"%s\",\"probe_invalidation\":\"%s\"}\n",
		HDN_NULL_SCHEMA_VERSION, HDN_NULL_ANALYZER_VERSION, id,
		analysis_profile, category, kind, esc_file, LOCATION_LINE(loc),
		LOCATION_COLUMN(loc), esc_function, taint, state_name(state),
		must_execute ? "must_execute" : "conditional",
		esc_callee, esc_probe_owner, esc_probe_invalidation);
	if (len < 0 || (size_t)len >= sizeof(record)) {
		warning(0, G_("HDN null-analysis record exceeds bounded size"));
		return;
	}
	if (write(report_fd, record, len) != len)
		warning(0, G_("cannot write HDN null-analysis report: %s"),
			xstrerror(errno));
}

static tree reference_pointer(tree ref)
{
	if (!ref)
		return NULL_TREE;
	switch (TREE_CODE(ref)) {
	case MEM_REF:
	case INDIRECT_REF:
		return TREE_OPERAND(ref, 0);
	case TARGET_MEM_REF:
		/*
		 * TARGET_MEM_REF is a composite address.  In particular, ASan can
		 * lower an ordinary dereference to a zero base plus a dynamic index.
		 * Looking at TMR_BASE alone therefore mistakes the addressing-mode
		 * placeholder for the effective pointer.  Use GCC's canonical helper
		 * so base, indexes, scale, and offset are all represented.
		 */
		return tree_mem_ref_addr(build_pointer_type(TREE_TYPE(ref)), ref);
	case COMPONENT_REF:
	case ARRAY_REF:
	case ARRAY_RANGE_REF:
	case BIT_FIELD_REF:
		return reference_pointer(TREE_OPERAND(ref, 0));
	default:
		return NULL_TREE;
	}
}

static bool reference_has_negative_offset(tree ref)
{
	if (!ref)
		return false;
	switch (TREE_CODE(ref)) {
	case MEM_REF:
		return constant_is_negative(TREE_OPERAND(ref, 1)) ||
		       reference_has_negative_offset(TREE_OPERAND(ref, 0));
	case POINTER_PLUS_EXPR:
	case PLUS_EXPR:
	case MINUS_EXPR:
		return constant_is_negative(TREE_OPERAND(ref, 1)) ||
		       reference_has_negative_offset(TREE_OPERAND(ref, 0));
	case TARGET_MEM_REF:
		return constant_is_negative(TMR_OFFSET(ref)) ||
		       reference_has_negative_offset(TMR_BASE(ref));
	case COMPONENT_REF:
	case ARRAY_REF:
	case ARRAY_RANGE_REF:
	case BIT_FIELD_REF:
		return reference_has_negative_offset(TREE_OPERAND(ref, 0));
	default:
		return false;
	}
}

struct hdn_walk_context {
	gimple *stmt;
	auto_vec<hdn_seen, 8> *seen;
};

static bool already_seen(auto_vec<hdn_seen, 8> *seen, tree pointer,
			 const char *kind, location_t location)
{
	if (seen_before(seen, pointer, kind, location))
		return true;
	hdn_seen item = { pointer, kind, location };
	seen->safe_push(item);
	return false;
}

static bool seen_before(const auto_vec<hdn_seen, 8> *seen, tree pointer,
			const char *kind, location_t location)
{
	unsigned int i;

	for (i = 0; i < seen->length(); i++)
		if ((*seen)[i].pointer == pointer &&
		    !strcmp((*seen)[i].kind, kind) &&
		    (*seen)[i].location == location)
			return true;
	return false;
}

static tree walk_reference(tree *tp, int *walk_subtrees, void *data)
{
	struct hdn_walk_context *ctx = (struct hdn_walk_context *)data;
	tree ref = *tp;
	tree pointer = NULL_TREE;
	const char *kind = NULL;

	if (!ref)
		return NULL_TREE;
	if (TREE_CODE(ref) == ADDR_EXPR) {
		*walk_subtrees = 0;
		return NULL_TREE;
	}
	if (TREE_CODE(ref) == COMPONENT_REF) {
		pointer = reference_pointer(ref);
		kind = "field_offset";
		*walk_subtrees = 0;
	} else if (TREE_CODE(ref) == MEM_REF ||
		   TREE_CODE(ref) == INDIRECT_REF ||
		   TREE_CODE(ref) == TARGET_MEM_REF) {
		pointer = reference_pointer(ref);
		kind = "direct_dereference";
		*walk_subtrees = 0;
	}
	if (pointer)
		emit_finding(pointer, ctx->stmt, ref, kind, ctx->seen);
	return NULL_TREE;
}

static unsigned int hdn_null_analysis_execute(void)
{
	basic_block bb;
	auto_vec<hdn_seen, 8> seen;
	hash_map<tree, hdn_guard_set> guard_cache(64);

	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);
	active_range_query = enable_ranger(cfun);
	active_guard_cache = &guard_cache;
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple *stmt = gsi_stmt(gsi);
			struct hdn_walk_context ctx = { stmt, &seen };
			unsigned int i;

			for (i = 0; i < gimple_num_ops(stmt); i++) {
				tree op = gimple_op(stmt, i);

				if (op)
					walk_tree(&op, walk_reference, &ctx, NULL);
			}
			if (is_gimple_call(stmt) && !gimple_call_fndecl(stmt)) {
				tree fn = gimple_call_fn(stmt);

				if (fn)
					emit_finding(fn, stmt, fn, "indirect_call",
						     &seen);
			}
		}
	}
	disable_ranger(cfun);
	active_range_query = NULL;
	active_guard_cache = NULL;
	free_dominance_info(CDI_POST_DOMINATORS);
	free_dominance_info(CDI_DOMINATORS);
	return 0;
}

#define PASS_NAME hdn_null_analysis
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_ssa
#define TODO_FLAGS_FINISH TODO_dump_func
#include "gcc-generate-gimple-pass.h"

static tree handle_attacker_attribute(tree *node, tree name, tree,
				      int, bool *no_add_attrs)
{
	if (TREE_CODE(*node) != FUNCTION_DECL) {
		*no_add_attrs = true;
		error(G_("%qE attribute applies only to functions"), name);
	}
	return NULL_TREE;
}

static tree handle_probe_attribute(tree *node, tree name, tree args,
				   int, bool *no_add_attrs)
{
	if (TREE_CODE(*node) != FUNCTION_DECL || !args || !TREE_CHAIN(args) ||
	    TREE_CODE(TREE_VALUE(args)) != STRING_CST ||
	    TREE_CODE(TREE_VALUE(TREE_CHAIN(args))) != STRING_CST) {
		*no_add_attrs = true;
		error(G_("%qE requires a function plus owner and invalidation strings"),
		      name);
	}
	return NULL_TREE;
}

static struct attribute_spec attacker_attribute = { };
static struct attribute_spec probe_attribute = { };

static void register_attributes(void *, void *)
{
	attacker_attribute.name = "hdn_null_attacker_entry";
	attacker_attribute.decl_required = true;
	attacker_attribute.handler = handle_attacker_attribute;
	register_attribute(&attacker_attribute);

	probe_attribute.name = "hdn_null_probe";
	probe_attribute.min_length = 2;
	probe_attribute.max_length = 2;
	probe_attribute.decl_required = true;
	probe_attribute.handler = handle_probe_attribute;
	register_attribute(&probe_attribute);
}

static void finish_plugin(void *, void *)
{
	if (report_fd >= 0)
		close(report_fd);
	report_fd = -1;
}

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	char path[HDN_NULL_PATH_MAX];
	int directory_error;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}
	for (i = 0; i < plugin_info->argc; i++) {
		const char *key = plugin_info->argv[i].key;
		const char *value = plugin_info->argv[i].value;

		if (!strcmp(key, "report-dir")) {
			if (!copy_option(report_dir, sizeof(report_dir), value, key))
				return 1;
		} else if (!strcmp(key, "source-root")) {
			if (!copy_option(source_root, sizeof(source_root), value, key))
				return 1;
		} else if (!strcmp(key, "profile")) {
			if (!copy_option(analysis_profile, sizeof(analysis_profile),
					 value, key))
				return 1;
		} else {
			error(G_("unknown HDN null-analysis option %qs"), key);
			return 1;
		}
	}
	if (!report_dir[0]) {
		error(G_("HDN null-analysis requires report-dir"));
		return 1;
	}
	if (!source_root[0]) {
		error(G_("HDN null-analysis requires source-root"));
		return 1;
	}
	directory_error = mkdir_parents(report_dir);
	if (directory_error) {
		error(G_("cannot create HDN null-analysis report directory %qs: %s"),
		      report_dir, xstrerror(-directory_error));
		return 1;
	}
	if (snprintf(path, sizeof(path), "%s/gcc.jsonl", report_dir) >=
	    (int)sizeof(path)) {
		error(G_("HDN null-analysis report path is too long"));
		return 1;
	}
	report_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) {
		error(G_("cannot open HDN null-analysis report %qs: %s"), path,
		      xstrerror(errno));
		return 1;
	}

	PASS_INFO(hdn_null_analysis, "optimized", 1, PASS_POS_INSERT_BEFORE);
	register_callback(plugin_info->base_name, PLUGIN_INFO, NULL,
			  &hdn_null_plugin_info);
	register_callback(plugin_info->base_name, PLUGIN_ATTRIBUTES,
			  register_attributes, NULL);
	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &hdn_null_analysis_pass_info);
	register_callback(plugin_info->base_name, PLUGIN_FINISH, finish_plugin,
			  NULL);
	return 0;
}
