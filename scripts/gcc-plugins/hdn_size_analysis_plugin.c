// SPDX-License-Identifier: GPL-2.0-only
/*
 * Inventory integer arithmetic feeding allocation/copy/length boundaries.
 * This is a reporting pass: it never rewrites arithmetic or grants an
 * exception. Review policy and source-bound exceptions live in the verifier.
 * Run immediately after SSA construction, before inlining erases checked-size
 * helper contracts and explicit wrapping annotations.
 */
#include "gcc-common.h"
#undef gimple

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;

static const char *source_root;
static const char *profile;
static int report_fd = -1;
static unsigned long finding_count;

static const char *decl_name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "";
}

static const char *json_boolean(bool value)
{
	if (value)
		return "true";
	return "false";
}

static const char *relative_file(const char *file)
{
	size_t n = strlen(source_root);

	if (!file)
		return "<unknown>";
	if (!strncmp(file, source_root, n) && file[n] == '/')
		return file + n + 1;
	while (file[0] == '.' && file[1] == '/')
		file += 2;
	return file;
}

static void json_string(FILE *out, const char *value)
{
	fputc('"', out);
	for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(out, "\\%c", *p);
		else if (*p < 0x20)
			fprintf(out, "\\u%04x", *p);
		else
			fputc(*p, out);
	}
	fputc('"', out);
}

static void string_field(FILE *out, const char *key, const char *value)
{
	fprintf(out, ",\"%s\":", key);
	json_string(out, value);
}

static void write_record(char *record, size_t len)
{
	size_t done = 0;
	int saved = 0;

	/* A record may exceed PIPE_BUF; serialize independent compiler writers. */
	while (flock(report_fd, LOCK_EX)) {
		if (errno != EINTR) {
			error(G_("cannot lock HDN size-analysis report: %s"),
			      xstrerror(errno));
			free(record);
			return;
		}
	}
	while (done < len) {
		ssize_t n = write(report_fd, record + done, len - done);

		if (n > 0)
			done += n;
		else if (n < 0 && errno == EINTR)
			continue;
		else {
			saved = n < 0 ? errno : EIO;
			break;
		}
	}
	if (flock(report_fd, LOCK_UN) && !saved)
		saved = errno;
	free(record);
	if (saved)
		error(G_("cannot write HDN size-analysis report: %s"),
		      xstrerror(saved));
}

static tree wrap_attribute(tree decl)
{
	return decl ? lookup_attribute("hdn_size_wrap", DECL_ATTRIBUTES(decl)) : NULL_TREE;
}

static void emit(gimple *stmt, gimple *sink, unsigned int argument,
		 const char *kind, const char *origin, tree type, tree annotation)
{
	location_t loc = stmt ? gimple_location(stmt) : DECL_SOURCE_LOCATION(current_function_decl);
	location_t sink_loc = sink ? gimple_location(sink) : loc;
	char *record = NULL;
	size_t len = 0;
	FILE *out = open_memstream(&record, &len);

	if (!out) {
		error(G_("cannot allocate HDN size-analysis record"));
		return;
	}
	fputs("{\"schema_version\":1,\"analyzer_version\":\"1.0.0\",\"record_type\":\"finding\"", out);
	string_field(out, "unit", relative_file(main_input_filename));
	string_field(out, "profile", profile);
	string_field(out, "file", relative_file(LOCATION_FILE(loc)));
	string_field(out, "function", decl_name(current_function_decl));
	string_field(out, "kind", kind);
	string_field(out, "origin", origin);
	string_field(out, "analysis_scope", "intraprocedural-early-ssa");
	string_field(out, "sink", sink ? decl_name(gimple_call_fndecl(sink)) : "annotated-wrap");
	string_field(out, "sink_file", relative_file(LOCATION_FILE(sink_loc)));
	fprintf(out, ",\"line\":%d,\"column\":%d,\"sink_line\":%d,\"sink_column\":%d,\"argument\":%u",
		LOCATION_LINE(loc), LOCATION_COLUMN(loc), LOCATION_LINE(sink_loc),
		LOCATION_COLUMN(sink_loc), argument + 1);
	fprintf(out, ",\"precision\":%u,\"unsigned\":%s",
		type && INTEGRAL_TYPE_P(type) ? TYPE_PRECISION(type) : 0,
		json_boolean(type && INTEGRAL_TYPE_P(type) && TYPE_UNSIGNED(type)));
	if (annotation) {
		tree args = TREE_VALUE(annotation);
		const char *keys[] = { "owner", "reason", "invalidation" };

		for (unsigned int i = 0; i < ARRAY_SIZE(keys); i++, args = TREE_CHAIN(args))
			string_field(out, keys[i], TREE_STRING_POINTER(TREE_VALUE(args)));
	}
	fputs("}\n", out);
	if (fclose(out)) {
		free(record);
		error(G_("cannot finish HDN size-analysis record"));
		return;
	}
	write_record(record, len);
	finding_count++;
}

static bool named(const char *name, const char * const *names, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

static bool checked_size_helper(const char *name)
{
	static const char * const helpers[] = { "size_add", "size_mul", "size_sub" };

	return named(name, helpers, ARRAY_SIZE(helpers));
}

static void trace_size(tree value, gimple *sink, unsigned int argument,
		       auto_vec<tree, 32> &visited, unsigned int depth)
{
	gimple *def;
	tree type;

	if (!value || TREE_CODE(value) == INTEGER_CST)
		return;
	type = TREE_TYPE(value);
	if (!type || !INTEGRAL_TYPE_P(type))
		return;
	if (depth > 64 || visited.length() > 512) {
		emit(sink, sink, argument, "analysis_limit", "unresolved", type, NULL_TREE);
		return;
	}
	for (unsigned int i = 0; i < visited.length(); i++)
		if (visited[i] == value)
			return;
	visited.safe_push(value);
	if (TREE_CODE(value) != SSA_NAME) {
		emit(sink, sink, argument, "external_size", "memory-or-expression", type, NULL_TREE);
		return;
	}
	if (SSA_NAME_IS_DEFAULT_DEF(value)) {
		emit(sink, sink, argument, "external_size", "parameter-or-initial-value", type, NULL_TREE);
		return;
	}
	def = SSA_NAME_DEF_STMT(value);
	if (!def) {
		emit(sink, sink, argument, "unresolved_size", "missing-definition", type, NULL_TREE);
		return;
	}
	if (gimple_code(def) == GIMPLE_PHI) {
		for (unsigned int i = 0; i < gimple_phi_num_args(def); i++)
			trace_size(gimple_phi_arg_def(def, i), sink, argument, visited, depth + 1);
		return;
	}
	if (is_gimple_call(def)) {
		tree decl = gimple_call_fndecl(def);
		const char *name = decl_name(decl);

		if (checked_size_helper(name)) {
			/* Checked outer arithmetic cannot repair pre-wrapped operands. */
			for (unsigned int i = 0; i < gimple_call_num_args(def); i++)
				trace_size(gimple_call_arg(def, i), sink, argument, visited, depth + 1);
		} else {
			emit(def, sink, argument,
			     wrap_attribute(decl) ? "wrapped_size" : "external_size",
			     "call-result", type, wrap_attribute(decl));
		}
		return;
	}
	if (is_gimple_assign(def)) {
		enum tree_code code = gimple_assign_rhs_code(def);
		tree rhs = gimple_assign_rhs1(def);
		const char *kind = NULL;

		switch (code) {
		case PLUS_EXPR: kind = "unchecked_add"; break;
		case MULT_EXPR: kind = "unchecked_multiply"; break;
		case MINUS_EXPR: kind = "unchecked_subtract"; break;
		case LSHIFT_EXPR: kind = "unchecked_shift"; break;
		case REALPART_EXPR: kind = "overflow_result_requires_guard"; break;
		default: break;
		}
		if (CONVERT_EXPR_CODE_P(code) && INTEGRAL_TYPE_P(TREE_TYPE(rhs)) &&
		    (TYPE_PRECISION(type) < TYPE_PRECISION(TREE_TYPE(rhs)) ||
		     TYPE_UNSIGNED(type) != TYPE_UNSIGNED(TREE_TYPE(rhs))))
			kind = "size_conversion";
		if (kind)
			emit(def, sink, argument, kind, "ssa-arithmetic", type, NULL_TREE);
		if (gimple_assign_load_p(def)) {
			emit(def, sink, argument, "external_size", "memory-load", type, NULL_TREE);
			return;
		}
		for (unsigned int i = 1; i < gimple_num_ops(def); i++)
			trace_size(gimple_op(def, i), sink, argument, visited, depth + 1);
		return;
	}
	emit(def, sink, argument, "unresolved_size", "unsupported-definition", type, NULL_TREE);
}

static void inspect_argument(gimple *stmt, unsigned int argument)
{
	auto_vec<tree, 32> visited;

	if (argument >= gimple_call_num_args(stmt)) {
		error_at(gimple_location(stmt), G_("invalid HDN allocation-size argument"));
		return;
	}
	trace_size(gimple_call_arg(stmt, argument), stmt, argument, visited, 0);
}

static unsigned int hdn_size_analysis_execute(void)
{
	static const char * const copies[] = {
		"memcpy", "memmove", "memset", "__builtin_memcpy", "__builtin_memmove",
		"__builtin_memset", "copy_from_user", "copy_to_user", "_copy_from_user",
		"_copy_to_user", "__copy_from_user", "__copy_to_user", "copy_in_user",
	};
	static const char * const allocators[] = {
		"kmalloc", "kzalloc", "kvmalloc", "kvzalloc", "vmalloc", "vzalloc",
		"__kmalloc", "__kmalloc_noprof", "kmalloc_noprof", "kzalloc_noprof",
		"kvmalloc_node_noprof", "__vmalloc_node_range_noprof",
	};
	static const char * const resizers[] = {
		"krealloc", "kvrealloc", "krealloc_noprof", "kvrealloc_node_align_noprof",
		"kmemdup", "kmemdup_noprof", "memdup_user", "vmemdup_user",
	};
	basic_block bb;
	tree annotation = wrap_attribute(current_function_decl);

	if (annotation)
		emit(NULL, NULL, 0, "intentional_wrap", "annotated-helper",
		     TREE_TYPE(TREE_TYPE(current_function_decl)), annotation);
	FOR_EACH_BB_FN(bb, cfun) {
		for (gimple_stmt_iterator it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
			gimple *stmt = gsi_stmt(it);
			tree decl, attr;
			const char *name;

			if (!is_gimple_call(stmt))
				continue;
			decl = gimple_call_fndecl(stmt);
			if (!decl)
				continue;
			name = decl_name(decl);
			attr = lookup_attribute("alloc_size", TYPE_ATTRIBUTES(TREE_TYPE(decl)));
			if (!attr)
				attr = lookup_attribute("alloc_size", DECL_ATTRIBUTES(decl));
			if (attr) {
				for (tree arg = TREE_VALUE(attr); arg; arg = TREE_CHAIN(arg)) {
					tree pos = TREE_VALUE(arg);

					if (!tree_fits_uhwi_p(pos) || !tree_to_uhwi(pos)) {
						error_at(gimple_location(stmt), G_("invalid alloc_size metadata"));
						continue;
					}
					inspect_argument(stmt, tree_to_uhwi(pos) - 1);
				}
			} else if (named(name, copies, ARRAY_SIZE(copies))) {
				inspect_argument(stmt, 2);
			} else if (named(name, allocators, ARRAY_SIZE(allocators))) {
				inspect_argument(stmt, 0);
			} else if (named(name, resizers, ARRAY_SIZE(resizers))) {
				inspect_argument(stmt, 1);
			} else if (checked_size_helper(name)) {
				for (unsigned int i = 0; i < gimple_call_num_args(stmt); i++)
					inspect_argument(stmt, i);
			}
		}
	}
	return 0;
}

#define PASS_NAME hdn_size_analysis
#define NO_GATE
#define PROPERTIES_REQUIRED PROP_ssa
#include "gcc-generate-gimple-pass.h"

static tree handle_wrap(tree *node, tree name, tree args, int, bool *no_add_attrs)
{
	bool valid = TREE_CODE(*node) == FUNCTION_DECL;
	unsigned int count = 0;

	if (valid) {
		tree result = TREE_TYPE(TREE_TYPE(*node));

		valid = INTEGRAL_TYPE_P(result) && TYPE_UNSIGNED(result);
		for (tree arg = TYPE_ARG_TYPES(TREE_TYPE(*node)); arg; arg = TREE_CHAIN(arg)) {
			tree type = TREE_VALUE(arg);

			if (type != void_type_node && (!INTEGRAL_TYPE_P(type) || !TYPE_UNSIGNED(type)))
				valid = false;
		}
	}
	for (tree arg = args; arg; arg = TREE_CHAIN(arg), count++)
		if (TREE_CODE(TREE_VALUE(arg)) != STRING_CST || TREE_STRING_LENGTH(TREE_VALUE(arg)) < 2)
			valid = false;
	if (!valid || count != 3) {
		*no_add_attrs = true;
		error(G_("%qE requires an unsigned integer helper and nonempty owner, reason, invalidation strings"), name);
	}
	return NULL_TREE;
}

static void register_attributes(void *, void *)
{
	static struct attribute_spec attr = {};

	attr.name = "hdn_size_wrap";
	attr.min_length = 3;
	attr.max_length = 3;
	attr.decl_required = true;
	attr.handler = handle_wrap;
	register_attribute(&attr);
}

static void finish(void *, void *)
{
	char *record = NULL;
	size_t len = 0;
	FILE *out = open_memstream(&record, &len);

	if (!out) {
		error(G_("cannot allocate HDN size-analysis unit record"));
		return;
	}
	fputs("{\"schema_version\":1,\"analyzer_version\":\"1.0.0\",\"record_type\":\"unit\"", out);
	string_field(out, "unit", relative_file(main_input_filename));
	string_field(out, "profile", profile);
	fprintf(out, ",\"findings\":%lu,\"compiler_errors\":%d}\n", finding_count, errorcount);
	if (fclose(out)) {
		free(record);
		error(G_("cannot finish HDN size-analysis unit record"));
	} else {
		write_record(record, len);
	}
	close(report_fd);
	report_fd = -1;
}

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	const char *report = NULL;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}
	for (int i = 0; i < info->argc; i++) {
		const char *key = info->argv[i].key;
		const char *value = info->argv[i].value;

		if (!value || !*value) {
			error(G_("missing HDN size-analysis option value"));
			return 1;
		}
		if (!strcmp(key, "report"))
			report = value;
		else if (!strcmp(key, "source-root"))
			source_root = value;
		else if (!strcmp(key, "profile"))
			profile = value;
		else {
			error(G_("unknown HDN size-analysis option %qs"), key);
			return 1;
		}
	}
	if (!report || !source_root || !profile) {
		error(G_("HDN size-analysis requires report, source-root, and profile"));
		return 1;
	}
	report_fd = open(report, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) {
		error(G_("cannot open HDN size-analysis report: %s"), xstrerror(errno));
		return 1;
	}
	PASS_INFO(hdn_size_analysis, "ssa", 1, PASS_POS_INSERT_AFTER);
	register_callback(info->base_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_size_analysis_pass_info);
	register_callback(info->base_name, PLUGIN_FINISH, finish, NULL);
	return 0;
}
