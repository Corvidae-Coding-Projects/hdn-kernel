// SPDX-License-Identifier: GPL-2.0-only
/* Source lifetime evidence, before optimization removes reads and writes. */
#include "gcc-common.h"
#undef gimple
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;
static const char *source_root, *profile;
static int report_fd = -1;
static unsigned long records;

static const char *name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "<anonymous>";
}

static const char *json_boolean(bool value)
{
	if (value)
		return "true";
	return "false";
}

static const char *relative_file(const char *file)
{
	if (!file)
		return "<unknown>";
	size_t n = strlen(source_root);
	if (!strncmp(file, source_root, n) && file[n] == '/')
		return file + n + 1;
	while (file[0] == '.' && file[1] == '/')
		file += 2;
	return file;
}

static void quoted(FILE *out, const char *value)
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

static void field(FILE *out, const char *key, const char *value)
{
	fprintf(out, ",\"%s\":", key);
	quoted(out, value);
}

static void type_field(FILE *out, tree type)
{
	char *buffer = NULL;
	size_t len = 0;
	FILE *text = open_memstream(&buffer, &len);

	if (!text) {
		error(G_("cannot allocate HDN lifetime type record"));
		return;
	}
	print_generic_expr(text, type, TDF_SLIM);
	if (fclose(text))
		error(G_("cannot finish HDN lifetime type record"));
	else
		field(out, "type", buffer);
	free(buffer);
}

static const char *decl_section(tree decl)
{
	const char *s = decl ? DECL_SECTION_NAME(decl) : NULL;
	return s ? s : "<default>";
}

static bool dispatch_type(tree type, unsigned int depth = 0)
{
	if (!type || depth > 32)
		return false;
	if (TREE_CODE(type) == POINTER_TYPE)
		return TREE_CODE(TREE_TYPE(type)) == FUNCTION_TYPE;
	if (TREE_CODE(type) == ARRAY_TYPE)
		return dispatch_type(TREE_TYPE(type), depth + 1);
	if (TREE_CODE(type) == RECORD_TYPE || TREE_CODE(type) == UNION_TYPE)
		for (tree f = TYPE_FIELDS(type); f; f = DECL_CHAIN(f))
			if (TREE_CODE(f) == FIELD_DECL && dispatch_type(TREE_TYPE(f), depth + 1))
				return true;
	return false;
}

static void append(char *buffer, size_t len)
{
	size_t done = 0;
	int saved = 0;

	while (flock(report_fd, LOCK_EX))
		if (errno != EINTR) {
			error(G_("cannot lock HDN lifetime report: %s"), xstrerror(errno));
			free(buffer);
			return;
		}
	while (done < len) {
		ssize_t n = write(report_fd, buffer + done, len - done);
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
	free(buffer);
	if (saved)
		error(G_("cannot write HDN lifetime report: %s"), xstrerror(saved));
}

static void emit(const char *kind, tree target, tree caller, location_t loc)
{
	char *buffer = NULL;
	size_t len = 0;
	FILE *out = open_memstream(&buffer, &len);

	if (!out) {
		error(G_("cannot allocate HDN lifetime record"));
		return;
	}
	fputs("{\"schema_version\":1,\"analyzer_version\":\"2.0.0\"", out);
	field(out, "kind", kind);
	field(out, "unit", relative_file(main_input_filename));
	field(out, "profile", profile);
	field(out, "file", relative_file(LOCATION_FILE(loc)));
	fprintf(out, ",\"line\":%d,\"column\":%d", LOCATION_LINE(loc), LOCATION_COLUMN(loc));
	field(out, "caller", caller ? name(caller) : "<initializer>");
	field(out, "caller_section", decl_section(caller));
	if (target) {
		type_field(out, TREE_TYPE(target));
		field(out, "symbol", name(target));
		field(out, "symbol_section", decl_section(target));
		field(out, "symbol_file", relative_file(DECL_SOURCE_FILE(target)));
		field(out, "symbol_context", DECL_CONTEXT(target) &&
		      TREE_CODE(DECL_CONTEXT(target)) == FUNCTION_DECL ? name(DECL_CONTEXT(target)) : "");
		field(out, "symbol_asm", DECL_ASSEMBLER_NAME_SET_P(target) ?
		      IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(target)) : name(target));
		fprintf(out, ",\"symbol_line\":%d,\"public\":%s,\"readonly\":%s,\"dispatch\":%s",
			DECL_SOURCE_LINE(target), json_boolean(TREE_PUBLIC(target)),
			json_boolean(TREE_READONLY(target)),
			json_boolean(dispatch_type(TREE_TYPE(target))));
	}
	if (!strcmp(kind, "unit"))
		fprintf(out, ",\"records\":%lu,\"compiler_errors\":%d", records, errorcount);
	fputs("}\n", out);
	if (fclose(out)) {
		free(buffer);
		error(G_("cannot finish HDN lifetime record"));
		return;
	}
	append(buffer, len);
	records++;
}

struct walk_context {
	const char *kind;
	tree caller;
	location_t location;
};

/* Resolve local SSA address copies without pretending an unknown alias is safe. */
static bool pointer_targets_impl(tree value, struct walk_context *ctx,
				 auto_vec<tree, 32> &visited, unsigned int depth)
{
	if (!value || depth > 32 || visited.length() >= 256)
		return false;
	for (unsigned int i = 0; i < visited.length(); i++)
		if (visited[i] == value)
			return false;
	visited.safe_push(value);
	if (TREE_CODE(value) == ADDR_EXPR) {
		tree base = get_base_address(TREE_OPERAND(value, 0));
		if (base && (TREE_CODE(base) == FUNCTION_DECL ||
		    (TREE_CODE(base) == VAR_DECL && (TREE_STATIC(base) || DECL_EXTERNAL(base))))) {
			emit(ctx->kind, base, ctx->caller, ctx->location);
			return true;
		}
		/* A local object's address is resolved but is outside static inventory. */
		return base && TREE_CODE(base) == VAR_DECL;
	}
	if (TREE_CODE(value) != SSA_NAME || SSA_NAME_IS_DEFAULT_DEF(value))
		return false;
	gimple *def = SSA_NAME_DEF_STMT(value);
	if (!def)
		return false;
	if (is_gimple_assign(def)) {
		enum tree_code code = gimple_assign_rhs_code(def);
		if (code == ADDR_EXPR || code == SSA_NAME || code == POINTER_PLUS_EXPR ||
		    code == NOP_EXPR || code == CONVERT_EXPR)
			return pointer_targets_impl(gimple_assign_rhs1(def), ctx, visited, depth + 1);
	} else if (gimple_code(def) == GIMPLE_PHI) {
		bool resolved = true;
		for (unsigned int i = 0; i < gimple_phi_num_args(def); i++)
			resolved &= pointer_targets_impl(gimple_phi_arg_def(def, i), ctx, visited, depth + 1);
		return resolved;
	}
	return false;
}

static bool pointer_targets(tree value, struct walk_context *ctx)
{
	auto_vec<tree, 32> visited;
	return pointer_targets_impl(value, ctx, visited, 0);
}

static tree visit(tree *node, int *walk_subtrees, void *data)
{
	struct walk_context *ctx = (struct walk_context *)data;
	tree t = *node;

	if (!t)
		return NULL_TREE;
	if (TREE_CODE(t) == MEM_REF || TREE_CODE(t) == TARGET_MEM_REF) {
		if (!pointer_targets(TREE_OPERAND(t, 0), ctx))
			emit(!strcmp(ctx->kind, "read") ? "indirect-read" : "indirect-reference",
			     NULL_TREE, ctx->caller, ctx->location);
		*walk_subtrees = 0;
	} else if (TREE_CODE(t) == ADDR_EXPR) {
		struct walk_context address = {
			!strcmp(ctx->kind, "initializer-reference") ? "initializer-reference" : "address",
			ctx->caller, ctx->location
		};
		tree value = TREE_OPERAND(t, 0);
		walk_tree_without_duplicates(&value, visit, &address);
		*walk_subtrees = 0;
	} else if (TREE_CODE(t) == VAR_DECL || TREE_CODE(t) == FUNCTION_DECL) {
		if (TREE_CODE(t) == FUNCTION_DECL || TREE_STATIC(t) || DECL_EXTERNAL(t))
			emit(ctx->kind, t, ctx->caller, ctx->location);
		*walk_subtrees = 0; /* Do not recursively visit a declaration's initializer. */
	} else if (TREE_CODE(t) == SSA_NAME) {
		if (POINTER_TYPE_P(TREE_TYPE(t)) && !pointer_targets(t, ctx))
			emit("indirect-reference", NULL_TREE, ctx->caller, ctx->location);
		*walk_subtrees = 0;
	} else if (TYPE_P(t)) {
		*walk_subtrees = 0;
	}
	return NULL_TREE;
}

static void operand(tree value, const char *kind, tree caller, location_t loc)
{
	if (!value)
		return;
	struct walk_context ctx = { kind, caller, loc };
	if (!strcmp(kind, "write")) {
		tree base = get_base_address(value);
		if (!base || TREE_CODE(base) == SSA_NAME)
			return;
		if (TREE_CODE(base) == MEM_REF || TREE_CODE(base) == TARGET_MEM_REF) {
			if (!pointer_targets(TREE_OPERAND(base, 0), &ctx))
				emit("indirect-write", NULL_TREE, caller, loc);
			return;
		}
		/* Array indices are reads, not writes to the index variable. */
		value = base;
	}
	walk_tree_without_duplicates(&value, visit, &ctx);
}

static void declaration(void *gcc_data, void *)
{
	tree decl = (tree)gcc_data;
	if (TREE_CODE(decl) != VAR_DECL || !TREE_STATIC(decl) || DECL_EXTERNAL(decl))
		return;
	emit("object", decl, NULL_TREE, DECL_SOURCE_LOCATION(decl));
	/* Initializer references are distinct from runtime address escapes. */
	operand(DECL_INITIAL(decl), "initializer-reference", decl, DECL_SOURCE_LOCATION(decl));
}

static unsigned int hdn_lifetime_execute(void)
{
	basic_block bb;
	tree caller = current_function_decl;
	emit("function", caller, caller, DECL_SOURCE_LOCATION(caller));
	FOR_EACH_BB_FN(bb, cfun) {
		for (gimple_stmt_iterator gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple *stmt = gsi_stmt(gsi);
			location_t loc = gimple_location(stmt);
			if (loc == UNKNOWN_LOCATION)
				loc = DECL_SOURCE_LOCATION(caller);
			if (is_gimple_assign(stmt)) {
				tree lhs = gimple_assign_lhs(stmt);
				operand(lhs, "write", caller, loc);
				for (unsigned int i = 1; i < gimple_num_ops(stmt); i++)
					operand(gimple_op(stmt, i), "read", caller, loc);
			} else if (is_gimple_call(stmt)) {
				tree callee = gimple_call_fndecl(stmt);
				emit(callee ? "call" : "indirect-call", callee, caller, loc);
				for (unsigned int i = 0; i < gimple_call_num_args(stmt); i++)
					operand(gimple_call_arg(stmt, i), "call-argument", caller, loc);
				operand(gimple_call_lhs(stmt), "write", caller, loc);
			} else {
				if (gimple_code(stmt) == GIMPLE_ASM)
					emit("assembly", NULL_TREE, caller, loc);
				for (unsigned int i = 0; i < gimple_num_ops(stmt); i++)
					operand(gimple_op(stmt, i), "reference", caller, loc);
			}
		}
	}
	return 0;
}

#define PASS_NAME hdn_lifetime
#define PROPERTIES_REQUIRED PROP_ssa
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

static void finish(void *, void *)
{
	emit("unit", NULL_TREE, NULL_TREE, UNKNOWN_LOCATION);
	close(report_fd);
}

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	const char *report = NULL;
	if (!plugin_default_version_check(version, &gcc_version))
		return 1;
	for (int i = 0; i < info->argc; i++) {
		const char *key = info->argv[i].key, *value = info->argv[i].value;
		if (!value || !*value)
			return 1;
		if (!strcmp(key, "report"))
			report = value;
		else if (!strcmp(key, "source-root"))
			source_root = value;
		else if (!strcmp(key, "profile"))
			profile = value;
		else
			return 1;
	}
	if (!report || !source_root || !profile) {
		error(G_("HDN lifetime analysis requires report, source-root and profile"));
		return 1;
	}
	report_fd = open(report, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) {
		error(G_("cannot open HDN lifetime report: %s"), xstrerror(errno));
		return 1;
	}
	PASS_INFO(hdn_lifetime, "ssa", 1, PASS_POS_INSERT_AFTER);
	register_callback(info->base_name, PLUGIN_FINISH_DECL, declaration, NULL);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_lifetime_pass_info);
	register_callback(info->base_name, PLUGIN_FINISH, finish, NULL);
	return 0;
}
