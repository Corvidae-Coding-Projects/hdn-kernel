// SPDX-License-Identifier: GPL-2.0-only
/* Inventory page-table writes before optimization erases their source shape. */
#include "gcc-common.h"
#undef gimple
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

__visible int plugin_is_GPL_compatible;
static const char *source_root, *profile;
static int report_fd = -1;
static unsigned long findings;

static const char *decl_name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "<anonymous>";
}

static const char *relative_file(const char *file)
{
	size_t length;

	if (!file)
		return "<unknown>";
	length = strlen(source_root);
	if (!strncmp(file, source_root, length) && file[length] == '/')
		return file + length + 1;
	while (file[0] == '.' && file[1] == '/')
		file += 2;
	return file;
}

static void quote(FILE *out, const char *value)
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
	quote(out, value ? value : "");
}

static const char *type_name(tree type)
{
	tree name;

	if (!type)
		return NULL;
	type = TYPE_MAIN_VARIANT(type);
	name = TYPE_NAME(type);
	if (!name)
		return NULL;
	if (TREE_CODE(name) == TYPE_DECL)
		name = DECL_NAME(name);
	return name && TREE_CODE(name) == IDENTIFIER_NODE ? IDENTIFIER_POINTER(name) : NULL;
}

static bool page_table_name(const char *name)
{
	static const char *const names[] = {
		"pte_t", "pmd_t", "pud_t", "p4d_t", "pgd_t",
		"pteval_t", "pmdval_t", "pudval_t", "p4dval_t", "pgdval_t",
	};

	if (!name)
		return false;
	for (unsigned int i = 0; i < ARRAY_SIZE(names); i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

static bool page_table_type(tree type, unsigned int depth = 0)
{
	if (!type || depth > 12)
		return false;
	type = TYPE_MAIN_VARIANT(type);
	if (page_table_name(type_name(type)))
		return true;
	if (TREE_CODE(type) == POINTER_TYPE || TREE_CODE(type) == ARRAY_TYPE ||
	    TREE_CODE(type) == REFERENCE_TYPE)
		return page_table_type(TREE_TYPE(type), depth + 1);
	return false;
}

static bool page_table_field(tree field)
{
	const char *name;

	if (!field || TREE_CODE(field) != FIELD_DECL)
		return false;
	if (page_table_type(DECL_CONTEXT(field)) || page_table_type(TREE_TYPE(field)))
		return true;
	name = decl_name(field);
	return !strcmp(name, "pte") || !strcmp(name, "pmd") || !strcmp(name, "pud") ||
	       !strcmp(name, "p4d") || !strcmp(name, "pgd") ||
	       !strcmp(name, "pte_low") || !strcmp(name, "pte_high") ||
	       !strcmp(name, "pmd_low") || !strcmp(name, "pmd_high");
}

static bool page_table_expr_impl(tree value, auto_vec<tree, 32> &visited,
				 unsigned int depth)
{
	if (!value || depth > 32 || visited.length() >= 256)
		return false;
	for (unsigned int i = 0; i < visited.length(); i++)
		if (visited[i] == value)
			return false;
	visited.safe_push(value);
	if (page_table_type(TREE_TYPE(value)))
		return true;
	switch (TREE_CODE(value)) {
	case COMPONENT_REF:
		return page_table_field(TREE_OPERAND(value, 1)) ||
		       page_table_expr_impl(TREE_OPERAND(value, 0), visited, depth + 1);
	case MEM_REF:
	case TARGET_MEM_REF:
	case INDIRECT_REF:
	case ADDR_EXPR:
	case NOP_EXPR:
	case CONVERT_EXPR:
	case VIEW_CONVERT_EXPR:
	case NON_LVALUE_EXPR:
		return page_table_expr_impl(TREE_OPERAND(value, 0), visited, depth + 1);
	case ARRAY_REF:
	case ARRAY_RANGE_REF:
		return page_table_expr_impl(TREE_OPERAND(value, 0), visited, depth + 1);
	case POINTER_PLUS_EXPR:
		return page_table_expr_impl(TREE_OPERAND(value, 0), visited, depth + 1);
	case SSA_NAME: {
		gimple *definition;

		if (SSA_NAME_IS_DEFAULT_DEF(value))
			return page_table_type(TREE_TYPE(value));
		definition = SSA_NAME_DEF_STMT(value);
		if (!definition)
			return false;
		if (is_gimple_assign(definition))
			return page_table_expr_impl(gimple_assign_rhs1(definition), visited, depth + 1);
		if (gimple_code(definition) == GIMPLE_PHI) {
			for (unsigned int i = 0; i < gimple_phi_num_args(definition); i++)
				if (page_table_expr_impl(gimple_phi_arg_def(definition, i), visited,
							 depth + 1))
					return true;
		}
		return false;
	}
	default:
		return false;
	}
}

static bool page_table_expr(tree value)
{
	auto_vec<tree, 32> visited;

	return page_table_expr_impl(value, visited, 0);
}

static bool indirect_store(tree lhs)
{
	tree base = lhs ? get_base_address(lhs) : NULL_TREE;

	return base && (TREE_CODE(base) == MEM_REF || TREE_CODE(base) == TARGET_MEM_REF ||
			TREE_CODE(base) == INDIRECT_REF);
}

static bool function_page_table_context(tree function)
{
	const char *name = decl_name(function);

	if (!strncmp(name, "hdn_pt_", 7) || !strncmp(name, "hdn_stack_mm_", 13) ||
	    !strncmp(name, "native_set_p", 12) || !strncmp(name, "set_p", 5) ||
	    !strncmp(name, "ptep_", 5) || !strncmp(name, "pmdp_", 5) ||
	    !strncmp(name, "pudp_", 5) || !strncmp(name, "p4dp_", 5) ||
	    !strncmp(name, "pgdp_", 5))
		return true;
	if (page_table_type(TREE_TYPE(function)))
		return true;
	for (tree argument = DECL_ARGUMENTS(function); argument; argument = DECL_CHAIN(argument))
		if (page_table_type(TREE_TYPE(argument)))
			return true;
	return false;
}

static bool mutation_name(const char *name)
{
	static const char *const prefixes[] = {
		"set_pte", "set_pmd", "set_pud", "set_p4d", "set_pgd",
		"native_set_pte", "native_set_pmd", "native_set_pud", "native_set_p4d",
		"native_set_pgd", "ptep_", "pmdp_", "pudp_", "p4dp_", "pgdp_",
		"native_ptep_", "native_pmdp_", "native_pudp_", "native_p4dp_",
		"native_pgdp_", "hdn_pt_",
	};

	if (!name)
		return false;
	for (unsigned int i = 0; i < ARRAY_SIZE(prefixes); i++)
		if (!strncmp(name, prefixes[i], strlen(prefixes[i])))
			return true;
	return false;
}

static bool bulk_write_name(const char *name)
{
	return name && (!strcmp(name, "memcpy") || !strcmp(name, "memmove") ||
			!strcmp(name, "memset") || !strcmp(name, "__memcpy") ||
			!strcmp(name, "__memset") || !strcmp(name, "__builtin_memcpy") ||
			!strcmp(name, "__builtin_memmove") || !strcmp(name, "__builtin_memset") ||
			!strcmp(name, "clear_page"));
}

static void type_field(FILE *out, tree value)
{
	char *buffer = NULL;
	size_t length = 0;
	FILE *type;

	if (!value || !TREE_TYPE(value))
		return;
	type = open_memstream(&buffer, &length);
	if (!type) {
		error(G_("cannot allocate HDN page-table type record"));
		return;
	}
	print_generic_expr(type, TREE_TYPE(value), TDF_SLIM);
	if (fclose(type))
		error(G_("cannot finish HDN page-table type record"));
	else
		field(out, "type", buffer);
	free(buffer);
}

static void append(char *buffer, size_t length)
{
	size_t done = 0;
	int saved = 0;

	while (flock(report_fd, LOCK_EX))
		if (errno != EINTR) {
			error(G_("cannot lock HDN page-table report: %s"), xstrerror(errno));
			free(buffer);
			return;
		}
	while (done < length) {
		ssize_t count = write(report_fd, buffer + done, length - done);
		if (count > 0)
			done += count;
		else if (count < 0 && errno == EINTR)
			continue;
		else {
			saved = count < 0 ? errno : EIO;
			break;
		}
	}
	if (flock(report_fd, LOCK_UN) && !saved)
		saved = errno;
	free(buffer);
	if (saved)
		error(G_("cannot write HDN page-table report: %s"), xstrerror(saved));
}

static void emit(const char *kind, tree caller, location_t location, tree value,
			 const char *operation)
{
	char *buffer = NULL;
	size_t length = 0;
	FILE *out = open_memstream(&buffer, &length);

	if (!out) {
		error(G_("cannot allocate HDN page-table record"));
		return;
	}
	fputs("{\"schema_version\":1,\"analyzer_version\":\"1.0.0\"", out);
	field(out, "kind", kind);
	field(out, "unit", relative_file(main_input_filename));
	field(out, "profile", profile);
	field(out, "file", relative_file(LOCATION_FILE(location)));
	fprintf(out, ",\"line\":%d,\"column\":%d", LOCATION_LINE(location),
		LOCATION_COLUMN(location));
	field(out, "caller", caller ? decl_name(caller) : "<unit>");
	field(out, "operation", operation);
	type_field(out, value);
	if (!strcmp(kind, "unit"))
		fprintf(out, ",\"findings\":%lu,\"compiler_errors\":%d", findings, errorcount);
	else
		fprintf(out, ",\"sequence\":%lu", findings);
	fputs("}\n", out);
	if (fclose(out)) {
		free(buffer);
		error(G_("cannot finish HDN page-table record"));
		return;
	}
	append(buffer, length);
	if (strcmp(kind, "unit"))
		findings++;
}

static unsigned int hdn_pgtable_execute(void)
{
	basic_block block;
	tree caller = current_function_decl;
	bool context = function_page_table_context(caller);

	/* First retain functions whose local GIMPLE still carries a page-table type. */
	FOR_EACH_BB_FN(block, cfun)
		for (gimple_stmt_iterator iterator = gsi_start_bb(block); !gsi_end_p(iterator);
		     gsi_next(&iterator)) {
			gimple *statement = gsi_stmt(iterator);
			for (unsigned int i = 0; i < gimple_num_ops(statement); i++)
				context |= page_table_expr(gimple_op(statement, i));
		}

	FOR_EACH_BB_FN(block, cfun) {
		for (gimple_stmt_iterator iterator = gsi_start_bb(block); !gsi_end_p(iterator);
		     gsi_next(&iterator)) {
			gimple *statement = gsi_stmt(iterator);
			location_t location = gimple_location(statement);

			if (location == UNKNOWN_LOCATION)
				location = DECL_SOURCE_LOCATION(caller);
			if (is_gimple_assign(statement)) {
				tree lhs = gimple_assign_lhs(statement);
				if (page_table_expr(lhs))
					emit("typed-store", caller, location, lhs, "assignment");
				else if (context && indirect_store(lhs))
					emit("unresolved-indirect-store", caller, location, lhs,
					     "assignment");
			} else if (is_gimple_call(statement)) {
				tree callee = gimple_call_fndecl(statement);
				const char *name = callee ? decl_name(callee) : NULL;
				if (mutation_name(name))
					emit("mutation-call", caller, location, NULL_TREE, name);
				if (bulk_write_name(name) && gimple_call_num_args(statement) &&
				    page_table_expr(gimple_call_arg(statement, 0)))
					emit("typed-bulk-write", caller, location,
					     gimple_call_arg(statement, 0), name);
				if (context && !callee)
					emit("indirect-call", caller, location, NULL_TREE, "<indirect>");
			} else if (context && gimple_code(statement) == GIMPLE_ASM) {
				emit("assembly", caller, location, NULL_TREE, "inline-assembly");
			}
		}
	}
	return 0;
}

#define PASS_NAME hdn_pgtable
#define PROPERTIES_REQUIRED PROP_ssa
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

static void finish(void *, void *)
{
	emit("unit", NULL_TREE, UNKNOWN_LOCATION, NULL_TREE, "finish");
	close(report_fd);
}

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	const char *report = NULL;

	if (!plugin_default_version_check(version, &gcc_version))
		return 1;
	for (int i = 0; i < info->argc; i++) {
		const char *key = info->argv[i].key;
		const char *value = info->argv[i].value;

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
		error(G_("HDN page-table analysis requires report, source-root and profile"));
		return 1;
	}
	report_fd = open(report, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) {
		error(G_("cannot open HDN page-table report: %s"), xstrerror(errno));
		return 1;
	}
	PASS_INFO(hdn_pgtable, "ssa", 1, PASS_POS_INSERT_AFTER);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
			  &hdn_pgtable_pass_info);
	register_callback(info->base_name, PLUGIN_FINISH, finish, NULL);
	return 0;
}
