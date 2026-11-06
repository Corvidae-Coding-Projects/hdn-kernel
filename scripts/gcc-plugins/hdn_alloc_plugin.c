// SPDX-License-Identifier: GPL-2.0-only
#include "gcc-common.h"
#undef gimple
#include <string>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include "../../include/linux/hdn_alloc_domains.h"

__visible int plugin_is_GPL_compatible;
static const char *source_root, *profile;
static int report_fd = -1;
static unsigned long records;
static bool module_unit;
static unsigned int metadata_records;

static void module_record(unsigned long long identity)
{
	if (!module_unit)
		return;
	char name[64];
	snprintf(name, sizeof(name), "__hdn_alloc_record_%u", metadata_records++);
	tree type = build_array_type_nelts(long_long_unsigned_type_node, 3);
	tree decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier(name), type);
	vec<constructor_elt, va_gc> *values = NULL;
	CONSTRUCTOR_APPEND_ELT(values, size_int(0), build_int_cstu(long_long_unsigned_type_node, identity));
	CONSTRUCTOR_APPEND_ELT(values, size_int(1), build_int_cstu(long_long_unsigned_type_node, HDN_ALLOC_MODULE));
	CONSTRUCTOR_APPEND_ELT(values, size_int(2), build_int_cstu(long_long_unsigned_type_node, 1));
	DECL_INITIAL(decl) = build_constructor(type, values);
	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 1;
	TREE_USED(decl) = 1;
	DECL_PRESERVE_P(decl) = 1;
	DECL_ARTIFICIAL(decl) = 1;
	SET_DECL_ALIGN(decl, 64);
	DECL_USER_ALIGN(decl) = 1;
	set_decl_section_name(decl, ".hdn.alloc");
	varpool_add_new_variable(decl);
}

static void start_unit(void *, void *)
{
	/* Even a unit without typed sites declares the metadata ABI. */
	module_record(0);
}

static const char *decl_name(tree decl)
{
	return decl && DECL_NAME(decl) ? IDENTIFIER_POINTER(DECL_NAME(decl)) : "<anonymous>";
}

static const char *relative_path(const char *path)
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

static const char *type_name(tree type)
{
	tree name = TYPE_NAME(TYPE_MAIN_VARIANT(type));
	if (!name)
		return "<anonymous>";
	return TREE_CODE(name) == IDENTIFIER_NODE ? IDENTIFIER_POINTER(name) : decl_name(name);
}

static void nominal(std::string &out, tree type)
{
	out += type_name(type);
	tree stub = TYPE_STUB_DECL(type);
	if (stub && DECL_SOURCE_LOCATION(stub) != UNKNOWN_LOCATION) {
		expanded_location loc = expand_location(DECL_SOURCE_LOCATION(stub));
		out += '@';
		out += relative_path(loc.file);
		out += ':' + std::to_string(loc.line);
	}
}

/* Nominal pointer targets do not recursively expand the entire kernel graph.
 * By-value layout, field types, signedness, qualifiers and bounds are complete.
 * Typedef aliases normalize to the same main variant. No runtime address enters
 * the identity. A nonconstant or oversized by-value graph fails compilation.
 */
static bool describe(std::string &out, tree type, unsigned int depth = 0)
{
	if (!type || depth > 64 || out.size() > 262144)
		return false;
	out += '(' + std::to_string(TREE_CODE(type)) + ',' + std::to_string(TYPE_QUALS(type));
	type = TYPE_MAIN_VARIANT(type);
	out += ',' + std::to_string(TYPE_ALIGN(type)) + ',';
	tree size = TYPE_SIZE(type);
	if (size && tree_fits_uhwi_p(size))
		out += std::to_string(tree_to_uhwi(size));
	else if (size)
		return false;
	else
		out += "incomplete";
	switch (TREE_CODE(type)) {
	case RECORD_TYPE:
	case UNION_TYPE:
		nominal(out, type);
		for (tree field = TYPE_FIELDS(type); field; field = DECL_CHAIN(field)) {
			if (TREE_CODE(field) != FIELD_DECL)
				continue;
			out += '[';
			out += decl_name(field);
			if (!DECL_FIELD_OFFSET(field) || !tree_fits_uhwi_p(DECL_FIELD_OFFSET(field)) ||
			    !DECL_FIELD_BIT_OFFSET(field) || !tree_fits_uhwi_p(DECL_FIELD_BIT_OFFSET(field)))
				return false;
			out += ':' + std::to_string(tree_to_uhwi(DECL_FIELD_OFFSET(field)));
			out += ':' + std::to_string(tree_to_uhwi(DECL_FIELD_BIT_OFFSET(field)));
			if (DECL_SIZE(field) && tree_fits_uhwi_p(DECL_SIZE(field)))
				out += ':' + std::to_string(tree_to_uhwi(DECL_SIZE(field)));
			if (!describe(out, TREE_TYPE(field), depth + 1))
				return false;
			out += ']';
		}
		break;
	case POINTER_TYPE:
	case REFERENCE_TYPE: {
		tree target = TREE_TYPE(type);
		out += '*' + std::to_string(TYPE_QUALS(target));
		target = TYPE_MAIN_VARIANT(target);
		if (TREE_CODE(target) == RECORD_TYPE || TREE_CODE(target) == UNION_TYPE)
			nominal(out, target);
		else if (!describe(out, target, depth + 1))
			return false;
		break;
	}
	case ARRAY_TYPE:
		if (!describe(out, TREE_TYPE(type), depth + 1))
			return false;
		break;
	case FUNCTION_TYPE:
		if (!describe(out, TREE_TYPE(type), depth + 1))
			return false;
		for (tree arg = TYPE_ARG_TYPES(type); arg; arg = TREE_CHAIN(arg))
			if (!describe(out, TREE_VALUE(arg), depth + 1))
				return false;
		out += TYPE_ARG_TYPES(type) ? ";prototype" : ";unprototyped";
		break;
	case INTEGER_TYPE:
	case ENUMERAL_TYPE:
	case BOOLEAN_TYPE:
		out += TYPE_UNSIGNED(type) ? 'u' : 's';
		out += std::to_string(TYPE_PRECISION(type));
		if (TREE_CODE(type) == ENUMERAL_TYPE)
			nominal(out, type);
		break;
	case REAL_TYPE:
	case COMPLEX_TYPE:
	case VECTOR_TYPE:
		out += std::to_string(TYPE_PRECISION(type));
		if (TREE_CODE(type) != REAL_TYPE && !describe(out, TREE_TYPE(type), depth + 1))
			return false;
		break;
	case VOID_TYPE:
		break;
	default:
		return false;
	}
	out += ')';
	return true;
}

static unsigned int domain_for(tree type)
{
	tree stub;
	expanded_location location;
	const char *definition;

	if (TREE_CODE(type) != RECORD_TYPE)
		return HDN_ALLOC_ORDINARY;
	stub = TYPE_STUB_DECL(type);
	if (!stub || DECL_SOURCE_LOCATION(stub) == UNKNOWN_LOCATION)
		return HDN_ALLOC_ORDINARY;
	location = expand_location(DECL_SOURCE_LOCATION(stub));
	definition = relative_path(location.file);
#define HDN_MATCH_DOMAIN(name, domain, source) \
	if (!strcmp(type_name(type), #name) && !strcmp(definition, source)) \
		return HDN_ALLOC_##domain;
	HDN_ALLOC_TYPE_DOMAINS(HDN_MATCH_DOMAIN)
#undef HDN_MATCH_DOMAIN
	return HDN_ALLOC_ORDINARY;
}

static void quoted(FILE *out, const char *value)
{
	fputc('"', out);
	for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(out, "\\%c", *p);
		else if (*p < 32)
			fprintf(out, "\\u%04x", *p);
		else
			fputc(*p, out);
	}
	fputc('"', out);
}

static void emit(const char *kind, location_t loc, const char *callee,
		 const std::string &canonical, unsigned long long identity, unsigned int domain)
{
	char *buffer = NULL;
	size_t size = 0, done = 0;
	expanded_location place = expand_location(loc);
	FILE *out = open_memstream(&buffer, &size);
	if (!out) {
		error(G_("cannot allocate HDN allocation report"));
		return;
	}
	fputs("{\"schema_version\":1,\"kind\":", out); quoted(out, kind);
	fputs(",\"unit\":", out); quoted(out, relative_path(main_input_filename));
	fputs(",\"profile\":", out); quoted(out, profile);
	fputs(",\"file\":", out); quoted(out, relative_path(place.file));
	fprintf(out, ",\"line\":%d,\"column\":%d,\"function\":", place.line, place.column);
	quoted(out, current_function_decl ? decl_name(current_function_decl) : "<unit>");
	fputs(",\"callee\":", out); quoted(out, callee);
	fprintf(out, ",\"identity\":\"%016llx\",\"domain\":%u,\"canonical\":", identity, domain);
	quoted(out, canonical.c_str());
	fprintf(out, ",\"records\":%lu,\"errors\":%d}\n", records, errorcount);
	fclose(out);
	while (flock(report_fd, LOCK_EX)) {
		if (errno == EINTR)
			continue;
		error(G_("cannot lock HDN allocation report"));
		free(buffer);
		return;
	}
	while (done < size) {
		ssize_t n = write(report_fd, buffer + done, size - done);
		if (n > 0)
			done += n;
		else if (n < 0 && errno == EINTR)
			continue;
		else {
			error(G_("cannot write HDN allocation report"));
			break;
		}
	}
	if (flock(report_fd, LOCK_UN))
		error(G_("cannot unlock HDN allocation report"));
	free(buffer);
	records++;
}

static bool allocation_callee(const char *callee)
{
	return strstr(callee, "kmalloc") || strstr(callee, "kvmalloc") ||
	       strstr(callee, "krealloc") || strstr(callee, "kvrealloc") ||
	       strstr(callee, "kmem_cache_alloc") ||
	       strstr(callee, "kmem_buckets_alloc");
}

static unsigned int hdn_alloc_execute(void)
{
	basic_block block;
	FOR_EACH_BB_FN(block, cfun) {
		for (gimple_stmt_iterator gsi = gsi_start_bb(block); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple *stmt = gsi_stmt(gsi);
			if (!is_gimple_call(stmt) || !gimple_call_fndecl(stmt))
				continue;
			const char *callee = decl_name(gimple_call_fndecl(stmt));
			if (!strcmp(callee, "__hdn_alloc_typed") &&
			    strcmp(relative_path(main_input_filename), "security/hardening/autoslab_test.c")) {
				error_at(gimple_location(stmt), G_("HDN allocation runtime entry requires compiler metadata"));
				continue;
			}
			if (strcmp(callee, "__hdn_alloc_marker")) {
				if (allocation_callee(callee))
					emit("unclassified-allocation", gimple_location(stmt), callee, "", 0, 0);
				continue;
			}
			if (gimple_call_num_args(stmt) != 5 ||
			    TREE_CODE(TREE_TYPE(gimple_call_arg(stmt, 4))) != POINTER_TYPE) {
				error_at(gimple_location(stmt), G_("invalid HDN typed allocation marker"));
				continue;
			}
			tree type = TREE_TYPE(TREE_TYPE(gimple_call_arg(stmt, 4)));
			std::string canonical = "hdn-allocation-type-v1:";
			if (!COMPLETE_TYPE_P(type) || !describe(canonical, type)) {
				error_at(gimple_location(stmt), G_("HDN allocation type is incomplete or not representable"));
				continue;
			}
			/* Identity is a deterministic tier selector, never an authorization secret.
			 * The report retains the full canonical type for collision checking. */
			unsigned long long identity = 14695981039346656037ULL;
			for (unsigned char byte : canonical)
				identity = (identity ^ byte) * 1099511628211ULL;
			if (!identity)
				identity = 1;
			unsigned int domain = module_unit ? HDN_ALLOC_MODULE : domain_for(TYPE_MAIN_VARIANT(type));
			module_record(identity);
			tree fn_type = build_function_type_list(ptr_type_node, size_type_node,
				unsigned_type_node, integer_type_node, unsigned_type_node,
				long_long_unsigned_type_node, unsigned_type_node, NULL_TREE);
			tree fn = build_fn_decl("__hdn_alloc_typed", fn_type);
			TREE_PUBLIC(fn) = 1;
			DECL_EXTERNAL(fn) = 1;
			gcall *replacement = gimple_build_call(fn, 6,
				gimple_call_arg(stmt, 0), gimple_call_arg(stmt, 1),
				gimple_call_arg(stmt, 2), gimple_call_arg(stmt, 3),
				build_int_cstu(long_long_unsigned_type_node, identity),
				build_int_cstu(unsigned_type_node, domain));
			gimple_call_set_lhs(replacement, gimple_call_lhs(stmt));
			gimple_set_location(replacement, gimple_location(stmt));
			emit("typed-allocation", gimple_location(stmt), callee, canonical, identity, domain);
			gsi_replace(&gsi, replacement, true);
		}
	}
	return TODO_update_ssa;
}

#define PASS_NAME hdn_alloc
#define PROPERTIES_REQUIRED PROP_ssa
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

static void finish(void *, void *)
{
	emit("unit", UNKNOWN_LOCATION, "", "", 0, 0);
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
		if (!strcmp(key, "report")) report = value;
		else if (!strcmp(key, "source-root")) source_root = value;
		else if (!strcmp(key, "profile")) profile = value;
		else if (!strcmp(key, "module") && !strcmp(value, "1")) module_unit = true;
		else return 1;
	}
	if (!report || !source_root || !profile)
		return 1;
	report_fd = open(report, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (report_fd < 0)
		return 1;
	PASS_INFO(hdn_alloc, "ssa", 1, PASS_POS_INSERT_AFTER);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_alloc_pass_info);
	register_callback(info->base_name, PLUGIN_FINISH, finish, NULL);
	register_callback(info->base_name, PLUGIN_START_UNIT, start_unit, NULL);
	return 0;
}
