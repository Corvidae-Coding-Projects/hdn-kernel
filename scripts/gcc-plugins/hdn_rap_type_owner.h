/* SPDX-License-Identifier: GPL-2.0-only */
/* Stable declaration ownership. Numeric GCC location/DECL IDs are cache keys,
 * never part of the emitted identity. Macro spelling and every expansion site
 * distinguish separate declarations produced by nested macro invocations. */
#ifndef HDN_RAP_TYPE_OWNER_H
#define HDN_RAP_TYPE_OWNER_H

static std::map<std::string, std::string> owner_files;
static std::map<location_t, std::string> owner_locations;
static std::set<std::string> owned_type_names;

static std::string owner_filename(const char *name)
{
	if (!name || !*name)
		return {};
	auto found = owner_files.find(name);
	if (found != owner_files.end())
		return found->second;
	char *physical = realpath(name, NULL);
	if (!physical) {
		std::string rooted = std::string(source_root) + '/' + name;
		physical = realpath(rooted.c_str(), NULL);
	}
	if (!physical)
		return {};
	std::string path = physical;
	free(physical);
	char *root = realpath(source_root, NULL);
	if (!root)
		return {};
	std::string prefix = std::string(root) + '/';
	free(root);
	if (!path.compare(0, prefix.size(), prefix))
		path.erase(0, prefix.size());
	else {
		char *cwd = getcwd(NULL, 0);
		if (!cwd)
			return {};
		prefix = std::string(cwd) + '/';
		free(cwd);
		if (!path.compare(0, prefix.size(), prefix))
			path = "<generated>/" + path.substr(prefix.size());
	}
	for (unsigned char c : path)
		if (c < 32 || c == 127)
			return {};
	return owner_files.emplace(name, path).first->second;
}

static std::string location_owner(location_t original)
{
	original = LOCATION_LOCUS(original);
	auto found = owner_locations.find(original);
	if (found != owner_locations.end())
		return found->second;
	location_t loc = original;
	std::set<location_t> seen;
	std::string result;
	for (unsigned int depth = 0; depth != 64; depth++) {
		loc = LOCATION_LOCUS(loc);
		if (loc < RESERVED_LOCATION_COUNT || !seen.insert(loc).second)
			return {};
		const line_map *map = linemap_lookup(line_table, loc);
		const line_map_ordinary *spelling_map = NULL;
		location_t spelling = linemap_resolve_location(line_table, loc,
			LRK_SPELLING_LOCATION, &spelling_map);
		expanded_location point = linemap_expand_location(line_table,
			spelling_map, spelling);
		std::string file = owner_filename(point.file);
		if (file.empty() || point.line <= 0 || point.column <= 0)
			return {};
		if (!result.empty())
			result += "<expanded@";
		result += file + ':' + std::to_string(point.line) + ':' +
			std::to_string(point.column);
		if (!map || !linemap_macro_expansion_map_p(map))
			return owner_locations.emplace(original, result).first->second;
		loc = linemap_check_macro(map)->get_expansion_point_location();
	}
	return {};
}

static tree type_function_context(tree type)
{
	tree context = TYPE_CONTEXT(type);
	if (!context && TYPE_STUB_DECL(type))
		context = DECL_CONTEXT(TYPE_STUB_DECL(type));
	while (context && TREE_CODE(context) == BLOCK)
		context = BLOCK_SUPERCONTEXT(context);
	return context && TREE_CODE(context) == FUNCTION_DECL ? context : NULL_TREE;
}

static bool declaration_location_outside_unit(location_t location)
{
	if (location <= BUILTINS_LOCATION)
		return false;
	std::string owner = location_owner(location);
	std::string unit = owner_filename(main_input_filename);
	if (owner.empty() || unit.empty())
		return false;
	return owner.compare(0, unit.size() + 1, unit + ':') != 0;
}

static bool type_declaration_outside_unit(tree type)
{
	tree stub = TYPE_STUB_DECL(type);
	if (!stub && TYPE_NAME(type) && TREE_CODE(TYPE_NAME(type)) == TYPE_DECL)
		stub = TYPE_NAME(type);
	return stub && declaration_location_outside_unit(DECL_SOURCE_LOCATION(stub));
}

static bool type_has_aggregate_context(tree type)
{
	tree context = TYPE_CONTEXT(type);
	if (!context && TYPE_STUB_DECL(type))
		context = DECL_CONTEXT(TYPE_STUB_DECL(type));
	return context && (TREE_CODE(context) == RECORD_TYPE ||
		TREE_CODE(context) == UNION_TYPE || TREE_CODE(context) == ENUMERAL_TYPE);
}

static const char *owned_type_name(tree type, const char *name)
{
	tree stub = TYPE_STUB_DECL(type);
	if (!stub && TYPE_NAME(type) && TREE_CODE(TYPE_NAME(type)) == TYPE_DECL)
		stub = TYPE_NAME(type);
	std::string owner = stub ? location_owner(DECL_SOURCE_LOCATION(stub)) : "";
	if (owner.empty()) {
		tree type_name = TYPE_NAME(type);
		tree context = TYPE_CONTEXT(type);
		expanded_location place = stub ? expand_location(DECL_SOURCE_LOCATION(stub)) :
			expanded_location{NULL, 0, 0, NULL, false};
		const char *type_name_text = type_name && TREE_CODE(type_name) == IDENTIFIER_NODE ?
			IDENTIFIER_POINTER(type_name) :
			type_name && TREE_CODE(type_name) == TYPE_DECL ? decl_name(type_name) : "<none>";
		error(G_("HDN RAP cannot bind type ownership: code=%s name-code=%s name=%s stub=%s location=%s:%d:%d context=%s"),
			get_tree_code_name(TREE_CODE(type)),
			type_name ? get_tree_code_name(TREE_CODE(type_name)) : "<none>",
			type_name_text, stub ? "yes" : "no", place.file ? place.file : "<none>",
			place.line, place.column,
			context ? get_tree_code_name(TREE_CODE(context)) : "<none>");
		return NULL;
	}
	tree context = type_function_context(type);
	if (context) {
		std::string unit = owner_filename(main_input_filename);
		if (unit.empty()) {
			error(G_("HDN RAP cannot bind local type ownership to its translation unit"));
			return NULL;
		}
		owner += "#function=" + std::string(decl_name(context));
		owner += "#unit=" + unit;
	}
	return owned_type_names.insert(std::string(name ? name : "<anonymous>") +
		'@' + owner).first->c_str();
}
#endif
