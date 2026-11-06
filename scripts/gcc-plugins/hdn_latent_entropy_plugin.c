// SPDX-License-Identifier: GPL-2.0-only
/* Closed-site, defined-arithmetic control-flow diversity, with zero credit. */
#include "gcc-common.h"
#undef gimple

__visible int plugin_is_GPL_compatible;
static const char *source_root;
static bool test_sites;

struct hdn_latent_site {
	const char *file;
	const char *function;
	unsigned int id;
};

static const struct hdn_latent_site sites[] = {
	{ "drivers/char/random.c", "random_init", 0 },
	{ "kernel/fork.c", "copy_process", 1 },
	{ "drivers/char/random.c", "add_interrupt_randomness", 2 },
};

static int current_site(void)
{
	const char *file = DECL_SOURCE_FILE(current_function_decl);
	const char *name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));
	size_t n = strlen(source_root);

	if (!file)
		return -1;
	if (!strncmp(file, source_root, n) && file[n] == '/')
		file += n + 1;
	while (file[0] == '.' && file[1] == '/')
		file += 2;
	for (unsigned int i = 0; i < ARRAY_SIZE(sites); i++)
		if (!strcmp(file, sites[i].file) && !strcmp(name, sites[i].function))
			return sites[i].id;
	if (test_sites && !strcmp(file, "security/hardening/latent_entropy_test.c") &&
	    !strcmp(name, "hdn_latent_fixture"))
		return 3;
	return -1;
}

static bool hdn_latent_entropy_gate(void)
{
	return current_site() >= 0 && !TREE_THIS_VOLATILE(current_function_decl);
}

static unsigned int hdn_latent_entropy_execute(void)
{
	unsigned int site = current_site();
	tree state = create_tmp_var(long_unsigned_type_node, "hdn_latent_trace");
	tree type = build_function_type_list(void_type_node, long_unsigned_type_node,
					    unsigned_type_node, NULL_TREE);
	tree collector = build_fn_decl("hdn_latent_mix", type);
	unsigned HOST_WIDE_INT domain = 0x9e3779b97f4a7c15ULL ^ site;
	basic_block entry, bb;
	gimple_stmt_iterator it;

	/* Keep the binary site boundary auditable after interprocedural passes. */
	DECL_UNINLINABLE(current_function_decl) = 1;
	DECL_ATTRIBUTES(current_function_decl) = tree_cons(get_identifier("noclone"),
		NULL_TREE, DECL_ATTRIBUTES(current_function_decl));
	DECL_EXTERNAL(collector) = 1;
	TREE_PUBLIC(collector) = 1;
	TREE_NOTHROW(collector) = 1;
	/* A dedicated entry block prevents loop backedges from reinitializing. */
	entry = split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
	it = gsi_after_labels(entry);
	gsi_insert_before(&it, gimple_build_assign(state,
		build_int_cstu(long_unsigned_type_node, domain)), GSI_NEW_STMT);

	FOR_EACH_BB_FN(bb, cfun) {
		if (bb == entry)
			continue;
		it = gsi_after_labels(bb);
		/* No memory reads, divisions, shifts, or signed overflow. */
		tree salt = build_int_cstu(long_unsigned_type_node,
					 domain ^ ((unsigned HOST_WIDE_INT)bb->index * 0x100000001b3ULL));
		gsi_insert_before(&it, gimple_build_assign(state, PLUS_EXPR, state, salt), GSI_NEW_STMT);
		for (it = gsi_start_bb(bb); !gsi_end_p(it); gsi_next(&it)) {
			if (gimple_code(gsi_stmt(it)) == GIMPLE_RETURN) {
				gcall *call = gimple_build_call(collector, 2, state,
					build_int_cstu(unsigned_type_node, site));

				gimple_set_location(call, gimple_location(gsi_stmt(it)));
				gsi_insert_before(&it, call, GSI_SAME_STMT);
			}
		}
	}
	return 0;
}

#define PASS_NAME hdn_latent_entropy
#define PROPERTIES_REQUIRED PROP_cfg
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version)
{
	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}
	for (int i = 0; i < info->argc; i++) {
		if (!strcmp(info->argv[i].key, "source-root") && info->argv[i].value)
			source_root = info->argv[i].value;
		else if (!strcmp(info->argv[i].key, "test-sites") && !info->argv[i].value)
			test_sites = true;
		else {
			error(G_("unknown HDN latent-mixing option"));
			return 1;
		}
	}
	if (!source_root || !*source_root) {
		error(G_("HDN latent mixing requires source-root"));
		return 1;
	}
	PASS_INFO(hdn_latent_entropy, "cfg", 1, PASS_POS_INSERT_AFTER);
	register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &hdn_latent_entropy_pass_info);
	return 0;
}
