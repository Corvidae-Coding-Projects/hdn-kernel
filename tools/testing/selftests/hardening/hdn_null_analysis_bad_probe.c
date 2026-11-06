// SPDX-License-Identifier: GPL-2.0-only

__attribute__((hdn_null_probe("missing-invalidation")))
int fixture_bad_probe(int *pointer)
{
	return *pointer;
}
