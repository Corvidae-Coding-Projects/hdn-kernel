// SPDX-License-Identifier: GPL-2.0-only
#include "hdn_alloc_fixture.h"
void *hdn_alloc_fixture_b(unsigned long size)
{
	return __hdn_alloc_marker(size, 0, -1, 0, (hdn_alloc_fixture_alias *)0);
}
#ifdef HDN_ALLOC_INCOMPLETE
struct hdn_alloc_incomplete;
void *hdn_alloc_fixture_incomplete(unsigned long size)
{
	return __hdn_alloc_marker(size, 0, -1, 0, (struct hdn_alloc_incomplete *)0);
}
#endif
