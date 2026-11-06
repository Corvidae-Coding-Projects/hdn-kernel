// SPDX-License-Identifier: GPL-2.0-only
#include "hdn_alloc_fixture.h"
void *hdn_alloc_fixture_a(unsigned long size)
{
	return __hdn_alloc_marker(size, 0, -1, 0, (struct hdn_alloc_fixture *)0);
}
struct hdn_alloc_incompatible {
	int size;
	char *name;
	int (*callback)(int, char *);
	unsigned char bytes[];
};
void *hdn_alloc_fixture_incompatible(unsigned long size)
{
	return __hdn_alloc_marker(size, 0, -1, 0, (struct hdn_alloc_incompatible *)0);
}
/* A protected tag name from an unauthoritative source must remain ordinary. */
struct msg_queue {
	unsigned long fake_payload;
};
void *hdn_alloc_fixture_spoof(unsigned long size)
{
	return __hdn_alloc_marker(size, 0, -1, 0, (struct msg_queue *)0);
}
