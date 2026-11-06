/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HDN_ALLOC_FIXTURE_H
#define HDN_ALLOC_FIXTURE_H
struct hdn_alloc_fixture {
	unsigned int size;
	const char *name;
	int (*callback)(unsigned int, const char *);
	unsigned char bytes[];
};
typedef struct hdn_alloc_fixture hdn_alloc_fixture_alias;
void *__hdn_alloc_marker(__SIZE_TYPE__, unsigned int, int, unsigned int, ...);
#endif
