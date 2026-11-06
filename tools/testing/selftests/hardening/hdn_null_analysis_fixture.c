// SPDX-License-Identifier: GPL-2.0-only

#include <stddef.h>

struct fixture_inner {
	int value;
};

struct fixture_outer {
	int prefix;
	struct fixture_inner inner;
	void (*callback)(void);
};

extern int *fixture_alloc(void);

#define fixture_container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

__attribute__((noinline, hdn_null_attacker_entry))
int fixture_direct(int *pointer)
{
	return *pointer;
}

__attribute__((noinline))
int __do_sys_fixture(int *pointer)
{
	return *pointer;
}

__attribute__((noinline, hdn_null_attacker_entry))
int fixture_repeated(int *pointer)
{
	int first = *(volatile int *)pointer;
	int second = *(volatile int *)pointer;

	return first + second;
}

__attribute__((noinline))
int fixture_nullable_return(void)
{
	return *fixture_alloc();
}

__attribute__((noinline))
int fixture_definite(void)
{
	return *(volatile int *)0;
}

__attribute__((noinline))
int fixture_conditional_zero(int enabled)
{
	if (!enabled)
		return 0;
	return *(volatile int *)0;
}

__attribute__((noinline, hdn_null_attacker_entry))
int fixture_field(struct fixture_outer *pointer)
{
	return pointer->prefix;
}

__attribute__((noinline, hdn_null_attacker_entry))
void fixture_indirect(struct fixture_outer *pointer)
{
	pointer->callback();
}

__attribute__((noinline, hdn_null_attacker_entry))
int fixture_container(struct fixture_inner *pointer)
{
	struct fixture_outer *outer =
		fixture_container_of(pointer, struct fixture_outer, inner);

	return outer->prefix;
}

__attribute__((noinline, hdn_null_probe("selftest", "remove with probe")))
int fixture_intentional_probe(int *pointer)
{
	return *pointer;
}

__attribute__((noinline))
int fixture_safe(int *pointer)
{
	if (!pointer)
		return 0;
	return *pointer;
}
