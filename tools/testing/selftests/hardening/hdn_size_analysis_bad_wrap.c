// SPDX-License-Identifier: GPL-2.0-only
/* Signed arithmetic must not acquire an intentional-unsigned-wrap annotation. */
__attribute__((hdn_size_wrap("hardening-selftests", "invalid signed helper", "always invalid")))
int invalid_wrap(int value)
{
	return value + 1;
}
