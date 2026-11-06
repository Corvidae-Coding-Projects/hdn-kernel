// SPDX-License-Identifier: GPL-2.0-only
extern int hdn_lifetime_shared;
extern int hdn_lifetime_shared_call(int value);

int (*hdn_lifetime_retained_callback)(int) = hdn_lifetime_shared_call;

int hdn_lifetime_cross_use(int value, const int *opaque)
{
	/* The ELF definition must identify the external init-only object and
	 * function. An unresolved load cannot disappear from source coverage. */
	return hdn_lifetime_shared_call(value) + hdn_lifetime_shared + *opaque;
}
