// SPDX-License-Identifier: GPL-2.0-only
/* Compile separately from cross_use: its extern declarations carry no section. */
#ifdef HDN_LIFETIME_RESIDENT_CONTROL
#define BOOT
#else
#define BOOT __attribute__((section(".init.data")))
#endif

int hdn_lifetime_shared BOOT;

#ifndef HDN_LIFETIME_RESIDENT_CONTROL
__attribute__((section(".init.text"), noinline))
#endif
int hdn_lifetime_shared_call(int value)
{
	return hdn_lifetime_shared + value;
}
