// SPDX-License-Identifier: GPL-2.0-only
/* Kbuild wrapper for the shared compiler/modpost lifetime fixture. */
#ifdef CONFIG_GCC_PLUGIN_HDN_LIFETIME_BAD_FIXTURE
#define HDN_LIFETIME_BAD
#endif
#include "../../tools/testing/selftests/hardening/hdn_lifetime_fixture.c"
