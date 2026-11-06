// SPDX-License-Identifier: GPL-2.0-only
/* Must fail: a compiler cannot infer hidden speculative memory effects. */
unsigned long hdn_spec_opaque(unsigned long *value)
{
	unsigned long result;
	asm volatile("mov (%1),%0" : "=r" (result) : "r" (value));
	return result;
}
