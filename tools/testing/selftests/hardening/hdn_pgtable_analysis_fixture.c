// SPDX-License-Identifier: GPL-2.0-only
/* Compiler-only negative fixture for the HDN page-table mutation producer. */
typedef struct { unsigned long pte; } pte_t;

extern void hdn_pt_store(unsigned long *, unsigned long, unsigned int);
extern void *memcpy(void *, const void *, __SIZE_TYPE__);

void hdn_pgtable_raw_store(pte_t *slot, pte_t value)
{
	*slot = value;
}

void hdn_pgtable_erased_store(pte_t *slot, unsigned long value)
{
	*(unsigned long *)slot = value;
}

void hdn_pgtable_approved_store(pte_t *slot, pte_t value)
{
	hdn_pt_store(&slot->pte, value.pte, 1);
}

void hdn_pgtable_bulk_store(pte_t *slot, const pte_t *value)
{
	memcpy(slot, value, sizeof(*slot));
}

void hdn_pgtable_indirect_call(pte_t *slot, void (*update)(pte_t *))
{
	update(slot);
}

void hdn_pgtable_inline_assembly(pte_t *slot)
{
	asm volatile("" : "+m" (*slot));
}
