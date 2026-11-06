// SPDX-License-Identifier: GPL-2.0-only
/* Compiler corpus; machine-code checks and native leakage runs are separate. */
typedef unsigned long word;
unsigned char hdn_spec_table[256];
struct hdn_spec_input { word length; const unsigned char *bytes; };
extern word hdn_spec_external(word value);
extern word copy_from_user(void *to, const void *from, word size);
static const word hdn_spec_trusted_constant = 7;

__attribute__((noinline, noclone)) word hdn_spec_constant(void)
{
	return 42;
}

word hdn_spec_index(word index)
{
	if (index < sizeof(hdn_spec_table))
		return hdn_spec_table[index];
	return 0;
}

word hdn_spec_pointer(struct hdn_spec_input *input, word index)
{
	if (index < input->length)
		return input->bytes[index];
	return 0;
}

word hdn_spec_arithmetic(word index)
{
	index = index * 3 + 1;
	if (index < sizeof(hdn_spec_table))
		return hdn_spec_table[index];
	return 0;
}

word hdn_spec_structure(struct hdn_spec_input *input, word index)
{
	struct hdn_spec_input copy = *input;

	if (index < copy.length)
		return copy.bytes[index];
	return 0;
}

word hdn_spec_usercopy(void *destination, const void *source, word size)
{
	word remaining = copy_from_user(destination, source, size);

	return hdn_spec_table[remaining & 255];
}

word hdn_spec_trusted(void)
{
	return hdn_spec_trusted_constant;
}

word hdn_spec_alias(volatile word *address, word value, volatile word *alias)
{
	*address = value;
	return hdn_spec_table[*alias & 255];
}

word hdn_spec_phi(const unsigned char *a, const unsigned char *b, word choice, word index)
{
	const unsigned char *selected = choice ? a : b;
	if (index < 8)
		return selected[index];
	return 0;
}

word hdn_spec_loop(const word *values, word size)
{
	word sum = 0;
	for (word n = 0; n < size; n++)
		sum += values[n];
	return sum;
}

word hdn_spec_call(word (*target)(word), word value)
{
	return target(hdn_spec_external(value));
}

word hdn_spec_length(void *destination, const void *source, word length)
{
	extern void *memcpy(void *, const void *, word);

	memcpy(destination, source, length);
	return length;
}

__attribute__((hdn_spec_review("assembly", "HDN compiler fixture",
	"register-only identity, no branch, memory access or hidden target",
	"any change to the assembly or its operands")))
word hdn_spec_reviewed(word value)
{
	asm volatile("" : "+r" (value));
	return value;
}

word hdn_spec_inlined_review(word value)
{
	return hdn_spec_reviewed(value);
}
