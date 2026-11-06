// SPDX-License-Identifier: GPL-2.0-only
/* Compiler-only corpus. The functions are never executed. */
typedef __SIZE_TYPE__ size_t;
extern void *allocate(size_t) __attribute__((alloc_size(1)));
extern void *memcpy(void *, const void *, size_t);

void *unchecked_product(size_t count, size_t width)
{
	return allocate(count * width);
}

void *unchecked_sum_product(size_t count, size_t width)
{
	return allocate((count + 1) * width);
}

void *checked_product(size_t count, size_t width)
{
	size_t bytes;

	if (__builtin_mul_overflow(count, width, &bytes))
		return (void *)0;
	return allocate(bytes);
}

void unchecked_copy(void *dst, const void *src, size_t count, size_t width)
{
	memcpy(dst, src, count * width);
}

__attribute__((hdn_size_wrap("hardening-selftests", "unsigned sequence arithmetic; never a size", "any use as allocation or copy extent")))
unsigned int intentional_sequence_wrap(unsigned int sequence, unsigned int delta)
{
	return sequence + delta;
}

void *bad_wrapped_size(unsigned int sequence, unsigned int delta)
{
	return allocate(intentional_sequence_wrap(sequence, delta));
}

void *narrowed_product(size_t count, size_t width)
{
	unsigned int bytes = count * width;

	return allocate(bytes);
}
