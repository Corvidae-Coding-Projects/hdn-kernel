// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
	const unsigned char return_instruction = 0xc3;
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	void (*code)(void);
	void *mapping;

	mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return 2;

	memcpy(mapping, &return_instruction, sizeof(return_instruction));
	if (mprotect(mapping, page_size, PROT_READ | PROT_EXEC)) {
		munmap(mapping, page_size);
		return 1;
	}

	code = mapping;
	code();
	return munmap(mapping, page_size) ? 2 : 0;
}
