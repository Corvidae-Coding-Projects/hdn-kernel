// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HDN_ELF_NOTE_NAME "HDN"
#define HDN_ELF_NOTE_NAME_SIZE 4
#define HDN_ELF_NOTE_MEMORY_TYPE 0x48444e01
#define HDN_ELF_NOTE_MEMORY_ABI_VERSION 1
#define HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE (1ULL << 4)
#define HDN_MEM_ALLOW_EXEC_STACK_ELF (1ULL << 5)
#define HDN_MEM_ALLOW_TEXTREL_MPROTECT (1ULL << 6)
#define HDN_EXEC_STACK_ELF "/hdn-elfnote-exec-stack-fixture"
#define HDN_TEXTREL_ELF "/hdn-elfnote-textrel-fixture"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct hdn_elf_memory_note {
	uint32_t abi_version;
	uint32_t reserved;
	uint64_t memory_flags;
};

struct hdn_note_payload {
	Elf64_Nhdr nhdr;
	char name[HDN_ELF_NOTE_NAME_SIZE];
	struct hdn_elf_memory_note desc;
};

__attribute__((section(".note.hdn"), aligned(4), used))
static const struct hdn_note_payload hdn_memory_note = {
	.nhdr = {
		.n_namesz = HDN_ELF_NOTE_NAME_SIZE,
		.n_descsz = sizeof(struct hdn_elf_memory_note),
		.n_type = HDN_ELF_NOTE_MEMORY_TYPE,
	},
	.name = HDN_ELF_NOTE_NAME,
	.desc = {
		.abi_version = HDN_ELF_NOTE_MEMORY_ABI_VERSION,
		.memory_flags = HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE |
				HDN_MEM_ALLOW_EXEC_STACK_ELF |
				HDN_MEM_ALLOW_TEXTREL_MPROTECT,
	},
};

static int write_all_fd(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t written = write(fd, p, len);

		if (written < 0)
			return -errno;
		if (!written)
			return -EIO;
		p += written;
		len -= written;
	}

	return 0;
}

static bool mapping_has_exec(void *addr)
{
	unsigned long target = (unsigned long)addr;
	unsigned long start;
	unsigned long end;
	char perms[5];
	char line[512];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps)
		return false;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
			continue;
		if (target < start || target >= end)
			continue;

		fclose(maps);
		return strchr(perms, 'x');
	}

	fclose(maps);
	return false;
}

static int write_exec_stack_elf_fixture(const char *path)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdr = {};
	int fd;
	int ret;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdr);
	ehdr.e_phnum = 1;

	phdr.p_type = PT_GNU_STACK;
	phdr.p_flags = PF_R | PF_W | PF_X;
	phdr.p_align = 16;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (fd < 0)
		return -errno;

	ret = write_all_fd(fd, &ehdr, sizeof(ehdr));
	if (!ret)
		ret = write_all_fd(fd, &phdr, sizeof(phdr));
	if (!ret && ftruncate(fd, 4096))
		ret = -errno;

	close(fd);
	if (ret)
		unlink(path);
	return ret;
}

static int write_textrel_elf_fixture(const char *path)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdrs[2] = {};
	Elf64_Dyn dyns[2] = {};
	int fd;
	int ret;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdrs[0]);
	ehdr.e_phnum = ARRAY_SIZE(phdrs);

	phdrs[0].p_type = PT_LOAD;
	phdrs[0].p_offset = 0;
	phdrs[0].p_vaddr = 0;
	phdrs[0].p_paddr = 0;
	phdrs[0].p_filesz = 4096;
	phdrs[0].p_memsz = 4096;
	phdrs[0].p_flags = PF_R | PF_X;
	phdrs[0].p_align = 4096;

	phdrs[1].p_type = PT_DYNAMIC;
	phdrs[1].p_offset = 0x200;
	phdrs[1].p_vaddr = 0x200;
	phdrs[1].p_paddr = 0x200;
	phdrs[1].p_filesz = sizeof(dyns);
	phdrs[1].p_memsz = sizeof(dyns);
	phdrs[1].p_flags = PF_R;
	phdrs[1].p_align = 8;

	dyns[0].d_tag = DT_TEXTREL;
	dyns[1].d_tag = DT_NULL;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (fd < 0)
		return -errno;

	ret = write_all_fd(fd, &ehdr, sizeof(ehdr));
	if (!ret)
		ret = write_all_fd(fd, phdrs, sizeof(phdrs));
	if (!ret && lseek(fd, phdrs[1].p_offset, SEEK_SET) < 0)
		ret = -errno;
	if (!ret)
		ret = write_all_fd(fd, dyns, sizeof(dyns));
	if (!ret && ftruncate(fd, 4096))
		ret = -errno;

	close(fd);
	if (ret)
		unlink(path);
	return ret;
}

static int jit_exec_after_write_allowed(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int ret;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return 2;

	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (!ret && !mapping_has_exec(addr))
		ret = -1;
	munmap(addr, page_size);

	return ret ? 1 : 0;
}

static int exec_stack_elf_mapping_allowed(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	void *addr;
	int fd;
	int ret;

	ret = write_exec_stack_elf_fixture(HDN_EXEC_STACK_ELF);
	if (ret)
		return 2;

	fd = open(HDN_EXEC_STACK_ELF, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_EXEC_STACK_ELF);
		return 2;
	}

	errno = 0;
	addr = mmap(NULL, page_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	else
		munmap(addr, page_size);
	close(fd);
	unlink(HDN_EXEC_STACK_ELF);

	if (addr != MAP_FAILED)
		return 0;
	return saved_errno == EACCES || saved_errno == EPERM ? 1 : 2;
}

static int textrel_mprotect_allowed(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	int saved_exec_errno = 0;
	void *addr;
	int fd;
	int ret;
	int ret_exec = 0;

	ret = write_textrel_elf_fixture(HDN_TEXTREL_ELF);
	if (ret)
		return 2;

	fd = open(HDN_TEXTREL_ELF, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_TEXTREL_ELF);
		return 2;
	}

	addr = mmap(NULL, page_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		unlink(HDN_TEXTREL_ELF);
		return 2;
	}

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_WRITE);
	if (ret)
		saved_errno = errno;
	if (!ret) {
		errno = 0;
		ret_exec = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
		if (ret_exec)
			saved_exec_errno = errno;
	}

	munmap(addr, page_size);
	close(fd);
	unlink(HDN_TEXTREL_ELF);

	if (ret)
		return saved_errno == EACCES || saved_errno == EPERM ? 1 : 2;
	if (ret_exec)
		return saved_exec_errno == EACCES || saved_exec_errno == EPERM ?
		       1 : 2;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 1 || !strcmp(argv[1], "jit"))
		return jit_exec_after_write_allowed();
	if (!strcmp(argv[1], "exec-stack"))
		return exec_stack_elf_mapping_allowed();
	if (!strcmp(argv[1], "textrel"))
		return textrel_mprotect_allowed();

	return 2;
}
