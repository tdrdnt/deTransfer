// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED)
	{
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_contents;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
	{
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
	{
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}
	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff);

	for (int i = 0; i < ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			size_t page_size = sysconf(_SC_PAGESIZE);
			int seg_start = phdr[i].p_vaddr & ~(page_size - 1);
			int seg_end = ((phdr[i].p_vaddr + phdr[i].p_memsz + page_size - 1) & ~(page_size - 1));
			int seg_size = seg_end - seg_start;

			// void *mapped_segment = mmap((void *)seg_start, seg_size, prot,
			//     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

			void *mapped_segment = mmap((void *)seg_start, seg_size, PROT_READ | PROT_WRITE | PROT_EXEC,
										MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			if (mapped_segment == MAP_FAILED)
			{
				perror("mmap");
				exit(2);
			}

			memcpy((void *)phdr[i].p_vaddr, (char *)elf_contents + phdr[i].p_offset, phdr[i].p_filesz);
			if (phdr[i].p_memsz > phdr[i].p_filesz)
			{
				memset((void *)(phdr[i].p_vaddr + phdr[i].p_filesz), 0, phdr[i].p_memsz - phdr[i].p_filesz);
			}

			int prot = 0;
			if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
			if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
			if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;

			if (mprotect((void *)seg_start, seg_size, prot) < 0)
			{
				perror("mprotect");
				exit(2);
			}
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */

	
	void *sp = malloc(8 * 1024 * 1024); // Allocate 8MB for stack

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	void (*entry)() = (void (*)())ehdr->e_entry;

	// Transfer control
	__asm__ __volatile__(
		"mov %0, %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"jmp *%1\n"
		:
		: "r"(sp), "r"(entry)
		: "memory");
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
