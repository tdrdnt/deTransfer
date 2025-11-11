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

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 || ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3)
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
	 * TODO: Load PT_LOAD Segs
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD Seg:
	 * - Map the Segs in memory. Permissions can be RWX for now.
	 */

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD Seg:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff);

	// iterez prin fiecare program header
	for (int i = 0; i < ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			// obtin marimea unei pagini in sistem
			int pagesize = sysconf(_SC_PAGESIZE);

			// aliniez memoria la dimensiunile paginii pentru a putea mapa
			// start are padding in jos si final are padding in sus
			int startAlin = phdr[i].p_vaddr & ~(pagesize - 1);
			int finalAlin = (phdr[i].p_vaddr + phdr[i].p_memsz + pagesize - 1) & ~(pagesize - 1);
			int lungSegAlin = finalAlin - startAlin;

			// mapez memoria necesara si verific daca da eroare
			void *mapOK = mmap((void *)startAlin, lungSegAlin, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			if (mapOK == MAP_FAILED)
			{
				perror("mmap");
				exit(2);
			}

			// copiez datele din program headerul curent la adresa ceruta
			// si completez cu 0-uri daca mai ramane spatiu
			memcpy((void *)phdr[i].p_vaddr, (char *)elf_contents + phdr[i].p_offset, phdr[i].p_filesz);
			if (phdr[i].p_memsz > phdr[i].p_filesz)
				memset((void *)phdr[i].p_vaddr + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

			// dupa ce am mutat datele le setez permisiunile
			int permisiuni = 0;
			if (phdr[i].p_flags & PF_R)
				permisiuni = permisiuni | PROT_READ;
			if (phdr[i].p_flags & PF_W)
				permisiuni = permisiuni | PROT_WRITE;
			if (phdr[i].p_flags & PF_X)
				permisiuni = permisiuni | PROT_EXEC;

			// setez permisiunile cu mprotect si verific daca da eroare
			int protOK = mprotect((void *)startAlin, lungSegAlin, permisiuni);
			if (protOK < 0)
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

	// aloc 8MB de memorie pentru stiva si verific daca da eroare
	int lungStiva = 8 * 1024 * 1024;
	uint8_t *stiva = mmap(NULL, lungStiva, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stiva == MAP_FAILED)
	{
		perror("mmap stiva");
		exit(1);
	}
	// mut pointerul in varful stivei si o construiesc de sus in jos
	uint8_t *varfStiva = stiva + lungStiva;
	uint8_t *sp = varfStiva;

	// numar variabilele de mediu
	int envc = 0;
	while (envp[envc])
		envc++;

	// aloc vectori de stringuri pentru argv si envp
	char **argvStiva = malloc((argc + 1) * sizeof(char *));
	char **envpStiva = malloc((envc + 1) * sizeof(char *));

	// copiez stringurile envp si pastrez referinte la ele in vector
	for (int i = envc - 1; i >= 0; i--)
	{
		int len = strlen(envp[i]) + 1;
		sp -= len;
		memcpy(sp, envp[i], len);
		envpStiva[i] = (char *)sp;
	}
	envpStiva[envc] = NULL;

	// copiez stringurile argv si pastrez referinte la ele in vector
	for (int i = argc - 1; i >= 0; i--)
	{
		int len = strlen(argv[i]) + 1;
		sp -= len;
		memcpy(sp, argv[i], len);
		argvStiva[i] = (char *)sp;
	}
	argvStiva[argc] = NULL;

	// construiesc cei 16 bytes pt AT_RANDOM
	sp -= 16;
	int *random = sp;
	for (int i = 0; i < 16; i++)
		random[i] = rand() & 0xff;

	// construiesc auxv folosind valori pe 64-bit
	Elf64_auxv_t auxv[8], *auxp = auxv;
	auxp->a_type = AT_PHDR;
	auxp->a_un.a_val = phdr;
	auxp++;
	auxp->a_type = AT_PHENT;
	auxp->a_un.a_val = sizeof(Elf64_Phdr);
	auxp++;
	auxp->a_type = AT_PHNUM;
	auxp->a_un.a_val = ehdr->e_phnum;
	auxp++;
	auxp->a_type = AT_PAGESZ;
	auxp->a_un.a_val = sysconf(_SC_PAGESIZE);
	auxp++;
	auxp->a_type = AT_ENTRY;
	auxp->a_un.a_val = ehdr->e_entry;
	auxp++;
	auxp->a_type = AT_RANDOM;
	auxp->a_un.a_val = random;
	auxp++;
	auxp->a_type = AT_NULL;
	auxp->a_un.a_val = 0;
	auxp++;

	// aliniez stiva la 16 bytes
	sp = (uint8_t *)((uintptr_t)sp & ~0xf);

	// copiez auxv, envp, argv si argc pe stiva
	sp -= sizeof(auxv);
	memcpy(sp, auxv, sizeof(auxv));
	Elf64_auxv_t *auxvStiva = (Elf64_auxv_t *)sp;

	sp -= sizeof(char *) * (envc + 1);
	memcpy(sp, envpStiva, sizeof(char *) * (envc + 1));
	char **envpEntry = (char **)sp;

	sp -= sizeof(char *) * (argc + 1);
	memcpy(sp, argvStiva, sizeof(char *) * (argc + 1));
	char **argvEntry = (char **)sp;

	sp -= sizeof(long);
	*(long *)sp = argc;
	sp = (uint8_t *)((uintptr_t)sp & ~0xf);

	// eliberez memoria pentru vectorii de stringuri
	free(argvStiva);
	free(envpStiva);
	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD Segs at a random load base.
	 * Adjust virtual addresses of Segs and entry point by load_base.
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
