#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/elf.h>

int find_hook_target(const char *libcxx, uint64_t *hook_target, uint64_t *payload_target, uint32_t* first_instruction) {
	Elf64_Ehdr hdr;

	*hook_target = 0;
	*payload_target = 0;

	int fd = open(libcxx, O_RDONLY);
	if(fd < 0){
		perror("open libc++.so");
		return 1;
	}
	if(read(fd, (char *)&hdr, sizeof(hdr)) < sizeof(hdr)){
		perror("read libc++.so");
		close(fd);
		return 1;
	}
	if(strncmp((char *)hdr.e_ident, "\x7f""ELF", 4) != 0){
		fprintf(stderr, "Invalid elf file: %s\n", libcxx);
		close(fd);
		return 1;
	}
	//printf("libc++.so Program header: %x %x %x\n", hdr.e_phoff, hdr.e_phnum, hdr.e_phentsize);
	if(lseek64(fd, hdr.e_phoff, SEEK_SET) < 0){
		perror("lseek64 e_phoff");
		close(fd);
		return 1;
	}
	if(hdr.e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stderr, "Invalid program header size: %d\n", hdr.e_phentsize);
		close(fd);
		return 1;
	}
	for(int i = 0; i < hdr.e_phnum; i++){
		Elf64_Phdr phdr;
		if(read(fd, (char *)&phdr, sizeof(phdr)) < 0){
			perror("read phdr");
			close(fd);
			return 1;
		}

		if(phdr.p_type == PT_LOAD){
			if(phdr.p_flags & PF_X){
				*payload_target = phdr.p_offset + phdr.p_filesz;
			}
		}
	}
	if(lseek64(fd, hdr.e_shoff + hdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) < 0){
		perror("lseek64 shdr");
		close(fd);
		return 1;
	}
	Elf64_Shdr str_shdr;
	if(read(fd, (char *)&str_shdr, sizeof(str_shdr)) < 0){
		perror("read shdr");
		close(fd);
		return 1;
	}
	uint64_t dynstr = 0;
	uint64_t dynsym_offset = 0;
	uint64_t dynsym_size = 0;
	for(int i = 0; i < hdr.e_shnum; i++){
		Elf64_Shdr shdr;
		if(lseek64(fd, hdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0){
			perror("lseek64 shdr");
			close(fd);
			return 1;
		}
		if(read(fd, (char *)&shdr, sizeof(shdr)) < 0){
			perror("read shdr");
			close(fd);
			return 1;
		}
		if(lseek64(fd, shdr.sh_name + str_shdr.sh_offset, SEEK_SET) < 0){
			perror("lseek64 e_phoff");
			close(fd);
			return 1;
		}
		char name[100];
		if(read(fd, name, sizeof(name) - 1) < 0){
			perror("read sh_name");
			close(fd);
			return 1;
		}
		name[sizeof(name) - 1] = 0;
		if(strcmp(name, ".dynstr") == 0){
			dynstr = shdr.sh_offset;
		}
		if(strcmp(name, ".dynsym") == 0){
			dynsym_offset = shdr.sh_offset;
			dynsym_size = shdr.sh_size;
		}
		//printf("Section[%d] = %s\n", i, name);
	}

	if(dynstr == 0 || dynsym_offset == 0){
		fprintf(stderr, ".dynstr or .dynsym not found\n");
		close(fd);
		return 1;
	}
	for(int i = 0; i < dynsym_size / sizeof(Elf64_Sym); i++){
		Elf64_Sym sym;
		if(lseek64(fd, dynsym_offset + i * sizeof(Elf64_Sym), SEEK_SET) < 0){
			perror("lseek64 dynsym");
			close(fd);
			return 1;
		}
		if(read(fd, (char *)&sym, sizeof(sym)) < 0){
			perror("read dynsym");
			close(fd);
			return 1;
		}
		if(lseek64(fd, dynstr + sym.st_name, SEEK_SET) < 0){
			perror("lseek64 st_name");
			close(fd);
			return 1;
		}
		char name[200];
		if(read(fd, name, sizeof(name) - 1) < 0){
			perror("read st_name");
			close(fd);
			return 1;
		}
		name[sizeof(name) - 1] = 0;
		if(strcmp(name, "_ZNSt3__115basic_streambufIcNS_11char_traitsIcEEEC2Ev") == 0){
			*hook_target = sym.st_value;
		}
		//printf("Dymsym[%d] = %s\n", i, name);
	}
	if(*hook_target == 0){
		fprintf(stderr, "Could not find symbol name for hook target.\n");
		close(fd);
		return 1;
	}
	// Extract first instruction
	if(lseek64(fd, *hook_target, SEEK_SET) < 0){
		perror("lseek64 hook_target");
		close(fd);
		return 1;
	}
	if(read(fd, first_instruction, sizeof(*first_instruction)) < 0){
		perror("read first instruction");
		close(fd);
		return 1;
	}
	if(*first_instruction == 0xd503233fU){
		// Hook next instruction if PACIASP is detected.
		printf("d503233f PACIASP was found. Offset hook address by +4.\n");
		*hook_target += 4UL;

		if(read(fd, first_instruction, sizeof(*first_instruction)) < 0){
			perror("read first instruction");
			close(fd);
			return 1;
		}
	}

	close(fd);
	return 0;
}
