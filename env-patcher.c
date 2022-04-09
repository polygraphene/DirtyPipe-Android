#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <linux/elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>

// Patching PATH for su in running process.
// Target: init, zygote, zygote64, adbd

#define LIB32 "/apex/com.android.runtime/lib/bionic/libc.so"
#define LIB64 "/apex/com.android.runtime/lib64/bionic/libc.so"
#define LIBINIT64 "/system/lib64/bootstrap/libc.so"

typedef uint64_t u64;
typedef uint32_t u32;

struct gnu_hash {
	u32 nbuckets;
	u32 symoffset;
	u32 bloom_size;
	u32 bloom_shift;
};

int readbuf(int fd, u64 addr, void *buf, int len){
	if(lseek64(fd, addr, SEEK_SET) < 0){
		return -1;
	}
	if(read(fd, buf, len) < len){
		return -1;
	}
	return 0;
}

int writebuf(int fd, u64 addr, void *buf, int len){
	if(lseek64(fd, addr, SEEK_SET) < 0){
		return -1;
	}
	if(write(fd, buf, len) < len){
		return -1;
	}
	return 0;
}

int get_environ_addr(int fd, bool is64, u64 base, u64 *addr){
	if(is64){
		Elf64_Ehdr hdr;
		if(readbuf(fd, base, &hdr, sizeof(hdr))){
			return -1;
		}

		u64 dyn_off = 0;
		u64 dyn_size = 0;
		for(int i = 0; i < hdr.e_phnum; i++){
			Elf64_Phdr phdr;
			if(readbuf(fd, base + hdr.e_phoff + sizeof(Elf64_Phdr) * i, &phdr, sizeof(phdr))){
				return -1;
			}

			if(phdr.p_type == PT_DYNAMIC){
				dyn_off = phdr.p_vaddr;
				dyn_size = phdr.p_memsz;
			}
		}

		u64 strtab = 0;
		u64 symtab = 0;
		u64 gnu_hash = 0;
		int dyn_count = dyn_size / sizeof(Elf64_Dyn);
		for(int i = 0; i < dyn_count; i++){
			Elf64_Dyn dyn;
			if(readbuf(fd, base + dyn_off + sizeof(Elf64_Dyn) * i, &dyn, sizeof(dyn))){
				return -1;
			}

			if(dyn.d_tag == DT_STRTAB){
				strtab = dyn.d_un.d_val;
			}
			if(dyn.d_tag == DT_SYMTAB){
				symtab = dyn.d_un.d_ptr;
			}
			if(dyn.d_tag == DT_GNU_HASH){
				gnu_hash = dyn.d_un.d_ptr;
			}
		}

		// Get symbol count from DT_GNU_HASH

		struct gnu_hash gnu_hash_obj;
		if(readbuf(fd, base + gnu_hash, &gnu_hash_obj, sizeof(gnu_hash_obj))){
			return -1;
		}
		u64 bucket_offset = base + gnu_hash + sizeof(gnu_hash_obj) + sizeof(u64) * gnu_hash_obj.bloom_size;
		u64 chain_offset = bucket_offset + sizeof(u32) * gnu_hash_obj.nbuckets;
		u32 last_bucket;
		if(readbuf(fd, bucket_offset + sizeof(u32) * (gnu_hash_obj.nbuckets - 1), &last_bucket, sizeof(last_bucket))){
			return -1;
		}
		//printf("nbu: %d symoffset: %d  %d,%d  last:%d\n", gnu_hash_obj.nbuckets, gnu_hash_obj.symoffset, gnu_hash_obj.bloom_size, gnu_hash_obj.bloom_shift, last_bucket);
		u64 symcount = 0;

		for(int i = 0;; i++){
			u32 last_sym = 0;
			if(readbuf(fd, chain_offset + sizeof(u32) * (last_bucket - gnu_hash_obj.symoffset + i), &last_sym, sizeof(last_sym))){
				return -1;
			}
			//printf("%d: %08x\n", i, last_sym);
			if(last_sym & 1){
				// last sym
				symcount = last_bucket + i + 1;
				break;
			}
		}

		// Linear search for dynamic symbols

		fprintf(stderr, "Symbol count: %lu\n", symcount);
		for(int i = 0; i < symcount; i++){
			Elf64_Sym sym;
			if(readbuf(fd, base + symtab + i * sizeof(Elf64_Sym), &sym, sizeof(sym))){
				return -1;
			}
			char name[100] = {};
			if(readbuf(fd, base + sym.st_name + strtab, name, sizeof(name) - 1)){
				return -1;
			}
			//printf("name[%d]: %s\n", i, name);
			if(strcmp(name, "environ") == 0){
				*addr = sym.st_value;
				return 0;
			}
		}
		fprintf(stderr, "environ symbol not found. Symbols=%lu\n", symcount);
		return -1;
	}else{
		Elf32_Ehdr hdr;
		if(readbuf(fd, base, &hdr, sizeof(hdr))){
			return -1;
		}

		u64 dyn_off = 0;
		u64 dyn_size = 0;
		for(int i = 0; i < hdr.e_phnum; i++){
			Elf32_Phdr phdr;
			if(readbuf(fd, base + hdr.e_phoff + sizeof(Elf32_Phdr) * i, &phdr, sizeof(phdr))){
				return -1;
			}

			if(phdr.p_type == PT_DYNAMIC){
				dyn_off = phdr.p_vaddr;
				dyn_size = phdr.p_memsz;
			}
		}

		u64 strtab = 0;
		u64 symtab = 0;
		u64 gnu_hash = 0;
		int dyn_count = dyn_size / sizeof(Elf32_Dyn);
		for(int i = 0; i < dyn_count; i++){
			Elf32_Dyn dyn;
			if(readbuf(fd, base + dyn_off + sizeof(Elf32_Dyn) * i, &dyn, sizeof(dyn))){
				return -1;
			}

			if(dyn.d_tag == DT_STRTAB){
				strtab = dyn.d_un.d_val;
			}
			if(dyn.d_tag == DT_SYMTAB){
				symtab = dyn.d_un.d_ptr;
			}
			if(dyn.d_tag == DT_GNU_HASH){
				gnu_hash = dyn.d_un.d_ptr;
			}
		}

		// Get symbol count from DT_GNU_HASH

		struct gnu_hash gnu_hash_obj;
		if(readbuf(fd, base + gnu_hash, &gnu_hash_obj, sizeof(gnu_hash_obj))){
			return -1;
		}
		u64 bucket_offset = base + gnu_hash + sizeof(gnu_hash_obj) + sizeof(u32) * gnu_hash_obj.bloom_size;
		u64 chain_offset = bucket_offset + sizeof(u32) * gnu_hash_obj.nbuckets;
		u32 last_bucket;
		if(readbuf(fd, bucket_offset + sizeof(u32) * (gnu_hash_obj.nbuckets - 1), &last_bucket, sizeof(last_bucket))){
			return -1;
		}
		//printf("nbu: %d symoffset: %d  %d,%d  last:%d\n", gnu_hash_obj.nbuckets, gnu_hash_obj.symoffset, gnu_hash_obj.bloom_size, gnu_hash_obj.bloom_shift, last_bucket);
		u64 symcount = 0;

		for(int i = 0;; i++){
			u32 last_sym = 0;
			if(readbuf(fd, chain_offset + sizeof(u32) * (last_bucket - gnu_hash_obj.symoffset + i), &last_sym, sizeof(last_sym))){
				return -1;
			}
			//printf("%d: %08x\n", i, last_sym);
			if(last_sym & 1){
				// last sym
				symcount = last_bucket + i + 1;
				break;
			}
		}

		// Linear search for dynamic symbols

		fprintf(stderr, "Symbol count: %lu\n", symcount);
		for(int i = 0; i < symcount; i++){
			Elf32_Sym sym;
			if(readbuf(fd, base + symtab + i * sizeof(Elf32_Sym), &sym, sizeof(sym))){
				return -1;
			}
			char name[100] = {};
			if(readbuf(fd, base + sym.st_name + strtab, name, sizeof(name) - 1)){
				return -1;
			}
			//printf("name[%d]: %s\n", i, name);
			if(strcmp(name, "environ") == 0){
				*addr = sym.st_value;
				return 0;
			}
		}
		fprintf(stderr, "environ symbol not found. Symbols=%lu\n", symcount);
		return -1;
	}

}

void patch_env(int pid, bool is64){
	char path[100];
	sprintf(path, "/proc/%d/maps", pid);

	FILE *fp = fopen(path, "r");
	if(fp == NULL){
		perror("fopen");
		return;
	}
	char buf[1000];
	unsigned long addr = 0;
	while(fgets(buf, sizeof(buf), fp)){
		int len = strlen(buf);
		if(len >= 1 && buf[len - 1] == '\0'){
			buf[len - 1] = 0;
		}
		if((pid == 1 && strstr(buf, LIBINIT64)) ||
				strstr(buf, is64 ? LIB64 : LIB32)){
			char *p = strchr(buf, '-');
			if(p){
				*p = 0;
				addr = strtoul(buf, NULL, 16);
				fprintf(stderr, "Found libc base: %lx (%s)\n", addr, buf);
				break;
			}

			break;
		}
	}
	fclose(fp);

	if(addr == 0){
		fprintf(stderr, "Failed to find libc.so base addr on %d\n", pid);
		return;
	}

	fprintf(stderr, "Base: %08lx\n", addr);

	sprintf(path, "/proc/%d/mem", pid);

	int fd = open(path, O_RDWR);
	if(fd < 0){
		perror("open mem");
		return;
	}

	u64 environ_addr = 0;
	if(get_environ_addr(fd, is64, addr, &environ_addr)){
		close(fd);
		return;
	}
	int wordsize = is64 ? 8 : 4;
	u64 environ_val = 0;
	if(readbuf(fd, addr + environ_addr, &environ_val, wordsize)){
		close(fd);
		return;
	}
	fprintf(stderr, "environ=%lx\n", environ_val);
	u64 env0_val = 0;
	if(readbuf(fd, environ_val, &env0_val, wordsize)){
		close(fd);
		return;
	}
	char buf2[100];
	if(readbuf(fd, env0_val, &buf2, sizeof(buf2) - 1)){
		close(fd);
		return;
	}
	buf2[sizeof(buf2) - 1] = 0;
	fprintf(stderr, "Current : %s\n", buf2);

	const char *prefix  = "PATH=/product/bin:";
	const char *patched = "PATH=/dev/.magisk:";
	// Check if not patched.
	if(strncmp(buf2, prefix, strlen(prefix)) == 0){
		fprintf(stderr, "Patching...\n");
		// Patch.
		if(writebuf(fd, env0_val, patched, strlen(patched))){
			close(fd);
			fprintf(stderr, "Failed to write env\n");
			return;
		}
		fprintf(stderr, "Done.\n");
	} else {
		fprintf(stderr, "Already patched.\n");
	}

	close(fd);
}

int main() {
	// Patch init env.
	fprintf(stderr, "Patching init env.\n");
	patch_env(1, false);

	DIR *d = opendir("/proc");

	while(1){
		struct dirent *ent = readdir(d);
		if(ent == NULL){
			break;
		}
		if('0' <= ent->d_name[0] && ent->d_name[0] <= '9') {
			int pid = atoi(ent->d_name);
			char path[100];
			sprintf(path, "/proc/%d", pid);

			// Check zygote process uid

			struct stat st;
			if(stat(path, &st) < 0){
				continue;
			}
			if(!S_ISDIR(st.st_mode)){
				continue;
			}
			if(st.st_uid != 0 && st.st_uid != 2000){
				continue;
			}

			// Check if cmdline equals zygote/adbd

			sprintf(path, "/proc/%d/cmdline", pid);
			int fd = open(path, O_RDONLY);
			if(fd < 0){
				continue;
			}
			char buf[100];
			read(fd, buf, sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = 0;
			close(fd);

			if(st.st_uid == 0){
				if(strcmp(buf, "zygote") == 0){
					fprintf(stderr, "Pid: %d name: %s\n", pid, buf);
					patch_env(pid, false);
				}else if(strcmp(buf, "zygote64") == 0){
					fprintf(stderr, "Pid: %d name: %s\n", pid, buf);
					patch_env(pid, true);
				}
			}else if(st.st_uid == 2000){
				if(strcmp(buf, "/apex/com.android.adbd/bin/adbd") == 0){
					fprintf(stderr, "Pid: %d name: %s\n", pid, buf);
					patch_env(pid, true);
				}
			}
		}

	}
	closedir(d);
}
