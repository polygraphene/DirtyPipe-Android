#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <linux/module.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "modprobe-payload", __VA_ARGS__); }

int _start() {
	//const char *lib_mod = "/vendor/lib/libstagefright_soft_mp3dec.so";
	// Parse cmdline
	int fd_c = open("/proc/self/cmdline", O_RDONLY);
	char cmdline[1000];
	int r = read(fd_c, cmdline, sizeof(cmdline) - 1);
	if(r <= 0){
		LOGV("Failed to get cmdline.");
		exit(1);
	}
	close(fd_c);

	cmdline[r] = 0;
	int path_len = strlen(cmdline);
	if(path_len >= r - 1){
		LOGV("Failed to parse cmdline");
		exit(1);
	}
	const char *lib_mod = cmdline + path_len + 1;
	int fd = open(lib_mod, O_RDONLY);

#if MODPROBE_DEBUG == 1
	LOGV("Parsed lib_mod: %s\n", lib_mod);

	if(lseek64(fd, 0x1000, SEEK_SET) < 0){
		LOGV("Failed to lseek\n");
	}
	char buf2[1000];
	if(read(fd, buf2, sizeof(buf2)) < 0){
		LOGV("Failed to read\n");
	}
	LOGV("Content: %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n", buf2[0], buf2[1], buf2[2], buf2[3], buf2[4], buf2[5], buf2[6], buf2[7]);

	exit(2);
#endif

	int ret = syscall(__NR_finit_module, fd, "", 0);
	if(ret != 0){
		// finit_module failed with:
		// EPERM 1: Not root or not has CAP_SYS_MODULE capability.
		// ENOEXEC 8: bad module file
		// EACCES 13: denied by selinux policy. current domain has no load_module permission.
		// EFAULT 14: module was loaded but something wrong on modifying selinux policy.
		// ENOMSG 42: ok. mymod returns ENOMSG even if succeed to load.
		if(errno == ENOMSG){
			LOGV("Successfully set permissive: %s %d %d\n", lib_mod, ret, errno);
		}else{
			LOGV("Error on finit_module: %s %d %d\n", lib_mod, ret, errno);
		}
	}else{
		LOGV("Succeed on finit_module: %s %d\n", lib_mod, ret);
	}
	close(fd);

	// If succeed to load module, we now on a permissive domain.

	int p[2];
	pipe2(p, O_CLOEXEC);

	int fdnull = open("/dev/null", O_RDWR);
	dup2(fdnull, 0);
	dup2(fdnull, 1);
	dup2(fdnull, 2);

	if(fork() == 0){
		execve("/data/local/tmp/startup-root", 0, 0);
		LOGV("execve: %d\n", errno);
		exit(2);
		return 0;
	}
	close(p[1]);
	char buf;
	// Wait for execve() of child. This should wait for close-on-exec on pipe.
	// If we don't wait execve(), stage2 will overwrite (restore) the content of /vendor/bin/modprobe.
	// This will crash the child process.
	read(p[0], &buf, 1);

	exit(ret);
}
