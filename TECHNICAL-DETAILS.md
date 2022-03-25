# Prior knowledge
1. Dirty Pipe (CVE-2022-0847) can overwrite readable files.
2. Can't overwrite first byte of each page (each 4096 byte)

# Basic idea
- On Android, there is neither /etc/passwd nor suid. Futhermore we are monitored by SELinux for every operations on the system.
    - But we can read (and overwrite) system libraries (/system/lib/lib\*.so) by any process.
    - init process load many system libraries (dynamically linked on modern Android).
    - init process can read (and overwrite) more files than app process.
    - Use dirtypipe multiple times to load kernel module we tailored.

# Exploit process
- This exploit comprises following stages.
    1. Hook init process
    2. Rewrite /vendor/bin/modprobe and vendor library.
    3. fork()/execve() into /vendor/bin/modprobe.
    4. Load kernel module to disable selinux.

- Stage1
  1. Overwrite `/system/lib64/libc++.so` which is used by init.
    - Hook the function `_ZNSt3__115basic_streambufIcNS_11char_traitsIcEEEC2Ev (std::__1::basic_streambuf<char, std::__1::char_traits<char> >::basic_streambuf())`
    - We can trigger that function by running `setprop` command.

  2. Send next stage payload via `/system/lib/libldacBT_enc.so`.
    - `libc++` has very limited space.
    - 32bit `libldacBT_enc.so` should not be used so frequently, right?

  3. Payload in `libc++` `mmap`s `libldacBT_enc.so` for stage2 payload.

- Stage2
  1. We now in init process!

  2. Overwrite `/vendor/bin/modprobe` with modprobe-payload
      - modprobe has the privilege to load kernel module

  3. Overwrite `/vendor/lib/libstagefright_soft_mp3dec.so` with content of kernel module (mymod.ko)
      - modprobe can load kernel module from vendor_file context.
      - I have chosen this library because it has the same content as mymod.ko at offset=4096 which cannot be overwritten by dirtypipe.

  4. Transition to `vendor_modprobe` context then fork()/execve(`/vendor/bin/modprobe`)

- vendor\_modprobe (modprobe-payload)
  1. open(`/vendor/lib/libstagefright_soft_mp3dec.so`)
      - The file content was replaced to mymod.ko

  2. finit\_module(mymod.ko)
      - mymod.ko sets selinux domain of calling process to permissive.

  3. Run `startup-root` script
      - root with permissive domain.

# Information
```
$ sesearch --allow policy-dump|grep module_load
allow init-insmod-sh vendor_kernel_modules:system module_load;
allow ueventd vendor_file:system module_load;
allow vendor_modprobe vendor_file:system module_load;

-rw-r--r-- 1 root root  u:object_r:system_lib_file:s0     43168 2009-01-01 09:00 /system/lib/libldacBT_enc.so
-rw-r--r-- 1 root root  u:object_r:system_lib_file:s0    700392 2009-01-01 09:00 /system/lib64/libc++.so
-rw-r--r-- 1 root root  u:object_r:vendor_file:s0         71068 2009-01-01 09:00 /vendor/lib/libstagefright_soft_mp3dec.so
lrwxr-xr-x 1 root shell u:object_r:vendor_file:s0             7 2009-01-01 09:00 /vendor/bin/modprobe -> toolbox
```

- `finit_module` can load `vendor_kernel_modules` or `vendor_file`. Both are not readable by adb shell or non-system app. So kernel module must be prepared by other selinux contexts. `init` context can be used for that (stage1 payload).

- init-insmod-sh and ueventd should also available for this technique. (Not yet implemented/tested)

# How to add device support
- This method has device dependency by the following points:
    - Function offset in libc++.so
    - Empty space size in libc++.so
    - Availability of `/vendor/bin/modprobe`
    - Availability of `/vendor/lib/libstagefright_soft_mp3dec.so`
        - It must match the content of mymod.ko
    - Build kernel module for specific devices.


