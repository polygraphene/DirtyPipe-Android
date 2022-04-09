# DirtyPipe for Android
Dirty Pipe (CVE-2022-0847) temporary root PoC for Android.

# Targets
Currently only run on Pixel 6 with security patch level from 2022-02-05 to 2022-04-05.
Don't use on other devices or other versions. It must crash (reboot).

# WARNING
There is possiblity to brick your phone by using this tool. Use it at your own risk.
Especially, don't update/install magisk from magisk app. It will cause permanent brick.

# How to use
1. Download binary from release page.
2. Setup adb (android platform tools).
3. Launch run.bat (For Windows) or run.sh (For Linux/Mac)
    - If you get `'adb' is not recognized ...` errors, check to add adb to PATH.
4. Wait several seconds (~30s) until Magisk app is automatically installed.
5. Run `adb shell` then `/dev/.magisk/su` (Or simply `su`) to get root shell.

![Screenshot](/screenshot1.png)

# About Magisk
1. Don't use install button on magisk app. It will brick your phone.
2. Don't reboot even if magisk app request. It will lose temporary root.
3. Only support root access. No magisk/zygisk modules support.

# How to build
1. Install Android NDK
2. Set PATH for aarch64-linux-android31-clang
```
export PATH=$PATH:$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
```
3. Run make
```
$ make
```

# How to build kernel module
1. Download Pixel 6 kernel source. [Link](https://source.android.com/setup/build/building-kernels)
2. Put mymod directory on kernel/private/google-modules/
3. Apply mymod/build-script-patch.patch to kernel/private/gs-google
4. Run build script

```
# For the first build
$ LTO=thin ./build/build.sh
# For faster rebuild (skip full rebuild)
$ SKIP_MRPROPER=1 SKIP_DEFCONFIG=1 LTO=thin ./build/build.sh
```

# Technical details
See [here](TECHNICAL-DETAILS.md)

# Future work
- ~~Stop using insecure telnet~~
- Make apk
- ~~Install Magisk~~
- Add device support

# Credits
- https://dirtypipe.cm4all.com/
- https://github.com/topjohnwu/Magisk
- https://github.com/j4nn/CVE-2020-0041/blob/v50g8-mroot/scripts/magisk-start.sh

