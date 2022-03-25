# DirtyPipe for Android
Dirty Pipe (CVE-2022-0847) temporary root PoC for Android.

# Targets
Currently only run on Pixel 6 with security patch level 2022-02-05.
Don't use on other devices or other versions. It must crash (reboot).

# How to use
1. Download binary from release page.
2. Setup adb (android platform tools).
3. Launch run.bat (For Windows) or run.sh (For Linux/Mac)
    - If you get `'adb' is not recognized ...` errors, check to add adb to PATH.
4. You now get temporary root shell by telnet \<Device IP Address\> 10847

![Screenshot](/screenshot1.png)

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
- Stop using insecure telnet
- Make apk
- Install Magisk
- Add device support

# Credits
- https://dirtypipe.cm4all.com/

