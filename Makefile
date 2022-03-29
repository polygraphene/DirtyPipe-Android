CC=aarch64-linux-android31-clang
CXX=aarch64-linux-android31-clang++
STRIP=llvm-strip
CFLAGS=-O2 $(CPPFLAGS)
ADB=adb
MYMOD_COPY=../../p6/kernel/out/android-gs-pixel-5.10/dist/mymod.ko
D=/data/local/tmp
LI=/system/lib/libldacBT_enc.so
OBJS=dirtypipe-android.o stage1.o stage2-payload-include.S
VERSION=1.0.3

build: dirtypipe-android mymod.ko

dirtypipe-android: dirtypipe-android.o elf-parser.o Makefile stage1.o stage2-payload-include.S stage2-payload
	$(CC) $(CFLAGS) -Wall -o $@ dirtypipe-android.o elf-parser.o stage1.o stage2-payload-include.S

dirtypipe-android.o: dirtypipe-android.c Makefile stage2-symbol.h
	$(CC) $(CFLAGS) -Os -c -o $@ $<

elf-parser.o: elf-parser.c Makefile
	$(CC) $(CFLAGS) -Os -c -o $@ $<

stage1.o: stage1.S Makefile include.inc
	$(CC) $(CPPFLAGS) -c -o $@ $<

stage2.o: stage2.S Makefile include.inc
	$(CC) -nostdlib -c -o $@ $<

stage2-c.o: stage2-c.c Makefile
	$(CC) -Os -nostdlib -c -o $@ $<

stage2: stage2-c.o stage2.o stage2.lds Makefile
	$(CC) -T stage2.lds -nostdlib -nostartfiles -static -o $@ stage2-c.o stage2.o

# Must be smaller than 4096 bytes
stage2.text: stage2 Makefile
	aarch64-linux-gnu-objcopy -O binary -j .text $< $@

stage2-symbol.h: stage2 Makefile
	echo -n "unsigned long stage2_libname_addr = 0x" > $@
	(nm $< | grep -e ' T libname'$ | cut -f 1 -d " " | tr -d $$'\n'; echo "UL - 0x2000UL;") >> $@ || rm $@

# Must be smaller than 4096 bytes
modprobe-payload: modprobe-payload.c Makefile
	$(CC) -Os -nostartfiles -o $@ $< -llog
	$(STRIP) $@

mymod.ko: $(MYMOD_COPY)
	cp $(MYMOD_COPY) mymod.ko

# Page 1: stage2.text (Up to 1 page)
# Page 2: modprobe-payload (Up to 1 page)
# Page 3-6: mymod.ko (Up to 4 page)
stage2-payload: stage2.text modprobe-payload mymod.ko Makefile
	test -z "$$(find stage2.text -size +4096c)"
	test -z "$$(find modprobe-payload -size +4096c)"
	test -z "$$(find mymod.ko -size +16384c)"
	cp stage2.text $@
	truncate -s 4096 $@
	cat modprobe-payload >> $@
	truncate -s $(shell echo $$(( 4096 * 2 ))) $@
	cat mymod.ko >> $@
	truncate -s $(shell echo $$(( 4096 * 6 ))) $@

stage2-payload-include.o: stage2-payload-include.S stage2-payload Makefile
	$(CC) -c -o $@ $<

clean:
	-rm dirtypipe-android.o elf-parser.o stage1.o stage2-payload dirtypipe-android
	-rm stage2.text stage2 stage2-c.o stage2.o
	-rm stage2-symbol.h
	-rm modprobe-payload

### INSTALL ###

install: dirtypipe-android startup-root magisk/busybox
	$(ADB) push dirtypipe-android startup-root magisk/busybox $(D)
	$(ADB) shell chmod 755 $(D)/dirtypipe-android $(D)/startup-root $(D)/busybox

run: install
	$(ADB) shell $(D)/dirtypipe-android

release: build
	./release.sh $(VERSION)

