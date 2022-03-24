obj-$(CONFIG_MYMOD)		+= mymod.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
M ?= $(shell pwd)
KERNEL_UAPI_HEADERS_DIR ?= $(shell readlink -m ${COMMON_OUT_DIR}/kernel_uapi_headers)
KBUILD_OPTIONS += CONFIG_MYMOD=m

modules clean modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) \
	$(KBUILD_OPTIONS) \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(@)

