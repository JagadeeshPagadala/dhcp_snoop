#make ARCH=powerpc CROSS_COMPILE=/home/jagadeesh/openwrt/openwrt/staging_dir/toolchain-powerpc_8540_gcc-4.8-linaro_uClibc-0.9.33.2/bin/powerpc-openwrt-linux- -C ~/git/git/  M=`pwd` modules

obj-m:= dhcp_snoop_trusted.o
#KDIR:=/lib/modules/$(shell uname -r)/build
KDIR:=/home/jagadeesh/git/git
PWD:=$(shell pwd)
ccflags-y:= -Wno-declaration-after-statement -Wno-unused-value

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	insmod hook.ko
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
