obj-m:=dhcp_snoop.o
#KDIR:=/lib/modules/$(shell uname -r)/build
KDIR:=/home/jagadeesh/git
PWD:=$(shell pwd)
ccflags-y:= -Wno-declaration-after-statement -Wno-unused-value

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	insmod hook.ko
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
