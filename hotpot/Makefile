#
# Makefile for Hotpot
# Copyright (C) 2016-2017 Wuklab, Purdue. All rights reserved.
#

obj-m := dsnvm-net.o
obj-m += dsnvm.o

# Transaction Related
dsnvm-y := xact.o
dsnvm-y += xact_mrsw_master.o

# Hotpot Filesystem Interface
dsnvm-y += super.o
dsnvm-y += file.o

dsnvm-y += init.o
dsnvm-y += on.o dn.o replica.o
dsnvm-y += vm.o rmap.o proc.o
dsnvm-y += recovery.o
dsnvm-y += migrate.o

# Memory Management
dsnvm-y += page_alloc.o
dsnvm-y += swap.o
dsnvm-y += event.o

# Targets
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
help:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) help
