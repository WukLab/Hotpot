#
# Makefile for Hotpot
# Copyright (C) 2016-2017 Wuklab, Purdue. All rights reserved.
#

obj-m := hotpot_net.o
obj-m += hotpot.o

hotpot_net-y := net.o

# Transaction Related
hotpot-y := xact.o
hotpot-y += xact_mrsw_master.o

# Hotpot Filesystem Interface
hotpot-y += super.o
hotpot-y += file.o

hotpot-y += init.o
hotpot-y += on.o dn.o replica.o
hotpot-y += vm.o rmap.o proc.o
hotpot-y += recovery.o
hotpot-y += migrate.o

# Memory Management
hotpot-y += page_alloc.o
hotpot-y += swap.o
hotpot-y += event.o

# Targets
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
help:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) help
