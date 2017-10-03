#!/bin/bash

#
# physaddr and size depends on your memmap
# [physaddr, physaddr + size) must fully fall into memmap reserved region.
# Otherwise ioremap will fail.
#
MOUNT_OPTIONS="physaddr=4G,size=4G,verbose,dbgmask=0"
MOUNT_POINT=/mnt/hotpot

IB_MODULE=net.ko
DSNVM_MODULE=hotpot.ko

start_hotpot() {
	insmod $IB_MODULE
	insmod $DSNVM_MODULE

	if [ -e $MOUNT_POINT ]; then
		if [ -f $MOUNT_POINT ]; then
			echo "ERROR: $MOUNT_POINT is not a directly"
			exit 1
		fi
	else
		mkdir -p $MOUNT_POINT
	fi

	mount -t hotpot -o $MOUNT_OPTIONS none $MOUNT_POINT
}

quit_hotpot() {
	n=$(grep "hotpot" /proc/mounts | wc -l)
	if [ "$n" != "0" ]; then
		umount $MOUNT_POINT
	fi
	rmmod $DSNVM_MODULE
	rmmod $IB_MODULE
}

usage() {
	echo "Usage:"
	echo "  $ ./run.sh 1 (install modules and mount hotpot)"
	echo "  $ ./run.sh 2 (umount hotpot and remove modules)"
	echo "  $ ./run.sh 3 (mount only)"
	echo "  $ ./run.sh 4 (umount only)"
}

set -e

if [ "$1" == "1" ]; then
	start_hotpot
elif [ "$1" == "2" ]; then
	quit_hotpot
elif [ "$1" == "3" ]; then
	mount -t hotpot -o $MOUNT_OPTIONS none $MOUNT_POINT
elif [ "$1" == "4" ]; then
	umount $MOUNT_POINT
else
	usage
fi
