#!/bin/bash

IB_MODULE=dsnvm-net.ko
DSNVM_MODULE=dsnvm.ko
MOUNT_OPTIONS="physaddr=4G,size=16G,verbose,dbgmask=0"
MOUNT_POINT=/mnt/dsnvm

start_dsnvm() {
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

	mount -t dsnvm -o $MOUNT_OPTIONS none $MOUNT_POINT
}

quit_dsnvm() {
	n=$(grep "dsnvm" /proc/mounts | wc -l)
	if [ "$n" != "0" ]; then
		umount $MOUNT_POINT
	fi
	rmmod $DSNVM_MODULE
	rmmod $IB_MODULE
}

usage() {
	echo "Usage:"
	echo "  pass 1 to install modules and mount dsnvm"
	echo "  pass 2 to umount dsnvm and remove modules"
	echo "  pass 3 to mount only"
	echo "  pass 4 to umount only"
}

set -e

if [ "$1" == "1" ]; then
	start_dsnvm
elif [ "$1" == "2" ]; then
	quit_dsnvm
elif [ "$1" == "3" ]; then
	mount -t dsnvm -o $MOUNT_OPTIONS none $MOUNT_POINT
elif [ "$1" == "4" ]; then
	umount $MOUNT_POINT
else
	usage
fi
