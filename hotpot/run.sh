#!/bin/bash

#
# This file will load hotpot modules and mount /mnt/hotpot.
# Afterwards, you can play with hotpot by manipulating files under hotpot fs.
# You can change the parameters accordingly based on your setting.
#

#
# [physaddr, physaddr + size) must fully fall into memmap reserved region.
#
MOUNT_OPTIONS="physaddr=4G,size=4G,verbose,dbgmask=0"
MOUNT_POINT=/mnt/hotpot

#
# Central Dispatcher's IP and listening port
#
SERVER_IP="192.168.1.1"
SERVER_PORT=18500

NET_MODULE=hotpot_net.ko
HOTPOT_MODULE=hotpot.ko

start_hotpot() {
	insmod $NET_MODULE ip=$SERVER_IP port=$SERVER_PORT
	insmod $HOTPOT_MODULE

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
	rmmod $HOTPOT_MODULE
	rmmod $NET_MODULE
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
