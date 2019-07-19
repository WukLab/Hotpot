# Hotpot

![Status](https://img.shields.io/badge/Version-Experimental-green.svg)

Hotpot is a kernel-level, RDMA-based Distributed Shared Persistent Memory (DSPM) system. Applications can access data through memory load/store instructions and at the same time make the data durable and survive various types of failures.

We built Hotpot as a linux module for the Linux 3.11.1 kernel (a small part of the original kernel is changed because of a limitation of the 3.11.1 kernel and will not be necessary for newer kernels). The Hotpot kernel module is in `hotpot/`. The folder `hotpot/test` has some simple examples of using Hotpot.

# Documentation
This file is a high level __HOW-TO__ run hotpot tutorial.

For Hotpot APIs and Hotpot configurations, please check [hotpot/Documentations](https://github.com/WukLab/Hotpot/tree/master/hotpot/Documentations).

For common setup and runtime issues, please check [KNOWN-ISSUES](https://github.com/WukLab/Hotpot/blob/master/KNOWN-ISSUES.md).

For more information about Hotpot itself, please check [Hotpot paper](https://engineering.purdue.edu/WukLab/hotpot-socc17.pdf).

# Caution:  
This is a BETA version, use under your own risk!

# How To Run Hotpot

## Prerequisites
1. More than two machines connected via InfiniBand.
2. One of the machines (served as central dispatcher) has installed InfiniBand OFED package. The rest of the machines serve as Hotpot nodes and need to install hotpot-kernel (see below).
3. Note on OFED: The network layer of Hotpot is an early version of [LITE](https://github.com/wuklab/LITE), which is not compatible with OFED kernel modules. That means, the nodes that are going to run Hotpot clients should not have OFED kernel modules installed. For the cental dispatcher node, you can install both user-level and kernel-level OFED packages. If you want to know more about OFED, please refer to this [document](https://github.com/lastweek/LITE/blob/master/README.md).

## S1: Compile central dispatcher (CD) server
Hotpot's CD source code is located in `hotpot/server/`, which runs on user space. Assume this machine has installed all IB user libraries, you can go to this directory and simply do `make`. After that, you will have a `hotpot-server`, which is our CD server. Also, get the IP address of this CD server, which will be used by all other hotpot nodes to establish connection.

## S2: Install and boot Hotpot kernel on Hotpot nodes
1. First, compile the `hotpot-kernel` using `hotpot-kernel` directory. Compile the kernel with your machine's old config:  
`cp /boot/config-your-default-kernel-version hotpot-kernel/.config`  
`make oldconfig` (Recommended to have a special _CONFIG_LOCALVERSION="-hotpot"_)  
`make && make modules && make modules_install && make install`  

2. To run Hotpot, a contiguous physical memory region must be reserved for Hotpot usage. To do so, CentOS users could open `/boot/grub2/grub.cfg` and find hotpot-kernel's entry. Append `memmap=N[KMG]\$S[KMG]` to kernel parameter. The actual parameter depends on your usage. For example, to reserve `[4G - 20G]`, you can append `memmap=16G\$4G`.

3. Reboot the machine and 1) use `uname` to check if the kernel version matches. 2) Use `dmesg` or `free` to check if memory has been reserved. x86 users can also check e820 tables.

## S3: Config Hotpot

Hotpot has several options that can be configured at compile time. The default configurations have been tested to work well for our applications. For detailed config options, please refer to this [document](https://github.com/WukLab/Hotpot/blob/master/hotpot/Documentations/configurations.md).

## S4: Compile Modules
After boot into `hotpot-kernel` successfully (S2), go to `hotpot` directory and type `make` to compile two modules. If the kernel is right, you will have 2 modules compiled: `hotpot.ko` and `hotpot_net.ko`. `hotpot.ko` is the Hotpot module, `hotpot_net.ko` is a customized RDMA-stack which Hopot runs on top of.

## S5: Run
In general, to run hotpot, you need to start CD server first, which will listen on a port you specified. After that, start hotpot node one by one to establish the connection with CD server.

### S5.1 Run CD
Assume the IP address of CD is `192.168.1.1`, and you want CD to listen on port `18500`, then you can start CD server like this:  
> `./hotpot-server -l 18500`  

### S5.2: Run Hotpot
There is a simple script `hotpot/run.sh`, which help us to install modules and mount hotpot's filesystem. The hotpot's filesystem interface is used to simplify our programming experience by supporting commonly used POSIX APIs, e.g., `open`, `close`, and `msync`. After you run `./run.sh 1`, you should be able to see some output at CD side. To connect multiple Hotpot nodes, just do the above steps one by one.  

In detail:  
1. **insmod hotpot_net.ko ip=192.168.1.1 port=18500**  
      This will insmod hotpot network module  
      ip=192.168.1.1 port=18500 need to match CD's setting  
2. **insmod hotpot.ko**  
3. **mount -t hotpot -o physaddr=4G,size=4G,verbose,dbgmask=0 none /mnt/hotpot**  
      Mount `/mnt/hotpot`  
      `[physaddr, physaddr+size)` must fully fall into `memmap` reserved area.  
(Please check `run.sh` for detailed steps. Please note that if `run.sh` fails at some intermediate steps, hotpot_net.ko or hotpot.ko can already be installed. You need to do rmmod before retry.)

## S6: Run User Programs
There are several code samples under `hotpot/test/`. Basically, we `open (or create)` a dataset by calling POSIX `open`. After that, the opened fd will be mmap'ed into application's address space. If mmap succeed, application can access the DSPM space directly and transpatently.

# Debug Hotpot
Hotpot will create two special files: `/proc/dsnvm-event` and `/proc/dsnvm`. The first one lists a lot of hotpot internal activities, which will help us to understand what is going within the system. The latter one lists some general informations. Both of them will help us debug and tune the system. If you have any issues with deploying Hotpot, please contact Yizhou Shan <shan13@purdue.edu>.


## To cite Hotpot, please use:

>\@inproceedings{Shan17-SOCC-Hotpot\,  
> author = {Yizhou Shan and Shin-Yeh Tsai and Yiying Zhang},  
> title = {Distributed Shared Persistent Memory},  
> booktitle = {Proceedings of the 8th Annual Symposium on Cloud Computing (SOCC '17)},  
> year = {2017},  
> address = {Santa Clara, CA, USA},  
> month = {September}  
>}
