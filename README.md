## Hotpot
Hotpot is a kernel-level, RDMA-based Distributed Shared Persistent Memory (DSPM) system. Applications can access data through memory load/store instructions and at the same time make the data durable and survive various types of failures. 

We built Hotpot as a linux module for the Linux 3.11.1 kernel (a small part of the original kernel is changed because of a limitation of the 3.11.1 kernel and will not be necessary for newer kernels). The Hotpot kernel module is in `hotpot/`. The folder `hotpot/test` has some simple examples of using Hotpot.

## Caution:  
This is a BETA version, use under your own risk! We will have our stable version ready soon.

For more information, check https://engineering.purdue.edu/WukLab/hotpot-socc17.pdf

## HowTo Run Hotpot

### Prerequisites
1. More than 2 servers connected via Infiniband switch.
2. At least 1 server has installed Infiniband user libraries (for central dispatcher).

## S1: Install and Boot `hotpot-kernel`
1. `hotpot-kernel` is based on `3.11.1`. To compile, go into `hotpot-kernel` directory. Compile kernel with your machine's old config:  
>`cp /boot/config-your-default-kernel-version hotpot-kernel/.config`  
>`make oldconfig` (Recommend to have a special _CONFIG_LOCALVERSION="-hotpot"_)  
>`make && make modules && make modules_install && make install`  

2. To run Hotpot, a contiguous physical memory region must be reserved for Hotpot usage. To do so, CentOS users could open `/boot/grub2/grub.cfg` and find hotpot-kernel's entry. Append `memmap=N[KMG]\$S[KMG]` to kernel parameter. The actual parameter depends on your usage. For example, to reserve `[4G - 8G]`, you can append `memmap=4G\$4G`.

3. Reboot and 1) use `uname` to check if the kernel version matches. 2) Use `dmesg` or `free` to check if memory has been reserved. x86 users can also check e820 tables.

## S2: Compile Modules
After  boot into `hotpot-kernel` successfully, you could go to `hotpot` directory and type `make` to compile two modules. If the kernel is right, you will have 2 modules compiled: `dsnvm.ko` and `rc_pingpong.ko` (The module name has legacy reasons). `dsnvm.ko` is the hotpot itself, `rc_pingpong.ko` is our customized RDMA-stack module.

## S3: Run Central Dispatcher (CD)
Hotpot's CD source code is located in `hotpot/server/`. Assume this server has installed all IB user libraries, you can go to this directory and simply do `make`. After that, you will have a `mgmt_server`, which is our CD server (Again, the name has some historic reasons). Before jumping to S4, the IP address of CD server, which will be used by all other hotpot nodes.

## S4: Run Hotpot
### S4.1: Config Network
### S4.2: Config Hotpot

## To cite Hotpot, please use:

>\@inproceedings{Shan17-SOCC-Hotpot\,  
> author = {Yizhou Shan and Shin-Yeh Tsai and Yiying Zhang},  
> title = {Distributed Shared Persistent Memory},  
> booktitle = {Proceedings of the 8th Annual Symposium on Cloud Computing (SOCC '17)},  
> year = {2017},  
> address = {Santa Clara, CA, USA},  
> month = {September}  
>}
