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

2. To run Hotpot, a contiguous physical memory region must be reserved for Hotpot usage. To do so, CentOS users could open `/boot/grub2/grub.cfg` and find hotpot-kernel's entry. Append `memmap=N[KMG]\$S[KMG]` to kernel parameter. The actual parameter depends on your usage. For example, to reserve `[4G - 20G]`, you can append `memmap=16G\$4G`.

3. Reboot and 1) use `uname` to check if the kernel version matches. 2) Use `dmesg` or `free` to check if memory has been reserved. x86 users can also check e820 tables.

## S2: Compile Modules
After  boot into `hotpot-kernel` successfully, you could go to `hotpot` directory and type `make` to compile two modules. If the kernel is right, you will have 2 modules compiled: `dsnvm.ko` and `rc_pingpong.ko` (The module name has legacy reasons). `dsnvm.ko` is the hotpot itself, `rc_pingpong.ko` is our customized RDMA-stack module.

## S3: Compile Central Dispatcher (CD)
Hotpot's CD source code is located in `hotpot/server/`. Assume this server has installed all IB user libraries, you can go to this directory and simply do `make`. After that, you will have a `mgmt_server`, which is our CD server (Again, the name has some historic reasons). Before jumping to S4, get the IP address of CD server, which will be used by all other hotpot nodes.

## S4: Config Hotpot

### S4.1: Config Network
In our setting, IB needs Ethernet to bootstrap the initial connection. That is why we need the IP address of CD. But do note that all hotpot nodes only need to know the IP address of CD. Currently, the IP address of CD has to be manually changed in the source code. To do so, open `hotpot/rc_pingpong.c`, and replace the following line:  
>`addr.sin_addr.s_addr = htonl((((((128 << 8) | 46) << 8) | 115) << 8) | 33);`  
with the IP address of your CD (Kind of raw, well..).

### S4.2: Config Hotpot
Hotpot has several config options that have to be configured at compile time. The configurations have already been set if you are running master. TODO: A detailed list and explanation.

### S4.3: Recompile Modules
After `S4.1` and `S4.2`, you need to recompile by doing `make` again.

## S5: Run CD
> `./mgmt_server`

## S6: Run Hotpot
There is a simple script `hotpot/install.sh`, which help us to install modules and mount hotpot's filesystem. The hotpot's filesystem interface is used to simplify our programming experience by supporting commonly used POSIX APIs, e.g., `open`, `close`, and `msync`.  
After you can `./install.sh`, you should be able to see some output at CD side. To connect multiple Hotpot nodes, just do the above steps one by one.  

## S7: Run User Programs
There are several code samples under `hotpot/test/`. Basically, we `open (or create)` a dataset by calling POSIX `open`. After that, the opened fd will be mmap'ed into application's address space. If mmap succeed, application can access the DSPM space directly and transpatently.

### Debug Hotpot
Hotpot will create two special files: `/proc/dsnvm-event` and `/proc/dsnvm`. The first one lists a lot of hotpot internal activities, which will help us to understand what is going within the system. The latter one lists some general informations. Both of them will help us debug and tune the system.

## To cite Hotpot, please use:

>\@inproceedings{Shan17-SOCC-Hotpot\,  
> author = {Yizhou Shan and Shin-Yeh Tsai and Yiying Zhang},  
> title = {Distributed Shared Persistent Memory},  
> booktitle = {Proceedings of the 8th Annual Symposium on Cloud Computing (SOCC '17)},  
> year = {2017},  
> address = {Santa Clara, CA, USA},  
> month = {September}  
>}
