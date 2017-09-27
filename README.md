Hotpot is a kernel-level, RDMA-based Distributed Shared Persistent Memory (DSPM) system. Applications can access data through memory load/store instructions and at the same time make the data durable and survive various types of failures. 

We built Hotpot as a linux module in the Linux 3.11.1 kernel (a small part of the original kernel is changed because of a limitation of the 3.11.1 kernel and will not be necessary for newer kernels). The Hotpot kernel module is in `hotpot/`. The folder `hotpot/test` has some simple examples of using Hotpot.

To run Hotpot, you need to first make and install `hotpot-kernel`. Make sure you can boot the modified 3.11.1 kernel.

Caution
This is a BETA version, use under your own risk! We will have our stable version ready soon.
