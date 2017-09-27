#Hotpot
Hotpot is a kernel-level, RDMA-based DSPM system. We build hotpot as a linux module.
Some part of the kernel is changed to accomplish goals hotpot wants to achieve.

The `hotpot-kernel` is a modified 3.11.1 Linux kernel. Some modifications are not
necessary with newer kernels. But given the choice we made at the beginning of
the project, we just stick to it now.

If you want to run Hotpot, you need to first install `hotpot-kernel` with old
config from your machine. Make sure you can boot the modified 3.11.1 kernel.

All Hotpot code is in `hotpot/`. Please check it out.

#Caution
This system is BETA version, use under your own risk!
