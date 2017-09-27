Hotpot is a kernel-level, RDMA-based Distributed Shared Persistent Memory (DSPM) system. Applications can access data through memory load/store instructions and at the same time make the data durable and survive various types of failures. 

We built Hotpot as a linux module in the Linux 3.11.1 kernel (a small part of the original kernel is changed because of a limitation of the 3.11.1 kernel and will not be necessary for newer kernels). The Hotpot kernel module is in `hotpot/`. The folder `hotpot/test` has some simple examples of using Hotpot.

To run Hotpot, you need to first make and install `hotpot-kernel`. Make sure you can boot the modified 3.11.1 kernel.

Caution
This is a BETA version, use under your own risk! We will have our stable version ready soon.

For more information, check https://engineering.purdue.edu/WukLab/hotpot-socc17.pdf

To cite Hotpot, please use:
@inproceedings {Shan17-SOCC-Hotpot,
  author = {Yizhou Shan and Shin-Yeh Tsai and Yiying Zhang},
  title = {Distributed Shared Persistent Memory},
  booktitle = {Proceedings of the 8th Annual Symposium on Cloud Computing (SOCC '17)},
  year = {2017},
  address = {Santa Clara, CA, USA},
  month = {September}
 }
