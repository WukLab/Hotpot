## Hotpot
Hotpot is an open-source, kernel-level, RDMA-based DSPM system.

## About the source code:
You can find all Hotpot core code at `fs/dsnvm/`.
We modified several kernel source files, which means you need to
download this repo and compile a new kernel from it.
Hotpot has to run on this kernel.  
(We will update a diff file compared with vanilla kernel soon).

## Caution
THIS IS A *BETA* VERSION, USE UNDER YOUR OWN RISK!  
(We will have a stable version soon)

## Compile
### Client
- Compile a new kernel from this repo and reboot to it
- Go into fs/dsnvm. Do `make`, which will generate two modules: `rc_pingpong.ko` and `dsnvm.ko`.

### Server
- Go to fs/dsnvm/server, issue make to get the server.

## How to Run
Coming soon with a full documentation.

Related Paper:  
`Distributed Shared Persistent Memory, SoCC17`
