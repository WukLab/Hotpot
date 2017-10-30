# Hotpot Usages

This document will explain how to use Hotpot.

## Open and mmap Hotpot
To use Hotpot, application needs to first map Hotpot into its virtual address space. This can done be by `open()` and `mmap()` together. Recall that Hotpot already mounted itself at `/mnt/hotpot`, so all application needs to do is to open a dataset from the mounting point and memory map it into its address space. Afterwards, application can access the distributed shared persistent memory space by direct memory load and store.

For example:
```c
static void open_and_mmap_files(void)
{
	mmap_len = 40960;

	/*
	 * Open Hotpot dataset named abc
	 * You should be able to see some outputs in CD side.
	 */
	fd = open("/mnt/hotpot/abc", O_RDWR | O_CREAT);
	if (fd < 0)
		die("Can not open file (1): %s", strerror(fd));

	/* mmap Hotpot regions */
	virt_hotpot = mmap(NULL, mmap_len, PROT_WRITE, MAP_SHARED, fd, 0);
	if (virt_hotpot == MAP_FAILED)
		die("Can not mmap (1): %s", strerror(errno));

	/* Direct memory load/store in DSPM address space */
	foo = *(int *)virt_hotpot;
}
```

### mmap()
`void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`  
All the parameters are using the current semantic. Note that @length argument specifies the length of the mapping. The maximum @length equals to the maximum length of a dataset, which is configured at building time (See [configurations.md](https://github.com/WukLab/Hotpot/blob/master/hotpot/Documentations/configurations.md) for how to config the maximum dataset size). If mmap() returns error, please use `dmesg` to check error messages.

## Distributed Barrier
Hotpot introduces a distributed barrier by adding a new syscall `dist_sync_barrier`. This syscall is synchronize, it will wait until all online hotpot nodes have called dist_sync_barrier. Currently, the barrier is `per-node`, instead of `per-application`. This means once an application from one node has called this barrier, all other online nodes need to do so also. We add a wrap for this syscall, you can check the [sample code](https://github.com/WukLab/Hotpot/blob/master/hotpot/test/dsnvm.h).

The wrap for this syscall is:
```c
static inline void dist_sync_barrier(void)
{
	syscall(__NR_dist_sync_barrier);
}

```

## Transaction
Hotpot reuse the `msync()` syscall to let applications to invoke hotpot transactions. But applications need to pass Hotpot specific flags to mync. Namely, `DSNVM_BEGIN_XACT_FLAG` to begin a transaction, and `DSNVM_COMMIT_XACT_FLAG` to commit a transaction. To do transaction, applications need to provide a scatter-gatther list of memory regions that will be involed in transaction. The format of the list is defined in `test/dsnvm.h`:
```c
struct dsnvm_addr_len {
	unsigned long	addr;
	unsigned int	len;
} __attribute__((__packed__));
```

## Begin Transaction
To begin a transation, applications just need to prepare the sg list of transaction areas. After that, applications call into `msync` with flag `DSNVM_BEGIN_XACT_FLAG`. The `msync()` will return a `transaction id`, which will be used later by commit transaction. Also, applications need to check if msync returns `DSNVM_RETRY`. `DSNVM_RETRY` means one or multiple areas within the provided sg list are already within another transaction, so applications should retry.

For example (you can find more details in `test/seq.c`):
```c
retry:
	ret = msync(xact_areas, NR_XACT_AREAS, DSNVM_BEGIN_XACT_FLAG);

	if (unlikely(ret == DSNVM_RETRY)) {
		sleep_random();
		round++;
		if (round > 20)
			die("Thread %d: too many retry begin xact rounds (%lu)", thread_id, round);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to start transaction", thread_id);
	}
	*xact_id = ret;
```

## Commit Transaction
To commit a transaction, applications need to provide more information. Namely, 1) transaction id, which is returned by begin transaction, 2) replication degree. This structure is defined in `test/dsnvm.h`:
```c
struct dsnvm_xact_header {
	unsigned int	rep_degree;
	unsigned int	xact_id;
} __attribute__((__packed__));
```

Same as begin transaction, commit also use msync, but with flag `DSNVM_COMMIT_XACT_FLAG`. Also, the first parameter needs to point to a contiguous memory region, of which the first portion is `struct dsnvm_xact_header`, the second portion is a list of `struct dsnvm_addr_len`. You can find more details on how to allocate and manage this memory space in `test/seq.c:init_xact()`. Similary, the return value of `msync` needs to be checked if `DSNVM_RETRY` is returned.

For example (you can find more details in `test/seq.c`):
```c
retry:
	ret = msync(xact_struct, NR_XACT_AREAS, DSNVM_COMMIT_XACT_FLAG);

	if (ret == DSNVM_RETRY) {
		sleep_random();
		round++;
		if (round > 20)
			die("Thread %d: too many retry commit xact id %d rounds (%lu)", thread_id, xact_id, round);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to commit transaction id %d ret %d", thread_id, xact_id, ret);
	}
```
