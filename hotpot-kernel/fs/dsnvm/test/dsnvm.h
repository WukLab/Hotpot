/*
 * Distributed Shared NVM
 *
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _INCLUDE_USERSPACE_DSNVM_H_
#define _INCLUDE_USERSPACE_DSNVM_H_

#define DSNVM_BEGIN_XACT_FLAG	8
#define DSNVM_COMMIT_XACT_FLAG	16
#define DSNVM_BEGIN_XACT_SINGLE_FLAG 32
#define DSNVM_COMMIT_XACT_SINGLE_FLAG 64

#define __NR_dist_lock		314
#define __NR_dist_unlock	315
#define __NR_dist_create_lock	316
#define __NR_dist_sync_barrier	317

struct dsnvm_xact_header {
	unsigned int	rep_degree;
	unsigned int	xact_id;
} __attribute__((__packed__));

struct dsnvm_addr_len {
	unsigned long	addr;
	unsigned int	len;
} __attribute__((__packed__));

static inline void dist_sync_barrier(void)
{
	barrier();
	syscall(__NR_dist_sync_barrier);
	barrier();
}

#endif /* _INCLUDE_USERSPACE_DSNVM_H_ */
