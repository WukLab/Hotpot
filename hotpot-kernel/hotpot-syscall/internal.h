/*
 * Distributed Shared Persistent Memory.
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _HOTPOT_INTERNAL_H_
#define _HOTPOT_INTERNAL_H_

struct dist_hooks {
	int (*dist_lock_hook)(void *);
	int (*dist_unlock_hook)(void *);
	int (*dist_create_lock_hook)(unsigned int, void *, unsigned int, void *);
	void (*dist_sync_barrier_hook)(void);

	void (*dist_mmap_consensus_hook)(struct file *file, unsigned long *addr, unsigned long len);
};

int register_dist_lock_hooks(const struct dist_hooks *hooks);
void unregister_dist_lock_hooks(void);

#endif /* _HOTPOT_INTERNAL_H_ */
