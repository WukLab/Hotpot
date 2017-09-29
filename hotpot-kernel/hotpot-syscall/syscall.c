/*
 * Distributed Shared NVM.
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "internal.h"

static int (*dist_lock_hook)(void *);
static int (*dist_unlock_hook)(void *);
static int (*dist_create_lock_hook)(unsigned int, void *, unsigned int, void *);
static void (*dist_sync_barrier_hook)(void);

static void (*dist_mmap_consensus_hook)(struct file *file, unsigned long *addr, unsigned long len);

int register_dist_lock_hooks(const struct dist_hooks *hooks)
{
	if (unlikely(!hooks))
		return -EINVAL;

	if (unlikely(!hooks->dist_lock_hook || !hooks->dist_unlock_hook ||
		!hooks->dist_create_lock_hook || !hooks->dist_sync_barrier_hook ||
		!hooks->dist_mmap_consensus_hook))
		return -EINVAL;

	dist_lock_hook = hooks->dist_lock_hook;
	dist_unlock_hook = hooks->dist_unlock_hook;
	dist_create_lock_hook = hooks->dist_create_lock_hook;
	dist_sync_barrier_hook = hooks->dist_sync_barrier_hook;

	dist_mmap_consensus_hook = hooks->dist_mmap_consensus_hook;

	return 0;
}
EXPORT_SYMBOL(register_dist_lock_hooks);

void unregister_dist_lock_hooks(void)
{
	dist_lock_hook = NULL;
	dist_unlock_hook = NULL;
	dist_create_lock_hook = NULL;
	dist_sync_barrier_hook = NULL;

	dist_mmap_consensus_hook = NULL;
}
EXPORT_SYMBOL(unregister_dist_lock_hooks);

void dist_mmap_consensus(struct file *file, unsigned long *addr, unsigned long len)
{
	if (likely(dist_mmap_consensus_hook))
		dist_mmap_consensus_hook(file, addr, len);
	else
		pr_info("WARNING: Install DSNVM before call dist_mmap_consensus");
}

SYSCALL_DEFINE1(dist_lock, void __user *, key)
{
	if (likely(dist_lock_hook))
		return dist_lock_hook(key);
	return -EFAULT;
}

SYSCALL_DEFINE1(dist_unlock, void __user *, key)
{
	if (likely(dist_unlock_hook))
		return dist_unlock_hook(key);
	return -EFAULT;
}

SYSCALL_DEFINE4(dist_create_lock, unsigned int, target_node, void __user *, msg,
				  unsigned int, size, void __user *, output_mr)
{
	if (likely(dist_create_lock_hook))
		return dist_create_lock_hook(target_node, msg, size, output_mr);
	return -EFAULT;
}

SYSCALL_DEFINE0(dist_sync_barrier)
{
	if (likely(dist_sync_barrier_hook)) {
		dist_sync_barrier_hook();
		return 0;
	}
	return -EFAULT;
}
