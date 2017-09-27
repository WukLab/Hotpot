/*
 * Distributed Shared NVM. The filesystem interface.
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes all definitions and helpers of dsnvm fs.
 */

#ifndef _INCLUDE_DSNVM_FS_H_
#define _INCLUDE_DSNVM_FS_H_

struct dsnvm_page;

/**
 * struct dsnvm_super_block	-	Persistent in-NVM super block
 *
 * Necessary structure! Fill it!
 */
struct dsnvm_super_block {

};

/**
 * struct dsnvm_sb_info		-	Runtime in-Memory super block
 * @phys_addr:		Base physicall address of NVM area
 * @virst_addr:		Base virtual address of NVM area
 * @size:		Size of the NVM area (in bytes)
 * @nr_pages:		Nr of NVM pages (4K)
 * @nr_pages_metadata:	Nr of NVM pages used by metadata in the begining of NVM
 * @s_mount_opt:	Mounting time options
 * @s_lock:		Protects this structure
 */
struct dsnvm_sb_info {
	unsigned long		phys_addr;
	unsigned long		virt_addr;
	unsigned long		size;
	unsigned long		nr_pages;
	unsigned long		nr_pages_map;
	unsigned long		nr_pages_metadata;
	unsigned long		usable_phys_addr;
	unsigned long		usable_virt_addr;
	unsigned long		nr_pages_usable;
	unsigned long		s_mount_opt;
	struct mutex		s_lock;
};

static inline struct dsnvm_sb_info *DSNVM_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct dsnvm_super_block *dsnvm_get_super(struct super_block *sb)
{
	struct dsnvm_sb_info *sbi = DSNVM_SB(sb);
	void *ptr = (void *)sbi->virt_addr;
	return (struct dsnvm_super_block *)ptr;
}

/* Default file mode */
#define DSNVM_DEFAULT_MODE		0755

/* Mount flags */
#define DSNVM_MOUNT_ERRORS_CONT		(0x00000001)
#define DSNVM_MOUNT_ERRORS_PANIC	(0x00000002)
#define DSNVM_MOUNT_VERBOSE		(0x00000004)

#define set_opt(o, opt)			(o |= DSNVM_MOUNT_##opt)
#define clear_opt(o, opt)		(o &= ~DSNVM_MOUNT_##opt)
#define test_opt(sb, opt)		(DSNVM_SB(sb)->s_mount_opt & DSNVM_MOUNT_##opt)

/* Verbose message */
extern bool verbose;
extern bool err_panic;
#define dsnvm_pr_info(fmt, ...)						\
do {									\
	if (verbose)							\
		printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__);		\
} while (0)
#define dsnvm_pr_crit(fmt, ...)						\
do {									\
	if (verbose)							\
		printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__);		\
} while (0)
#define dsnvm_pr_debug(fmt, ...)					\
do {									\
	if (verbose)							\
		printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__);		\
} while (0)

/* Debug mask */

extern unsigned int dbgmask;
#define DSNVM_DBGMASK			(0x00000001)
#define DSNVM_DBGMASK1			(0x00000002)
#define DSNVM_DBGMASK2			(0x00000004)
#define DSNVM_DBGMASK_BLOCK		(0x00000008)
#define DSNVM_DBGMASK_VM		(0x00000010)
#define DSNVM_DBGMASK_LOG		(0x00000020)
#define DSNVM_DBGMASK_BARRIER		(0x00000040)
#define DSNVM_DBGMASK_MIGRATE		(0x00000080)

#undef dsnvm_printk
#undef dsnvm_printk1
#undef dsnvm_printk2
#define dsnvm_printk(x...)		((dbgmask&DSNVM_DBGMASK)?pr_crit(x):0)
#define dsnvm_printk1(x...)		((dbgmask&DSNVM_DBGMASK1)?pr_crit(x):0)
#define dsnvm_printk2(x...)		((dbgmask&DSNVM_DBGMASK2)?pr_crit(x):0)

#define DSNVM_PRINTK(format...)					\
do {								\
	if (dbgmask & DSNVM_DBGMASK) {				\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}                                               	\
} while (0)

#define DSNVM_PRINTK1(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK1) {				\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}                                               	\
} while (0)

#define DSNVM_PRINTK2(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK2) {				\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}                                               	\
while (0)

/*
 * Print ON_REGION page block/unblock info
 * Used by transaction.c 
 */
#define DSNVM_PRINTK_BLOCK(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK_BLOCK) {			\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}                                               	\
} while (0)

/*
 * Print VM info, including PageFault and COW
 * Used by vm.c and rmap.c
 */
#define DSNVM_PRINTK_VM(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK_VM) {			\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}                                               	\
} while (0)

/*
 * Print XACT log related info
 * Used by transaction.c
 */
#define DSNVM_PRINTK_LOG(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK_LOG) {			\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}							\
} while (0)

/*
 * Print SYSCALL barrier related info
 */
#define DSNVM_PRINTK_BARRIER(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK_BARRIER) {			\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}							\
} while (0)

/* Print migration related info */
#define DSNVM_PRINTK_MIGRATE(format...)				\
do {								\
	if (dbgmask & DSNVM_DBGMASK_MIGRATE) {			\
		pr_cont("[%s:%d] ", __func__, __LINE__);	\
		pr_cont(format);				\
		pr_cont("\n\n");				\
	}							\
} while (0)

extern const struct file_operations dsnvm_file_ops;
extern const struct file_operations dsnvm_dir_ops;
extern const struct vm_operations_struct dsnvm_vm_ops;

#endif /* _INCLUDE_DSNVM_FS_H_ */
