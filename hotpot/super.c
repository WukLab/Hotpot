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

#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/backing-dev.h>

#include "dsnvm.h"

char *server_name = "wuklab";
int ib_port_no = 1;

bool verbose = false;
bool err_panic = false;
unsigned int dbgmask = 0;

static bool IB_ON;

static const struct inode_operations dsnvm_file_inode_ops;
static const struct inode_operations dsnvm_dir_inode_ops;
static struct address_space_operations dsnvm_aops;
static struct backing_dev_info dsnvm_backing_dev_info;
static const struct super_operations dsnvm_sb_ops;

enum {
	Opt_addr, Opt_size,
	Opt_err_cont, Opt_err_panic,
	Opt_verbose, Opt_dbgmask, Opt_err
};

/*
 * e.g.
 * mount -t dsnvm -o physaddr=4G,size=2G,errors=continue,verbose=1 none /mnt/hotpot/
 * -- Base physical address is 4G (should have been reserved at boot time)
 * -- NVM area is 2G (should have been reserved at boot time)
 * -- Continue when error happens
 * -- Verbose debug message
 * -- Mount at /mnt/hotpot/
 */
static const match_table_t tokens = {
	{ Opt_addr,		"physaddr=%s"		},
	{ Opt_size,		"size=%s"		},
	{ Opt_err_cont,		"errors=continue"	},
	{ Opt_err_panic,	"errors=panic"		},
	{ Opt_verbose,		"verbose"		},
	{ Opt_dbgmask,		"dbgmask=%u"		},
	{ Opt_err,		NULL			},
};

static int dsnvm_parse_options(char *options, struct dsnvm_sb_info *sbi)
{
	int option;
	char *p, *rest;
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return -EINVAL;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_addr:
			if (!isdigit(*args[0].from))
				goto bad;
			sbi->phys_addr = memparse(args[0].from, &rest);
			break;
		case Opt_size:
			if (!isdigit(*args[0].from))
				goto bad;
			sbi->size = memparse(args[0].from, &rest);
			break;
		case Opt_err_cont:
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_err_panic:
			err_panic = true;
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_verbose:
			set_opt(sbi->s_mount_opt, VERBOSE);
			verbose = true;
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad;
			dbgmask = option;
			break;
		default:
			pr_err("error: unknown mount options: '%s'", p);
			return -EINVAL;
		}
	}
	return 0;
bad:
	pr_err("error: bad value '%s' for mount option '%s'\n", args[0].from, p);
	return -EINVAL;
}

static struct inode *dsnvm_get_inode(struct super_block *sb,
				     const struct inode *dir,
				     umode_t mode, dev_t dev)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = get_next_ino();
	inode_init_owner(inode, dir, mode);
	inode->i_mapping->a_ops = &dsnvm_aops;
	inode->i_mapping->backing_dev_info = &dsnvm_backing_dev_info;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;

	switch (mode & S_IFMT) {
		case S_IFREG:
			inode->i_op = &dsnvm_file_inode_ops;
			inode->i_fop = &dsnvm_file_ops;
			break;
		case S_IFDIR:
			inode->i_op = &dsnvm_dir_inode_ops;
			inode->i_fop = &dsnvm_dir_ops;

			/* dir inodes start with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		default:
			pr_err("error: unknown inode mode");
			return ERR_PTR(-EINVAL);
	}
	return inode;
}

/* File creation */

static int dsnvm_mknod(struct inode *dir, struct dentry *dentry,
		       umode_t mode, dev_t dev)
{
	struct inode *inode;

	inode = dsnvm_get_inode(dir->i_sb, dir, mode, dev);
	if (IS_ERR(inode))
		return -ENOSPC;

	d_instantiate(dentry, inode);
	dget(dentry);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

	return 0;
}

static int dsnvm_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int ret = dsnvm_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!ret)
		inc_nlink(dir);
	return ret;
}

static int dsnvm_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool excl)
{
	return dsnvm_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Note that you should have done, e.g.:
 * 	boot options: memmap=1G$4G		(reserved memory, 1G after 4G)
 * 	mount options: physaddr=4G,size=1G	(tell dsnvm where is nvm)
 * The reserved memory region should be lager than dsnvm ioremapped area.
 */
static int dsnvm_ioremap(struct dsnvm_sb_info *sbi)
{
	void __iomem *ret;

	/*
	 * high does not hurt, low does
	 * low does not hurt, high does
	 */
	sbi->phys_addr = round_up(sbi->phys_addr, DSNVM_PAGE_SIZE);
	sbi->size = round_down(sbi->size, DSNVM_PAGE_SIZE);
	sbi->nr_pages = sbi->size / DSNVM_PAGE_SIZE;

	ret = ioremap_cache(sbi->phys_addr, sbi->size);
	if (!ret) {
		pr_err("error: fail to ioremap range [%#lx - %#lx]",
			sbi->phys_addr, sbi->phys_addr + sbi->size);
		return -ENOMEM;
	}
	sbi->virt_addr = (unsigned long)ret;

	pr_crit("physical address range: [%#18lx - %#18lx]",
		sbi->phys_addr, sbi->phys_addr + sbi->size);
	pr_crit(" virtual address range: [%#18lx - %#18lx]",
		sbi->virt_addr, sbi->virt_addr + sbi->size);

	return 0;
}

static void dsnvm_iounmap(struct dsnvm_sb_info *sbi)
{
	if (!sbi->virt_addr) {
		pr_warning("WARNING: do ioremap first, fix it");
		return;
	}
	iounmap((void __iomem *)sbi->virt_addr);
	sbi->virt_addr = 0;
}

static int dsnvm_show_options(struct seq_file *m, struct dentry *root)
{
	struct dsnvm_sb_info *sbi = DSNVM_SB(root->d_sb);

	if (sbi->phys_addr)
		seq_printf(m, ",phys_addr=%#lx", sbi->phys_addr);

	if (sbi->virt_addr)
		seq_printf(m, ",virt_addr=%#lx", sbi->virt_addr);
	else
		seq_puts(m, ",unmapped");

	if (sbi->size)
		seq_printf(m, ",size=%ldGB", sbi->size >> 30);

	if (test_opt(root->d_sb, ERRORS_PANIC))
		seq_puts(m, ",errors=panic");
	
	if (test_opt(root->d_sb, VERBOSE))
		seq_puts(m, ",verbose");

	if (dbgmask)
		seq_printf(m, ",dbgmask=%u", dbgmask);

	return 0;
}

#ifdef DSNVM_DUMP_MSG
struct file *fp;
static const char *fname = "/root/hotpot-msg.log";
static DEFINE_MUTEX(fp_lock);
static void open_msg_dump_file(void)
{
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(get_ds());

	fp = filp_open(fname, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (IS_ERR_OR_NULL(fp))
		pr_err("Can not open: %s\n", fname);
}

static void close_msg_dump_file(void)
{
	if (!IS_ERR_OR_NULL(fp))
		filp_close(fp, NULL);
}

void write_2_msg_file(const char *buf)
{
	if (!IS_ERR_OR_NULL(fp)) {
                mutex_lock(&fp_lock);
		kernel_write(fp, buf, strlen(buf), fp->f_pos);
		vfs_fsync(fp, 0);
                mutex_unlock(&fp_lock);
	}
}

static char msg_buffer[256];
void log_msg_bytes(size_t nr_bytes)
{
	struct timespec ts;

	getnstimeofday(&ts);
	memset(msg_buffer, 0, 256);
	sprintf(msg_buffer, "%lu, %zu\n", ts.tv_sec, nr_bytes);

	write_2_msg_file(msg_buffer);
}
#endif /* DSNVM_DUMP_MSG */

/* umount time, reset all */
static void dsnvm_put_super(struct super_block *sb)
{
	struct dsnvm_sb_info *sbi = DSNVM_SB(sb);

	verbose = false;
	err_panic = false;
	dbgmask = 0;

	sb->s_fs_info = NULL;
	kfree(sbi);

	/* stop kswapd etc. */
	destroy_dsnvm_allocator();

	/*
	 * DN_REGIONs are embedded in dsnvm_client_file, whose
	 * lifetime only spans from file open() to close().
	 */
	free_all_on_regions();
	free_all_replica_regions();

	/*
	 * We should send CD this leave message, so CD would remove us
	 * from the known machine list. However, if CD is closed then
	 * IB will turn us into deadlock. So comment this for safety.
	 */
#if 1
	dsnvm_send_machine_leave();
#endif

	/*
	 * BIT FAT NOTE: Always unmap NVM area at the very end.
	 */
	if (sbi->virt_addr)
		dsnvm_iounmap(sbi);

	close_msg_dump_file();
}

/* mounting time, establish all */
static int dsnvm_fill_super(struct super_block *sb, void *data, int silent)
{
	struct dsnvm_super_block *super;
	struct dsnvm_sb_info *sbi;
	struct inode *root;
	int ret;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	ret = dsnvm_parse_options(data, sbi);
	if (ret)
		goto out;

	ret = dsnvm_ioremap(sbi);
	if (ret)
		goto out;

	ret = init_dsnvm_allocator(sbi);
	if (ret)
		goto out_unmap;

	/*
	 * TODO: If it is real persistent NVM, then we could load
	 * old metadata from it, which including dsnvm_bitmap, dsnvm
	 * page array, etc. So if we are doing _recovery_ later, this
	 * is a start point.
	 */
	super = dsnvm_get_super(sb);

	sb->s_op = &dsnvm_sb_ops;
	sb->s_xattr = NULL;
	sb->s_blocksize = 4096;
	sb->s_blocksize_bits = 12;
	sb->s_time_gran = 1;

	root = dsnvm_get_inode(sb, NULL, S_IFDIR | DSNVM_DEFAULT_MODE, 0);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto out_nvmm;
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		pr_err("error: get root inode failed");
		ret = -ENOMEM;
		goto out_nvmm;
	}

	open_msg_dump_file();

	/*
	 * Say hello to CD
	 */
	if (IB_ON)
		dsnvm_send_machine_join();

	return 0;

out_nvmm:
	destroy_dsnvm_allocator();
out_unmap:
	dsnvm_iounmap(sbi);
out:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return ret;
}

static struct dentry *dsnvm_mount(struct file_system_type *fs_type, int flags,
				  const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, dsnvm_fill_super);
}

static const struct inode_operations dsnvm_file_inode_ops = {
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

static const struct inode_operations dsnvm_dir_inode_ops = {
	.create		= dsnvm_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.mkdir		= dsnvm_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= dsnvm_mknod,
	.rename		= simple_rename,
};

static struct address_space_operations dsnvm_aops = {
	.readpage	= simple_readpage,
	.write_begin	= simple_write_begin,
	.write_end	= simple_write_end,
};

static struct backing_dev_info dsnvm_backing_dev_info = {
	.name		= "dsnvm",
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK | BDI_CAP_MAP_DIRECT |
			  BDI_CAP_MAP_COPY | BDI_CAP_READ_MAP |
			  BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP,
};

static const struct super_operations dsnvm_sb_ops = {
	.alloc_inode	= NULL,
	.destroy_inode	= NULL,
	.write_inode	= NULL,
	.put_super	= dsnvm_put_super,
	.show_options	= dsnvm_show_options
};

static struct file_system_type dsnvm_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hotpot",
	.mount		= dsnvm_mount,
	.kill_sb	= kill_litter_super
};

unsigned long total_dsnvm_size = 0x40000000;

static int dsnvm_fs_init(void)
{
	int ret;

	BUILD_BUG_ON(__NR_DSNVM_PAGE_FLAGS > sizeof(long)*BITS_PER_BYTE);
	BUILD_BUG_ON(sizeof(struct dsnvm_request) > DSNVM_MAX_REQUEST_LEN);
	BUILD_BUG_ON(sizeof(struct dsnvm_reply) > DSNVM_MAX_REPLY_LEN);

	ret = -EIO;
	IB_ON = false;

	ret = dsnvm_client_init_ib(server_name, ib_port_no, total_dsnvm_size);
	if (ret) {
		pr_err("ERROR: fail to init InfiniBand");
		return -EIO;
	} else
		IB_ON = true;

	ret = init_dsnvm_client_cache();
	if (ret) {
		pr_err("ERROR: fail to init client cache");
		return ret;
	}

	ret = register_filesystem(&dsnvm_fs_type);
	if (ret) {
		pr_err("ERROR: fail to register filesystem");
		goto out;
	}

	ret = create_dsnvm_proc_file();
	if (ret) {
		pr_err("ERROR: fail to create proc file");
		goto out2;
	}

	ret = dsnvm_init_xact();
	if (ret) {
		pr_err("ERROR: fail to init xact");
		goto out3;
	}

	ret = alloc_pff_reason_array();
	if (ret) {
		pr_err("ERROR: fail to alloc pff");
		goto out3;
	}

	/* The background migration guy */
	ret = init_dsnvm_migrated();
	if (ret)
		goto out4;

	pr_crit("dsnvm ready to mount");

	return 0;

out4:
	free_pff_reason_array();
out3:
	remove_dsnvm_proc_file();
out2:
	unregister_filesystem(&dsnvm_fs_type);
out:
	destroy_dsnvm_client_cache();

	return ret;
}

static void dsnvm_fs_exit(void)
{
	stop_dsnvm_migrated();
	free_pff_reason_array();
	destroy_dsnvm_client_cache();
	remove_dsnvm_proc_file();
	unregister_filesystem(&dsnvm_fs_type);
}

module_init(dsnvm_fs_init);
module_exit(dsnvm_fs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wuklab@Purdue");
