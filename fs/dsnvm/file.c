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
 * This file describes function hooks of POSIX file APIs.
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/bitmap.h>

#include "dsnvm.h"

#if 0
static void dump_dsnvm_file(struct dsnvm_client_file *file)
{
#define LEN 128
	struct dn_region_info *r;
	unsigned int i;
	char buf[LEN];

	DSNVM_PRINTK("Dump dsnvm client file:");
	DSNVM_PRINTK("  - Filename: %s", file->name);
	DSNVM_PRINTK("  - mmaped DR range: %lu ~ %lu", file->dr_start, file->dr_end);
	for (i = 0; i < DR_PAGE_NR; i++) {
		r = &file->regions[i];
		if (r->dr_no == 0)
			break;

		memset(buf, 0, LEN);
		scnprintf(buf, LEN, "[dro %8d] [dr_no: %5lu] [owner id: %2u]",
			i, r->dr_no, r->owner_id);
		DSNVM_PRINTK("  - %s", buf);
	}
#undef LEN
}
#else
static void dump_dsnvm_file(struct dsnvm_client_file *file) { }
#endif

/**
 * dsnvm_open
 *
 * This function asks CD to open a dsnvm file, create one if the file
 * does not exsit in CD (iff O_CREAT is set). If succeed, CD will reply
 * us with all region infos of the dsnvm file at this moment, and the
 * dsnvm_client_file will be initialized properly. If CD reports failure,
 * the reason why it failed will be printed.
 */
static int dsnvm_open(struct inode *inode, struct file *file)
{
	struct dsnvm_request_open_file request;
	struct dsnvm_reply *reply;
	struct __region_info *region;
	struct dsnvm_client_file *f;
	char buf[DSNVM_MAX_NAME], *cret;
	int ret, reply_len;
	int i, nr_dr, max_nr_dr;

	f = alloc_dsnvm_file();
	if (unlikely(!f)) {
		DSNVM_WARN();
		return -ENOMEM;
	}

	/*
	 * Allocate DSNVM_MAX_REPLY_LEN of reply
	 * to contain all __region_info from CD.
	 */
	reply = alloc_dsnvm_reply();
	if (unlikely(!reply)) {
		ret = -ENOMEM;
		goto out;
	}

	/* Generate request body */
	if (file->f_flags & O_CREAT)
		request.op = DSNVM_OP_OPEN_OR_CREAT;
	else
		request.op = DSNVM_OP_OPEN;

	cret = d_path(&file->f_path, buf, DSNVM_MAX_NAME);
	if (IS_ERR(cret)) {
		ret = PTR_ERR(cret);
		goto out3;
	}
	strncpy(request.name, cret, DSNVM_MAX_NAME);
	strncpy(f->name, cret, DSNVM_MAX_NAME);

	/* Send to CD */
	reply_len = ibapi_send_reply(0, (char *)&request, sizeof(request), (char *)reply);
	if (unlikely(reply_len < sizeof(unsigned int))) {
		DSNVM_WARN();
		ret = -EIO;
		goto out3;
	}

	if (unlikely(reply->status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_WARN("%s", dsnvm_status_string(reply->status));
		switch (reply->status) {
		case DSNVM_OPEN_FILE_FAIL:
			ret = -EFAULT;
			goto out3;
		case DSNVM_OPEN_NON_EXIST_FILE:
			ret = -ENOENT;
			goto out3;
		case DSNVM_CREAT_FILE_FAIL:
			ret = -ENOSPC;
			goto out3;
		default:
			ret = -EIO;
			goto out3;
		}
	}

	/*
	 * Succeed, copy CD replied DR region infos into dsnvm_client_file.
	 *
	 * Note that since we do not support read() and write() on dsnvm file,
	 * and the valid regions are those mmap()'ed one. Hence, we do *not*
	 * queue CD reported DRs into hashtable here, instead, only mmaped
	 * region would be queued at mmap() time.
	 */

	max_nr_dr = ((reply_len - (sizeof(struct dsnvm_reply) - sizeof(struct __region_info *)))
			/ sizeof(struct __region_info));
	nr_dr = reply->nr_dr;
	if (nr_dr > max_nr_dr || nr_dr > DSNVM_MAX_REGIONS) {
		DSNVM_BUG("invalid nr_dr: %u", nr_dr);
		ret = -EFBIG;
		goto out3;
	}

	for (i = 0, region = &reply->base[0]; i < nr_dr; i++, region++) {
		f->regions[i].dr_no = region->dr_no;
		f->regions[i].owner_id = region->owner_id;
		bitmap_copy(f->regions[i].other_dn_list, region->dn_list, DSNVM_MAX_NODE);
	}

	/* Flush all except valid flag */
	dsnvm_flush_buffer(f, sizeof(*f));

	/* After flushing, this file is valid persistent */
	f->valid = FILE_VALID_MAGIC;
	dsnvm_flush_buffer(&f->valid, sizeof(f->valid));

	dump_dsnvm_file(f);

	file->private_data = f;

	free_dsnvm_reply(reply);
	return 0;

out3:
	free_dsnvm_reply(reply);
out:
	free_dsnvm_file(f);

	return ret;
}

/*
 * Note that mmaped data regions are queued into DN hashtable here.
 * Applications are allowed to access pages with those mmaped region only.
 */
static int dsnvm_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct dsnvm_client_file *f = file->private_data;
	struct dn_region_info *dr;
	int dr_index, i, ret;

	DSNVM_PRINTK("[pid %u]: range: [%#016lx - %#016lx]",
		current->pid, vma->vm_start, vma->vm_end);

	/*
	 * It seems that the only entry point of dsnvm_mmap
	 * is at mmap_region. But be paranoid about it, ensure
	 * we are in right context.
	 */
	if (unlikely(!f)) {
		DSNVM_BUG("unknown context");
		return -ENOENT;
	}

	if (vma->vm_pgoff % DR_PAGE_NR) {
		DSNVM_WARN("pgoff is not aligned to region boundary");
		return -EINVAL;
	};

	if (pgoff_to_dr_index(vma->vm_pgoff) >= DSNVM_MAX_REGIONS) {
		DSNVM_WARN("pgoff is too large");
		return -EOVERFLOW;
	}

	f->vma = vma;
	f->vm_start = vma->vm_start;
	f->vm_end = vma->vm_end;
	f->vm_pgoff = vma->vm_pgoff;
	f->vm_flags = vma->vm_flags;

	f->dr_start = pgoff_to_dr_index(vma->vm_pgoff);
	f->dr_end = f->dr_start + (dsnvm_file_pages(f) / DR_PAGE_NR);

	if ((dsnvm_file_pages(f) % DR_PAGE_NR))
		f->partial_end = 1;

	if (f->dr_end >= DSNVM_MAX_REGIONS) {
		DSNVM_WARN("mmaped range exceeds dsnvm file size");
		return -EINVAL;
	}

	/*
	 * If the first operation is read, we mark the NVM page
	 * as read-only. Then we could be notified when this page
	 * is being written to (pfn_mkwrite).
	 *
	 * Because we need this feature no matter what parameters
	 * are passed to open(2) and mmap(2), so we clear RW bit
	 * so all ptes established will be marked as read-only,
	 * if the first op is read. For write first case, we
	 * would set RW bit temporary in page fault.
	 */
	pgprot_val(vma->vm_page_prot) &= ~(pgprotval_t)_PAGE_RW;

	vma->vm_flags |= VM_SHARED;
	vma->vm_flags |= VM_WRITE;
	vma->vm_flags |= VM_PFNMAP;

	for_each_mmaped_region(dr_index, dr, f) {
		if (dr->dr_no == 0) {
			/*
			 * The mmaped range is bigger than the CD reported
			 * file size. So we need to extend this dsnvm file
			 *
			 * Note that we could do this in PF handler, which
			 * could give us a "demand-paging" feeling. But PF
			 * handler is in critical path, so for performance
			 * reasons, we establish everything at mmap() time
			 */
			ret = extend_one_region(f, dr_index);
			if (ret) {
				DSNVM_WARN();
				goto remove;
			}
		}

		ret = ht_add_dn_region(dr);
		if (ret) {
			DSNVM_BUG("dn_region (dr_no: %lu) exist", dr->dr_no);
			goto remove;
		}
	}

	file_accessed(file);
	vma->vm_ops = &dsnvm_vm_ops;

	dump_dsnvm_file(f);

	/*
	 * Note here, we could go though f->regions now, ask each ON
	 * for page mapping info, or even prefetech pages from ON.
	 *
	 * Or, we do nothing here, leave everything to fault handler.
	 */

	return 0;

remove:
	/* Remove previously queued dn regions */
	--dr_index;
	for_each_mmaped_region(i, dr, f) {
		if (i > dr_index)
			break;
		ht_remove_dn_region(dr->dr_no);
	}
	return -EFAULT;
}

/* vfs callback for close */
static int dsnvm_release(struct inode *inode, struct file *file)
{
	struct dsnvm_client_file *f = file->private_data;

	if (unlikely(!f)) {
		DSNVM_WARN("unknown context");
		return 0;
	}

	DSNVM_PRINTK("[pid %u]: close %s", current->pid, f->name);

	/*
	 * Free NVM pages and
	 * try to remove DN_REGION from hashtable
	 */
	free_dn_regions(f);

	free_dsnvm_file(f);
	file->private_data = NULL;

	return 0;
}

static ssize_t dsnvm_read(struct file *file, char __user *buf,
			  size_t len, loff_t *ppos)
{
	DSNVM_PRINTK("dsnvm_read");
	return -EINVAL;
}

static ssize_t dsnvm_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *ppos)
{
	DSNVM_PRINTK("dsnvm_write");
	return -EINVAL;
}

static int dsnvm_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	DSNVM_PRINTK("dsnvm_fsync");
	return 0;
}

const struct file_operations dsnvm_file_ops = {
	.open		= dsnvm_open,
	.release	= dsnvm_release,
	.read		= dsnvm_read,
	.write		= dsnvm_write,
	.mmap		= dsnvm_mmap,
	.fsync		= dsnvm_fsync,
};

const struct file_operations dsnvm_dir_ops = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.iterate	= dcache_readdir,
	.fsync		= noop_fsync,
};
