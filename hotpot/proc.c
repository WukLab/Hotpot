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

/*
 * This file creates /proc/dsnvm which show some runtime info about dsnvm.
 */

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/bitmap.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "dsnvm.h"

/*
 * Use
 * 	echo verbose > /proc/dsnvm
 *
 * to dump all ON_REGION, REPLICA_REGION and xact log info
 * while reading this proc file.
 */
static bool verbose_proc = true;

static void show_log_rec_list(struct seq_file *f)
{
	int i, j;
	unsigned char buf[128];

	seq_printf(f, "\n------ Active Log Info ------\n");

	bitmap_scnlistprintf(buf, 128, logmap_slot, DSNVM_MAX_LOG_RECORDS);
	seq_printf(f, "Active log list:           %s\n", buf);

	spin_lock(&dsnvm_logmap_lock);
	for_each_set_bit(i, logmap_slot, DSNVM_MAX_LOG_RECORDS) {
		struct dsnvm_log_record *log = dsnvm_logmap + i;

		seq_printf(f, "  %3d: log_id = %3d, xact_id = %3d, sender_id = %3d, single_on = %d, nr_areas = %3d, "
			"%s, %s\n", i, log->log_id, log->xact_id, log->sender_id, log->single_on,
			log->nr_areas, log_record_reply_string(log), log_record_phase_string(log));
	
		for (j = 0; j < log->nr_areas; j++) {
			seq_printf(f, "      area[%d]: dr_no: %llu dro: %u\n",
				j, log->meta_for_areas[j].dr_no,
				log->meta_for_areas[j].dro);
		}
	}
	spin_unlock(&dsnvm_logmap_lock);
}

static void show_on_region_list(struct seq_file *f)
{
	int i, j;
	unsigned char buf[64];

	seq_printf(f, "\n------ Owner Region Info ------\n");

	bitmap_scnlistprintf(buf, 128, onmap_slot, DSNVM_MAX_ON_REGION_INFO);
	seq_printf(f, "Owner_Region list:         %s\n", buf);

	/* Print the fist line */
	seq_printf(f, "DR_NO  FLAG  PGX  ");
	for_each_set_bit(i, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		/*    Page-Fetch from remote NODE */
		/* or Page-Fault from myself */
		seq_printf(f, "PF%02d  Commit%02d  Commit-B%02d  ",
			i, i, i);
	}
	seq_printf(f, "\n");

	/* Then each line */
	spin_lock(&dsnvm_onmap_lock);
	for_each_set_bit(i, onmap_slot, DSNVM_MAX_ON_REGION_INFO) {
		struct on_region_info *on = dsnvm_onmap + i;

		seq_printf(f, "%5lu  %#4x  %3d  ",
			on->dr_no, on->flag, atomic_read(&on->nr_pages_in_trasaction));

		for_each_set_bit(j, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
			long bytes, bytes_total;

			seq_printf(f, "%4d  %8d  ",
				atomic_read(&on->nr_page_fetch[j]),
				atomic_read(&on->nr_commit_total[j]));

			bytes = atomic64_read(&on->nr_commit_bytes[j]);
			bytes_total = atomic64_read(&on->nr_commit_bytes_total[j]);

#define PRINT_BYTES(bytes, align)					\
	do {								\
		if (bytes < 1024)					\
			seq_printf(f, "%"#align"ld  B  ", bytes);	\
		else if (bytes < 1024 * 1024)				\
			seq_printf(f, "%"#align"ld KB  ", bytes >> 10);\
		else if (bytes < 1024 * 1024 * 1024)			\
			seq_printf(f, "%"#align"ld MB  ", bytes >> 20);\
		else if (bytes < 1024 * 1024 * 1024)			\
			seq_printf(f, "%"#align"ld GB  ", bytes >> 30);\
	} while (0)

			/* PRINT_BYTES(bytes, 4); */
			PRINT_BYTES(bytes_total, 7);
#undef PRINT_BYTES
		}
		seq_printf(f, "\n");
	}
	spin_unlock(&dsnvm_onmap_lock);
}

static void show_replica_region_list(struct seq_file *f)
{
	int i, j;
	unsigned char buf[64];

	seq_printf(f, "\n------ Replica Region Info ------\n");

	bitmap_scnlistprintf(buf, 128, replicamap_slot, DSNVM_MAX_REPLICA_REGION_INFO);
	seq_printf(f, "Replica_Region list:       %s\n", buf);

	/* Print the fist line */
	seq_printf(f, "Index    DR_NO    FLAG    OWNER_ID    ");
	for_each_set_bit(i, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		/*    Page-Fetch from remote NODE */
		/* or Page-Fault from myself */
		seq_printf(f, "PF-NODE%02d    ", i);
	}
	seq_printf(f, "\n");

	/* Then each line */
	spin_lock(&dsnvm_replicamap_lock);
	for_each_set_bit(i, replicamap_slot, DSNVM_MAX_REPLICA_REGION_INFO) {
		struct replica_region_info *r = dsnvm_replicamap + i;

		seq_printf(f, "%5d    %5lu    %#4x    %8u    ",
			i, r->dr_no, r->flags, r->owner_id);

		for_each_set_bit(j, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
			seq_printf(f, "%9d    ", atomic_read(&r->nr_page_fetch[j]));
		}
		seq_printf(f, "\n");
	}
	spin_unlock(&dsnvm_replicamap_lock);
}

static void show_buddy_allocator_info(struct seq_file *f)
{
	int i;

	seq_printf(f, "\n------ DSNVM Buddy Allocator ------\n");

	seq_printf(f, "nr_total_pages: %lu\n"
		      "nr_free_pages:  %ld\n",
		      buddy->nr_pages,
		      atomic_long_read(&buddy->vm_stat[NR_FREE_DSNVM_PAGES]));

	seq_printf(f, "\n  Free Area lists:\n");
	seq_printf(f, "           nr_free_areas\n");
	for (i = 0; i < DSNVM_MAX_ORDER; i++) {
		struct dsnvm_free_area *free_area= &buddy->free_area[i];
		seq_printf(f, "Order%2d    %13lu\n",
			i, free_area->nr_free);
	}

	seq_printf(f, "\n  PCP Lists:\n");

	seq_printf(f, "         Batch    High    Count\n");
	for_each_online_cpu(i) {
		struct dsnvm_per_cpu_pageset *pageset;
		struct dsnvm_per_cpu_pages *pcp;

		pageset = per_cpu_ptr(buddy->pageset, i);
		pcp = &pageset->pcp;

		seq_printf(f, "CPU%02d    %5d    %4d    %5d\n",
			i, pcp->batch, pcp->high, pcp->count);
	}
}

static int dsnvm_proc_show(struct seq_file *f, void *v)
{
	unsigned long size = dsnvm_nr_pages * DSNVM_PAGE_SIZE;
	unsigned char buf[128];

	if (!size)
		return 0;

	bitmap_scnlistprintf(buf, 128, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);

	seq_printf(f, "Online Clients:            %s\n", buf);
	seq_printf(f, "NR of Online Clients:      %d\n", atomic_read(&nr_client_machines));
	seq_printf(f, "DSNVM Local ID:            %u\n", DSNVM_LOCAL_ID);
	seq_printf(f, "Region size:               %lu MB\n", DR_SIZE >> 20);
	seq_printf(f, "Regions per file:          %u\n", DSNVM_MAX_REGIONS);
	seq_printf(f, "DSNVM file size:           %lu GB\n", DSNVM_MAX_FILE_SIZE >> 30);

	/* Total = Metadata + Usable */
	seq_printf(f, "Total NVM pages:           %ld\n", dsnvm_nr_pages);
	seq_printf(f, "+ NVM pages for metadata:  %ld\n", dsnvm_nr_pages_metadata);
	seq_printf(f, "   -pages for map:         %ld\n", dsnvm_nr_pages_map);
	seq_printf(f, "   -pages for filemap:     %ld\n", dsnvm_nr_pages_filemap);
	seq_printf(f, "   -pages for logmap:      %ld\n", dsnvm_nr_pages_logmap);
	seq_printf(f, "   -pages for onmap:       %ld\n", dsnvm_nr_pages_onmap);
	seq_printf(f, "   -pages for replicamap:  %ld\n", dsnvm_nr_pages_replicamap);

	/* Usable = Busy + Free */
	seq_printf(f, "+ Usable NVM pages:        %ld\n", dsnvm_nr_pages_usable);

#ifdef CONFIG_DSNVM_SWAP
	seq_printf(f, "LRU active pages:          %d\n", atomic_read(&nr_active));
	seq_printf(f, "LRU inactive pages:        %d\n", atomic_read(&nr_inactive));
#endif

	seq_printf(f, "Entries of wait table:     %ld\n", wait_table_hash_nr_entries);
	seq_printf(f, "Bits of wait table:        %ld\n", wait_table_bits);
	seq_printf(f, "Barrier Counter:           %d\n", atomic_read(&BARRIER_COUNTER));

	seq_printf(f, "PFN range:               [ %13lu - %13lu]\n",
		dsnvm_pfn_offset, dsnvm_pfn_offset + dsnvm_nr_pages);
	seq_printf(f, "DSNVM_PFN range:         [ %13lu - %13lu]\n",
		(unsigned long)0, dsnvm_nr_pages);

	seq_printf(f, "Physical range:          [ %#018lx - %#018lx ]\n",
		dsnvm_phys_addr, dsnvm_phys_addr + dsnvm_nr_pages * DSNVM_PAGE_SIZE);
	seq_printf(f, "Virtual range:           [ %#018lx - %#018lx ]\n",
		dsnvm_virt_addr, dsnvm_virt_addr + dsnvm_nr_pages * DSNVM_PAGE_SIZE);

	seq_printf(f, "Transaction Model:         ");
#ifdef DSNVM_MODE_MRSW
	seq_printf(f, "Multiple Readers Single Writer (MRSW)\n");
#else
	seq_printf(f, "Multiple Readers Multiple Writers (MRMW)\n");
#endif

	seq_printf(f, "CPU has PCOMMIT:           %s\n", SUPPORT_PCOMMIT()? "Yes" : "No");
	seq_printf(f, "CPU has CLWB:              %s\n", SUPPORT_CLWB()? "Yes" : "No");
	seq_printf(f, "CPU has CLFLUSH_OPT:       %s\n", SUPPORT_CLFLUSHOPT()? "Yes" : "No");

	seq_printf(f, "DSNVM State:               %s\n", dsnvm_state_string());
	seq_printf(f, "Migration:                 %s\n", enable_migration? "On" : "off");

	/* Now very detailed runtime info */

	if (verbose_proc) {
		show_log_rec_list(f);
		show_replica_region_list(f);
		show_on_region_list(f);
		show_buddy_allocator_info(f);
	} else {
		seq_printf(f, "[Verbose proc disabled, use `echo verbose > /proc/dsnvm` if you desire]\n");
	}

	return 0;
}

static int dsnvm_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, dsnvm_proc_show, NULL);
}

static void __dump_dsnvm_page_content(unsigned long base)
{
	int i, j;
	void *p = (void *)base;

	for (i = 0; i < DSNVM_PAGE_SIZE / 16; i++) {
		printk(KERN_CONT "%p ", p);
		for (j = 0; j < 16; j++) {
			printk(KERN_CONT "%02x ", *(char *)p);
			p++;
		}
		printk(KERN_CONT "\n");
	}
}

static void __dump_on_page(unsigned long dr_no, unsigned int dro)
{
	struct on_region_info *on;
	unsigned long vaddr, pfn;

	on = ht_get_on_region(dr_no);
	if (!on)
		return;

	pfn = on->mapping[dro].local_pfn;
	if (!pfn) {
		DSNVM_BUG();
		return;
	}

	vaddr = pfn_to_dsnvm_virt(pfn);

	__dump_dsnvm_page_content(vaddr);
}

static void __dump_replica_page(unsigned long dr_no, unsigned int dro)
{
	struct replica_region_info *rn;
	unsigned long vaddr, pfn;

	rn = ht_get_replica_region(dr_no);
	if (!rn)
		return;

	pfn = rn->mapping[dro];
	if (!pfn)
		return;

	vaddr = pfn_to_dsnvm_virt(pfn);

	__dump_dsnvm_page_content(vaddr);
}

enum {
	Opt_dbgmask,		/* OP */
	Opt_verbose,		/* OP */
	Opt_dump_pg_d_pfn,	/* OP */
	Opt_migrate,		/* OP */
	Opt_dump_on,		/* OP */
	Opt_dump_on_page,	/* OP */
	Opt_dump_replica,	/* OP */
	Opt_dump_replica_page,	/* OP */
	Opt_free_replica_page,	/* OP */
	Opt_enable_migration,	/* OP */
	Opt_dr_no,
	Opt_nid,
	Opt_dro,
	Opt_err,
};

static const match_table_t tokens = {
	{ Opt_dbgmask,			"dbgmask=%u"		},
	{ Opt_verbose,			"verbose"		},
	{ Opt_dump_pg_d_pfn,		"dump_pg_d_pfn=%u"	},
	{ Opt_migrate,			"migrate"		},
	{ Opt_dump_on,			"dump_on"		},
	{ Opt_dump_on_page,		"dump_on_page"		},
	{ Opt_dump_replica,		"dump_replica"		},
	{ Opt_dump_replica_page,	"dump_replica_page"	},
	{ Opt_free_replica_page,	"free_replica_page"	},
	{ Opt_enable_migration,		"enable_migration=%u"	},
	{ Opt_dr_no,			"dr_no=%u"		},
	{ Opt_nid,			"nid=%u"		},
	{ Opt_dro,			"dro=%u"		},
	{ Opt_err,			NULL			},
};

/*
 * echo dbgmask=1 > /proc/dsnvm
 * 	Change dbgmask to 1
 *
 * echo dump_pg=12340 > /proc/dsnvm
 * 	Dump dsnvm page info of dsnvm_pfn 12340
 *
 * echo dbgmask=64,migrate,dr_no=3,nid=2 > /proc/dsnvm
 *	Change dbgmask to 64, migrate ON chunk dr_no 3 to node 2
 */
static ssize_t dsnvm_proc_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offs)
{
#define MAX_NR_BYTES	64
	int option;
	char *p;
	char *options;
	substring_t args[MAX_OPT_ARGS];

	int new_dbgmask = -1;
	int dump_pg_dsnvm_pfn = -1;
	bool migrate = false;
	bool dump_on = false;
	bool dump_on_page = false;
	bool dump_replica = false;
	bool dump_replica_page = false;
	bool free_replica_page = false;
	int __enable_migration = -1;
	long dr_no = -1;
	int nid = 0, dro = -1;

	if (count > MAX_NR_BYTES)
		return -EINVAL;

	options = kzalloc(count, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	if (copy_from_user(options, buf, count)) {
		kfree(options);
		return -EFAULT;
	}

	/* Blame the parser */
	if (options[count - 1] == '\n')
		options[count - 1] = '\0';

	/* Parse strings */
	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad;
			new_dbgmask = option;
			break;
		case Opt_verbose:
			verbose_proc = true;
			break;
		case Opt_dump_pg_d_pfn:
			if (match_int(&args[0], &option))
				goto bad;
			dump_pg_dsnvm_pfn = option;
			break;
		case Opt_migrate:
			migrate = true;
			break;
		case Opt_dump_on:
			dump_on = true;
			break;
		case Opt_dump_on_page:
			dump_on_page = true;
			break;
		case Opt_dump_replica:
			dump_replica = true;
			break;
		case Opt_dump_replica_page:
			dump_replica_page = true;
			break;
		case Opt_free_replica_page:
			free_replica_page = true;
			break;
		case Opt_enable_migration:
			if (match_int(&args[0], &option))
				goto bad;
			__enable_migration = option;
			break;
		case Opt_dr_no:
			if (match_int(&args[0], &option))
				goto bad;
			dr_no = (long)option;
			if (dr_no < 0)
				goto bad;
			break;
		case Opt_nid:
			if (match_int(&args[0], &option))
				goto bad;
			nid = (int)option;
			if (nid <= 0)
				goto bad;
			break;
		case Opt_dro:
			if (match_int(&args[0], &option))
				goto bad;
			dro = (int)option;
			if (dro < 0 || dro > DR_PAGE_NR)
				goto bad;
			break;
		default:
			pr_err("unknown options: '%s'", p);
			goto free;
		}
	}

	/* Always change dbgmask first if any */
	if (new_dbgmask >= 0) {
		dbgmask = (unsigned int)new_dbgmask;
		pr_info("Change dbgmask to %x", dbgmask);
	}

	if (__enable_migration > 0)
		enable_migration = true;
	else if (__enable_migration == 0)
		enable_migration = false;

	if (dsnvm_pfn_valid(dump_pg_dsnvm_pfn)) {
		struct dsnvm_page *page;

		page = dsnvm_pfn_to_dsnvm_page(dump_pg_dsnvm_pfn);
		dump_dsnvm_page(page, NULL);
		goto done;
	}

	/*
	 * The thing is: only one OP is allowed at one time..
	 */

	/* Do migration explicitly if any */
	if (migrate) {
		if (dr_no == -1 || nid == 0) {
			pr_info("Please provide dr_no & nid");
			goto free;
		}

		if (!test_bit(nid, DSNVM_CLIENT_MACHINES)) {
			pr_info("nid: %u is offline", nid);
			goto free;
		}

		pr_info("migrate_on_chunk: dr_no: %lu, new_owner: %u", dr_no, nid);

		migrate_on_chunk(dr_no, nid);
		goto done;
	}

	if (dump_on) {
		if (dr_no == -1) {
			pr_info("Please provide dr_no");
			goto free;
		}

		dump_on_region_info(dr_no);
		goto done;
	}

	if (dump_on_page) {
		if (dr_no == -1 || dro == -1) {
			pr_info("Please provide dr_no & dro");
			goto free;
		}

		__dump_on_page(dr_no, dro);
		goto done;
	}

	if (dump_replica) {
		if (dr_no == -1) {
			pr_info("Please provide dr_no");
			goto free;
		}

		dump_replica_region_info(dr_no);
		goto done;
	}

	if (dump_replica_page) {
		if (dr_no == -1 || dro == -1) {
			pr_info("Please provide dr_no & dro");
			goto free;
		}

		__dump_replica_page(dr_no, dro);
		goto done;
	}

	if (free_replica_page) {
		if (dr_no == -1 || dro == -1) {
			pr_info("Please provide dr_no & dro");
			goto free;
		}

		proc_free_replica_page_notify_on(dr_no, dro);
		goto done;
	}

done:
	kfree(options);
	return count;

bad:
	pr_err("bad value '%s' for '%s'", args[0].from, p);
free:
	kfree(options);
	return -EINVAL;
#undef MAX_NR_BYTES
}

static const struct file_operations dsnvm_proc_fops = {
	.open		=	dsnvm_proc_open,
	.read		=	seq_read,
	.write		=	dsnvm_proc_write,
	.llseek		=	seq_lseek,
	.release	=	single_release
};

int create_dsnvm_proc_file(void)
{
	proc_create("dsnvm", 0, NULL, &dsnvm_proc_fops);
	create_dsnvm_stat_file();
	return 0;
}

void remove_dsnvm_proc_file(void)
{
	remove_dsnvm_stat_file();
	remove_proc_entry("dsnvm", NULL);
}
