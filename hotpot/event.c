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

#include <linux/cpu.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>

#include "dsnvm.h"

#ifdef DSNVM_EVENT_COUNTERS

const char *const dsnvm_event_text[] = {
	/* VM stats */
	"------ VM Stats ------",
	"nr_page_fetch_retry",
	"pgfault (total)",
	"pgfault (read)",
	"pgfault (write)",
	"pgfault (concurrent)",
	"get faulting page",

	"pgfault retry due to remote ON migration",

	"local ON fault",
	"local RN fault",
	"remote fault (total)",
	"remote fault (non-coherent)",
	"remote fault (coherent)",

	"cow (total)",
	"cow (onwer)",
	"cow (replica)",
	"cow (coherent)",
	"cow (concurrent)",

	/* RN Related */
	"------ Replica ------",
	"REPLICA_REGION created",

	/* ON Related */
	"------ ON ------",
	"ON_REGION created",
	"page-fetch (total)",
	"page-fetch (non-coherent)",
	"page-fetch (coherent)",

	/* Swap Related */
	"------ Swap ------",
	"kswapdrun",
	"directrun",

	"pgreclaim_kswapd",
	"pgreclaim_direct",
	"pgreclaim_replica",

	"pgactivate",
	"pgdeactivate",

	/* IB Related */
	"------ IB ------",
	"IB Requests (total)",
	"IB Requests (send)",
	"IB Requests (send_reply_opt)",
	"IB Requests (send_reply)",
	"IB Requests (atomic_send)",
	"IB Bytes",
	"IB nr of false request len",

	/* XACT Related */
	"------ XACT ------",
	"nr_commit",
	"nr_mrsw_commit",
	"nr_mrmw_commit",
	"nr_atomic_commit",

	"nr_commit_failed",
	"nr_commit_retry",
	"nr_commit_succeed",

	"nr_begin",
	"nr_mrsw_begin",
	"nr_mrmw_begin",
	"nr_begin_retry",
	"nr_begin_succeed",

	"nr_revert_tx",
	"nr_revert_rx",

	"nr_mrmw_commit_remote_ON_0",
	"nr_mrmw_commit_remote_ON_1",
	"nr_mrmw_commit_remote_ON_N",
	"nr_mrmw_commit_remote_ON_N_RX",

	"nr_page-fetch_blocked_by_xact",

	"nr_single_ON_xact_tx",
	"nr_single_ON_xact_rx",

	/* Rejections to remote xact commit to this local ON */
	"nr_xact_reject_due_to_migration",
	"nr_xact_reject_due_to_blocked_page",

	"nr_coherence_tx",
	"nr_coherence_rx",
	"nr_coherence_updated_pages",

	"nr_replication_tx",
	"nr_replication_rx",
	"nr_replication_need_extra",

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	"nr_mrsw_master_commit",
	"nr_mrsw_master_begin",
	"nr_mrsw_master_begin_retry",
	"nr_mrsw_master_begin_fail",
	"nr_mrsw_master_begin_succeed",
#endif

	/* Migration Related */
	"------ Migration ------",
	"migratedrun",
	"nr_regions_migrated_out",
	"nr_pages_migrated_out",
	"nr_regions_migrated_in",
	"nr_pages_migrated_in",
	"migration_rejected_by_cost",
	"migration_rejected_by_commit_bytes",
};

DEFINE_PER_CPU(struct dsnvm_event_state, dsnvm_event_states) = {{0}};

static void sum_dsnvm_events(unsigned long *ret)
{
	int cpu, i;
	struct dsnvm_event_state *this;

	memset(ret, 0, __NR_DSNVM_EVENT_ITEMS * sizeof(unsigned long));

	for_each_online_cpu(cpu) {
		this = &per_cpu(dsnvm_event_states, cpu);
		for (i = 0; i < __NR_DSNVM_EVENT_ITEMS; i++)
			ret[i] += this->event[i];
	}
}

/*
 * Accumulate the dsnvm event counters across all CPUs.
 * The result is unavoidably approximate - it can change
 * during and after execution of this function.
 */
void all_dsnvm_events(unsigned long *ret)
{
	get_online_cpus();
	sum_dsnvm_events(ret);
	put_online_cpus();
}

static void *dsnvm_stat_start(struct seq_file *m, loff_t *pos)
{
	unsigned long *v;

	if (*pos >= ARRAY_SIZE(dsnvm_event_text))
		return NULL;

	v = kmalloc(__NR_DSNVM_EVENT_ITEMS * sizeof(unsigned long), GFP_KERNEL);
	m->private = v;
	if (!v)
		return ERR_PTR(-ENOMEM);

	all_dsnvm_events(v);

	return (unsigned long *)m->private + *pos;
}

static void *dsnvm_stat_next(struct seq_file *m, void *arg, loff_t *pos)
{
	(*pos)++;
	if (*pos >= ARRAY_SIZE(dsnvm_event_text))
		return NULL;
	return (unsigned long *)m->private + *pos;
}

static int dsnvm_stat_show(struct seq_file *m, void *arg)
{
	unsigned long *l = arg;
	unsigned long off = l - (unsigned long *)m->private;

	seq_printf(m, "%s: %lu\n", dsnvm_event_text[off], *l);
	return 0;
}

static void dsnvm_stat_stop(struct seq_file *m, void *arg)
{
	kfree(m->private);
	m->private = NULL;
}

static const struct seq_operations dsnvm_stat_op = {
	.start	= dsnvm_stat_start,
	.next	= dsnvm_stat_next,
	.stop	= dsnvm_stat_stop,
	.show	= dsnvm_stat_show
};

static int dsnvm_stat_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dsnvm_stat_op);
}

static const struct file_operations dsnvm_stat_file_operations = {
	.open		= dsnvm_stat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

void create_dsnvm_stat_file(void)
{
	proc_create("dsnvm-event", S_IRUGO, NULL, &dsnvm_stat_file_operations);
}

void remove_dsnvm_stat_file(void)
{
	remove_proc_entry("dsnvm-event", NULL);
}

#endif /* DSNVM_EVENT_COUNTERS */
