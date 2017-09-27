/*
 * Distributed Shared NVM
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes definitions used by Owner Nodes (ON).
 */

#ifndef _INCLUDE_DSNVM_ON_H_
#define _INCLUDE_DSNVM_ON_H_

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct on_page_info {
	int			if_blocked_by_commit_xact;
	unsigned long		local_pfn;

	/* Coherent/committed DNs */
	DECLARE_BITMAP(dn_list, DSNVM_MAX_NODE);
};

#define NR_RECORD_HOTTEST_NODE	2

struct on_region_info {
	unsigned long		dr_no;
	unsigned int		flag;

	/* Count nr of pages in xact, for migration checking */
	atomic_t		nr_pages_in_trasaction;

	/* Lock to protect each page's mapping */
	spinlock_t		page_lock[DR_PAGE_NR];
	struct on_page_info	mapping[DR_PAGE_NR];

	/* A counter for page-fetch events from DNs or self page-fault */
	atomic_t		nr_page_fetch[DSNVM_MAX_NODE];

	/*
	 * Commit events from DNs or self in current time window.
	 * Updated from transaction, cleared by hrtimer.
	 */
	atomic_t		nr_commit[DSNVM_MAX_NODE];

	/*
	 * Total commit events form DNs or self.
	 * Updated by hrtimer only
	 */
	atomic_t		nr_commit_total[DSNVM_MAX_NODE];

	atomic64_t		nr_commit_bytes[DSNVM_MAX_NODE];
	atomic64_t		nr_commit_bytes_total[DSNVM_MAX_NODE];

	/*
	 * Record for the hottest node in the last
	 * @NR_RECORD_HOTTEST_NODE time windows.
	 * (Similar to branch history prediction n-bit counter)
	 *
	 * record_hottest[i] = 0 means this previous time-window
	 * does not count. Maybe due to a very low throughput.
	 */
	unsigned int		record_hottest[NR_RECORD_HOTTEST_NODE];

	spinlock_t		region_lock;
	struct kref		region_ref;
	struct hlist_node	hlist;
};

#define _ON_REGION_MIGRATING_OUT	0
#define _ON_REGION_MIGRATING_IN		1

#define ON_REGION_MIGRATING_OUT		(1U << _ON_REGION_MIGRATING_OUT)
#define ON_REGION_MIGRATING_IN		(1U << _ON_REGION_MIGRATING_IN)

/* Helpers to mark/clear ON_REGION migration status: */
static inline int is_on_region_migrating_out(struct on_region_info *on)
{
	return on->flag & ON_REGION_MIGRATING_OUT;
}

static inline int is_on_region_migrating_in(struct on_region_info *on)
{
	return on->flag & ON_REGION_MIGRATING_IN;
}

static inline void mark_on_region_migrating_out(struct on_region_info *on)
{
	on->flag |= ON_REGION_MIGRATING_OUT;
}

static inline void mark_on_region_migrating_in(struct on_region_info *on)
{
	on->flag |= ON_REGION_MIGRATING_IN;
}

static inline void clear_on_region_migrating_in(struct on_region_info *on)
{
	on->flag &= ~ON_REGION_MIGRATING_IN;
}

/* Helpers to manipulate nr_pages_in_trasaction of ON_REGION: */
static inline void inc_pages_in_transaction(struct on_region_info *on)
{
	atomic_inc(&on->nr_pages_in_trasaction);
}

static inline void dec_pages_in_transaction(struct on_region_info *on)
{
	atomic_dec(&on->nr_pages_in_trasaction);
}

static inline bool is_on_region_in_transaction(struct on_region_info *on)
{
	return (atomic_read(&on->nr_pages_in_trasaction) > 0)? true : false;
}

/* An ON_PAGE is shared if it has some mapping attached: */
static inline int on_page_shared(struct dsnvm_page *page)
{
	return dsnvm_page_mapped(page);
}

int __must_check ht_add_on_region(struct on_region_info *new);
int remove_on_region(unsigned long dr_no);
struct on_region_info *ht_get_on_region(unsigned long dr_no);
void put_on_region(struct on_region_info *r);
void free_all_on_regions(void);
void on_remove_coherent_node(unsigned long dr_no, unsigned int dro, unsigned int node);

struct page_fetch_failed_reason {
	int reason;
	unsigned int new_owner;
};

int handle_page_fetch(char *, unsigned long *, unsigned int *, int, bool);
int handle_create_region_at_on(struct dsnvm_request *, char *, unsigned int *, int);
int handle_remove_region_at_on(struct dsnvm_request *, char *, unsigned int *, int);

void dump_on_region_info(unsigned long dr_no);

struct on_region_info *find_or_alloc_on_region(unsigned long dr_no);

int alloc_pff_reason_array(void);
void free_pff_reason_array(void);


#endif /* _INCLUDE_DSNVM_ON_H_ */
