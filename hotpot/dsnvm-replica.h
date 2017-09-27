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
 * This file describes definitions for replica handling.
 */

#ifndef _INCLUDE_DSNVM_REPLICA_H_
#define _INCLUDE_DSNVM_REPLICA_H_

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct replica_region_info {
	unsigned long		dr_no;
	unsigned int		owner_id;
	unsigned int		flags;

	/* Lock to protect each page's mapping */
	spinlock_t		page_lock[DR_PAGE_NR];
	unsigned long		mapping[DR_PAGE_NR];

	/* A counter for page-fetch events from DNs or self page-fault */
	atomic_t		nr_page_fetch[DSNVM_MAX_NODE];

	spinlock_t		region_lock;
	struct kref		region_ref;
	struct hlist_node	hlist;
};

#define _REPLICA_IN_MIGRATION_CONTEXT	0

#define REPLICA_IN_MIGRATION_CONTEXT	(1U << _REPLICA_IN_MIGRATION_CONTEXT)

static inline void replica_region_set_flag(struct replica_region_info *r,
					   unsigned int flagbit)
{
	set_bit(flagbit, (unsigned long *)&r->flags);
}

static inline void replica_region_clear_flag(struct replica_region_info *r,
					     unsigned int flagbit)
{
	clear_bit(flagbit, (unsigned long *)&r->flags);
}

static inline int replica_region_test_flag(struct replica_region_info *r,
					   unsigned int flagbit)
{
	return test_bit(flagbit, (unsigned long *)&r->flags);
}

static inline void
set_dsnvm_page_rr_info(struct dsnvm_page *page, struct replica_region_info *rr)
{
	if (likely(DSNVM_PageReplica(page))) {
		set_dsnvm_page_private(page, (unsigned long)rr);
		DSNVM_SetPagePrivate(page);
	}
}

static inline void
clear_dsnvm_page_rr_info(struct dsnvm_page *page)
{
	if (likely(DSNVM_PageReplica(page) && DSNVM_PagePrivate(page))) {
		set_dsnvm_page_rr_info(page, 0);
		DSNVM_ClearPagePrivate(page);
		return;
	}
	dump_dsnvm_page(page, "invalid page state (1)");
}

static inline struct replica_region_info *
dsnvm_page_rr_info(struct dsnvm_page *page)
{
	if (likely(DSNVM_PageReplica(page) && DSNVM_PagePrivate(page)))
		return (void *)(page->private);
	dump_dsnvm_page(page, "invalid page state (2)");
	return NULL;
}

static inline int replica_page_shared(struct dsnvm_page *page)
{
	WARN_ON_ONCE(!DSNVM_PageReplica(page));
	return dsnvm_page_mapped(page);
}

int ht_add_replica_region(struct replica_region_info *);
int ht_remove_replica_region(unsigned long dr_no);
struct replica_region_info *ht_get_replica_region(unsigned long dr_no);
void ht_put_replica_region(struct replica_region_info *);
void free_all_replica_regions(void);

void proc_free_replica_page_notify_on(unsigned long dr_no, unsigned int dro);
int free_replica_page_notify_on(struct dsnvm_page *);

int dsnvm_handle_receive_replica(int node_id, int nr_reqs, struct atomic_struct *reqs, char *output_buf, unsigned int *output_size);

void dump_replica_region_info(unsigned long dr_no);

struct replica_region_info *find_or_alloc_replica(unsigned long dr_no,
						  unsigned int owner_id);

/**
 * REGION_IS_REPLICA
 * @dri: dn_region_info
 *
 * Check if a region is a local replica region
 */
#define REGION_IS_REPLICA(dri)								\
({											\
	struct replica_region_info *__rr;						\
	bool answer = false;								\
	__rr = ht_get_replica_region(dri->dr_no);					\
	if (__rr) {									\
		answer = !replica_region_test_flag(__rr, _REPLICA_IN_MIGRATION_CONTEXT);\
		ht_put_replica_region(__rr);						\
	}										\
	answer;										\
})

#endif /* _INCLUDE_DSNVM_REPLICA_H_ */
