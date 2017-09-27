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

#ifndef _INCLUDE_DSNVM_STAT_H_
#define _INCLUDE_DSNVM_STAT_H_

/*
 * Lightweight percpu counter for DSNVM.
 *
 * Counters should only be incremented.
 * Counters are handled completely inline.
 */

enum dsnvm_event_item {
	__VM_FORMAT_LINE__,
	DSNVM_PAGE_FETCH_RETRY,
	DSNVM_PGFAULT,
	DSNVM_PGFAULT_READ,
	DSNVM_PGFAULT_WRITE,
	DSNVM_PGFAULT_CONCURRENT,
	DSNVM_GET_FAULTING_PAGE_RUN,

	/*
	 * Retry in page-fault handler.
	 * Due to the migration case where a previous remote
	 * ON_REGION was migrated to this node. And the fault
	 * happens before the final notify.
	 */
	DSNVM_PF_RARE_RETRY,

	DSNVM_LOCAL_OWNER_FAULT,
	DSNVM_LOCAL_REPLICA_FAULT,
	DSNVM_REMOTE_FAULT,
	DSNVM_REMOTE_FAULT_NON_COHERENT,
	DSNVM_REMOTE_FAULT_COHERENT,

	DSNVM_COW,
	DSNVM_OWNER_COW,
	DSNVM_REPLICA_COW,
	DSNVM_COHERENCE_COW,
	DSNVM_CONCURRENT_COW,

	/* Replica Ralted */
	__REPLICA_FORMAT_LINE__,
	DSNVM_REPLICA_REGION_CREATED,

	/* ON Realted */
	__ON_FORMAT_LINE__,
	DSNVM_OWNER_REGION_CREATED,
	DSNVM_OWNER_REMOTE_PAGE_FETCH,
	DSNVM_OWNER_REMOTE_PAGE_FETCH_NON_COHERENT,
	DSNVM_OWNER_REMOTE_PAGE_FETCH_COHERENT,

	/* Swap Related */
	__SWAP_FORMAT_LINE__,
	DSNVM_KSWAPD_RUN,
	DSNVM_DIRECT_RUN,

	DSNVM_PGRECLAIM_KSWAPD,
	DSNVM_PGRECLAIM_DIRECT,
	DSNVM_PGRECLAIM_REPLICA,

	DSNVM_PGACTIVATE,
	DSNVM_PGDEACTIVATE,

	/* IB Related */
	__IB_FORMAT_LINE__,
	DSNVM_IB_REQUESTS,
	DSNVM_IB_SEND_REQ,
	DSNVM_IB_SEND_REPLY_OPT_REQ,
	DSNVM_IB_SEND_REPLY_REQ,
	DSNVM_IB_ATOMIC_SEND_REQ,
	DSNVM_IB_BYTES,
	DSNVM_IB_FALSE_REQUEST_LEN,

	/* Transaction Related */
	__XACT_FORMAT_LINE__,

	/* nr_commit = mrsw+mrmw+atomic */
	DSNVM_XACT_COMMIT,
	DSNVM_XACT_MRSW_COMMIT,
	DSNVM_XACT_MRMW_COMMIT,
	DSNVM_XACT_ATOMIC_COMMIT,

	/* nr_commit = fail+retry+succeed */
	DSNVM_XACT_COMMIT_FAIL,
	DSNVM_XACT_COMMIT_RETRY,
	DSNVM_XACT_COMMIT_SUCCEED,

	DSNVM_XACT_BEGIN,
	DSNVM_XACT_MRSW_BEGIN,
	DSNVM_XACT_MRMW_BEGIN,
	DSNVM_XACT_BEGIN_RETRY,
	DSNVM_XACT_BEGIN_SUCCEED,

	DSNVM_XACT_REVERT_TX,
	DSNVM_XACT_REVERT_RX,

	/* nr_mrmw = nr_0+nr_1+nr_N */
	DSNVM_MRMW_REMOTE_ON_0,
	DSNVM_MRMW_REMOTE_ON_1,
	DSNVM_MRMW_REMOTE_ON_N,
	DSNVM_MRMW_REMOTE_ON_N_RX,

	/*
	 * Remote page-fetch request is blocked because
	 * the ON_REGION page is under committing.
	 */
	DSNVM_XACT_BLOCK_PAGE_FETCH,

	/*
	 * MRSW always use single_on 3-phase to commit even
	 * if there are more than 1 ON involved.
	 * MRMW only use single_on 3-phase when there is 1 ON
	 */
	DSNVM_SINGLE_REMOTE_ON_XACT_TX,
	DSNVM_SINGLE_REMOTE_ON_XACT_RX,

	/* Remote commit request is blocked because the ON_REGION
	 * is being migrated out. */
	DSNVM_XACT_REJECT_DUE_TO_MIGRATION,
	DSNVM_XACT_REJECT_DUE_TO_BLOCKED_PAGES,

	/* xact phase2 coherence/replication */
	DSNVM_COHERENCE_TX,
	DSNVM_COHERENCE_RX,
	DSNVM_COHERENCE_NR_UPDATED_PAGES,

	DSNVM_REPLICATION_TX,
	DSNVM_REPLICATION_RX,

	/*
	 * nr of times that rep_degree can not be meet by
	 * DNs alone, where phase 2 has to choose other nodes
	 * to make extra replicas, to meet user defined rep_degree.
	 */
	DSNVM_REPLICATION_NEED_EXTRA,

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	DSNVM_MRSW_MASTER_COMMIT,
	DSNVM_MRSW_MASTER_BEGIN,
	DSNVM_MRSW_MASTER_BEGIN_RETRY,
	DSNVM_MRSW_MASTER_BEGIN_FAIL,
	DSNVM_MRSW_MASTER_BEGIN_SUCCEED,
#endif

	/* Migration Related */
	__MIGRATE_FORMAT_LINE__,

	/* Migration Related */
	DSNVM_MIGRATED_RUN,

	DSNVM_NR_REGION_MIGRATED_OUT,
	DSNVM_NR_PAGES_MIGRATED_OUT,

	DSNVM_NR_REGION_MIGRATED_IN,
	DSNVM_NR_PAGES_MIGRATED_IN,

	DSNVM_MIGRATE_REJECTED_BY_COST,
	DSNVM_MIGRATE_REJECTED_BY_COMMIT,

	__NR_DSNVM_EVENT_ITEMS
};

struct dsnvm_event_state {
	unsigned long event[__NR_DSNVM_EVENT_ITEMS];
};

#define DSNVM_EVENT_COUNTERS
#ifdef DSNVM_EVENT_COUNTERS

DECLARE_PER_CPU(struct dsnvm_event_state, dsnvm_event_states);

static inline void __count_dsnvm_event(enum dsnvm_event_item item)
{
	__this_cpu_inc(dsnvm_event_states.event[item]);
}

static inline void count_dsnvm_event(enum dsnvm_event_item item)
{
	this_cpu_inc(dsnvm_event_states.event[item]);
}

static inline void __count_dsnvm_events(enum dsnvm_event_item item, long delta)
{
	__this_cpu_add(dsnvm_event_states.event[item], delta);
}

static inline void count_dsnvm_events(enum dsnvm_event_item item, long delta)
{
	this_cpu_add(dsnvm_event_states.event[item], delta);
}

void create_dsnvm_stat_file(void);
void remove_dsnvm_stat_file(void);

#else
/* Disable counters */
static inline void __count_dsnvm_event(enum dsnvm_event_item item)
{
}
static inline void count_dsnvm_event(enum dsnvm_event_item item)
{
}
static inline void __count_dsnvm_events(enum dsnvm_event_item item, long delta)
{
}
static inline void count_dsnvm_events(enum dsnvm_event_item item, long delta)
{
}
void create_dsnvm_stat_file(void)
{
}
void remove_dsnvm_stat_file(void)
{
}
#endif /* DSNVM_EVENT_COUNTERS */
#endif /* _INCLUDE_DSNVM_STAT_H_ */
