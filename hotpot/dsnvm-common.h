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
 * BIG FAT NOTE:
 *
 * This file including definitions used by both client and server.
 * Everthing should be totally generic, which means we can NOT have
 * any kernel related types, labels or func here.
 */

#ifndef _INCLUDE_DSNVM_COMMON_H_
#define _INCLUDE_DSNVM_COMMON_H_

/**
 * MRSW or MRMW mode bit
 * Comment this out to disable MRSW:
 */
#if 0
# define DSNVM_MODE_MRSW
# define DSNVM_MODE_MRSW_IN_KERNEL
#endif

/* MRSW Master Node Number */
#ifdef DSNVM_MODE_MRSW_IN_KERNEL
# define DSNVM_MRSW_MASTER_NODE		1
#endif

enum {
	XACT_MRMW,
	XACT_MRSW,
};

#ifdef DSNVM_MODE_MRSW
# define XACT_MODE		XACT_MRSW
#else
# define XACT_MODE		XACT_MRMW
#endif

/* Maximum number of nodes dsnvm support */
#define DSNVM_MAX_NODE			24

/* Maximum length of dsnvm filename */
#define DSNVM_MAX_NAME			128

/**
 * This shift determins the size of a data region (4KB pages):
 * ...
 * 1<<14:	2^14 * 4KB = 64  MB
 * 1<<13:	2^13 * 4KB = 32  MB
 * 1<<12:	2^12 * 4KB = 16  MB
 * 1<<11:	2^11 * 4KB = 8   MB
 * 1<<10:	2^10 * 4KB = 4   MB
 * 1<<9 :	2^9  * 4KB = 2   MB
 * 1<<8 :	2^8  * 4KB = 1   MB
 * ...
 */
#define DR_PAGE_NR_SHIFT		10
#define DR_PAGE_NR			(1<<DR_PAGE_NR_SHIFT)
#define DR_SIZE				(DR_PAGE_NR*DSNVM_PAGE_SIZE)

/*
 * This shift determins the maximum size of dsnvm file:
 * FILE_SIZE = 2^(12 + DR_PAGE_NR_SHIFT + DSNVM_MAX_REGIONS_SHIFT)
 */
#define DSNVM_MAX_REGIONS_SHIFT		11
#define DSNVM_MAX_REGIONS		(1<<DSNVM_MAX_REGIONS_SHIFT)
#define DSNVM_MAX_FILE_SIZE		(DSNVM_MAX_REGIONS*DR_SIZE)

/* Maximum number of opened files */
#define NR_DSNVM_FILE			5

/* x86 */
#define CACHELINE_SIZE			(64)
#define CLINE_SHIFT			(6)
#define CACHELINE_MASK  		(~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) 		(((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

#define DSNVM_PAGE_SHIFT		12
#define DSNVM_PAGE_SIZE			(1UL << DSNVM_PAGE_SHIFT)
#define DSNVM_PAGE_MASK			(~(DSNVM_PAGE_SIZE - 1))

/* Maximum length of messages */
#define DSNVM_MAX_REQUEST_LEN		(DSNVM_PAGE_SIZE << 1)
#define DSNVM_MAX_REPLY_LEN		(DSNVM_PAGE_SIZE << 1)

/* Retry to begin transaction */
#define DSNVM_RETRY			((int)(~0U>>1))

/* Maximum msgs in one ibapi atomic call */
#define MAX_ATOMIC_SEND_NUM		4096

enum DSNVM_REQUEST_OPS {		/* From->To; Type; Description; More */
	DSNVM_OP_INVALID,		/* Empty, invalid operation */
	DSNVM_OP_OPEN,			/* DN->CD; Send_Reply; Open a file; Failed if file does not exist */
	DSNVM_OP_OPEN_OR_CREAT,		/* DN->CD; Send_Reply; Open a file; Create one if file does not exist */
	DSNVM_OP_CREAT_REGION_AT_ON,	/* CD->ON; Send_Reply; Create a region; ON will create a region if it does not exist */
	DSNVM_OP_REMOVE_REGION_AT_ON,	/* CD->ON; Send_Reply; Remove a region; ON will remove a region if it already exist */
	DSNVM_OP_EXTEND_ONE_REGION,	/* DN->CD; Send_Reply; DN ask CD to extend the dsnvm file size */
	DSNVM_OP_BEGIN_XACT,		/* DN->CD; Send_reply; DN asks CD if a xact can begin in the case of MRSW */ 
	DSNVM_OP_REQUEST_COMMIT_XACT,	/* DN->ON; Atomic_Send_Reply; DN sends xact data and request to start commit the xact to ON */
	DSNVM_OP_COMMIT_XACT,		/* DN->ON; Atomic_Send; DN asks ON to actually commit the xact */
	DSNVM_OP_ACK_COMMIT_XACT,	/* DN->ON; Send; DN tells ON that xact commit finished */
	DSNVM_OP_ACK_COMMIT_XACT_REVERT,
	DSNVM_OP_COMMIT_XACT_SINGLE_ON,	/* DN->ON; Atomic_Send; DN tells the only ON to commit a xact */
	DSNVM_OP_SEND_COHERENCE_XACT,	/* ON->DN; Atomic_Send_Reply; ON pushes coherence update to DNs during xact commit */
	DSNVM_OP_SEND_REPLICA_XACT,	/* ON->DN; Atomic_Send_Reply; ON pushes redundant copies to DNs during xact commit */
	DSNVM_OP_LOOKUP_OWNER,		/* DN/ON->CD; Send_Reply; Ask a region's information */
	DSNVM_OP_FETCH_PAGE,		/* DN->ON; Send_Reply; Fetch a page from ON, and ON do not need to mark this DN coherent*/
	DSNVM_OP_FETCH_PAGE_COHERENT,	/* DN->ON; Send_Reply; Fetch a page from ON, and ON must mark this DN coherent  */
	DSNVM_OP_UPDATE_STATE_PADDR_FOR_DRO,
	DSNVM_OP_MRSW_BEGIN_XACT,	/* DN->CD; MRSW asking to begin a xact */
	DSNVM_OP_MRSW_COMMIT_XACT,	/* DN->CD; MRSW asking to commit a xact */
	DSNVM_OP_SEND_MACHINE_JOIN,	/* DN/ON->CD; Send_Reply */
	DSNVM_OP_SEND_MACHINE_LEAVE,	/* DN/ON->CD; Send_Reply */
	DSNVM_OP_RECEIVE_MACHINE_JOIN,	/* CD->DN/ON; Send_Reply */
	DSNVM_OP_RECEIVE_MACHINE_LEAVE,	/* CD->DN/ON; Send_Reply */
	DSNVM_OP_FREE_REPLICA_PAGE,	/* DN->ON; Send_Reply */
	DSNVM_OP_SYNC_BARRIER,		/* dist synchronization barrier */
	DSNVM_OP_MMAP_CONSENSUS,	/* to gain a consensus on mmap starting address */
	DSNVM_OP_MIGRATE_ON_CHUNK,	/* ON->DN; ON is migrating a chunk to DN */
	DSNVM_OP_MIGRATE_ON_CHUNK_NO_PAGE, /* ON->DN; ON is migrating a chunk to DN, and this DN has all pages already */
	DSNVM_OP_MIGRATE_ON_CHUNK_NOTIFY, /* ON->DN/CD; Notify a completion of migration */

	DSNVM_OP_FETCH_COMMITTED_DN_PAGE,
	DSNVM_OP_NOTIFY_PROMOTED_NEW_ON,

	DSNVM_OP_TEST,

	__NR_DSNVM_REQUEST_OPS
};

enum DSNVM_REPLY_STATUS {
	DSNVM_INVALID_OP,
	DSNVM_REPLY_SUCCESS,
	DSNVM_REPLY_INVALID,
	DSNVM_REPLY_LOG_FULL,
	DSNVM_REPLY_PAGE_IN_OTHER_XACT,
	DSNVM_REPLY_ON_REGION_MIGRATING_OUT,
	DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA,
	DSNVM_EINVAL,
	DSNVM_EPERM,
	DSNVM_EBUSY,
	DSNVM_EEXIST,
	DSNVM_ENOMEM,
	DSNVM_ENOREGION,
	DSNVM_ENOENT,
	DSNVM_OPEN_NON_EXIST_FILE,
	DSNVM_OPEN_FILE_FAIL,
	DSNVM_CREAT_FILE_FAIL,
	DSNVM_ON_MIGRATED_TO_NEW_OWNER,		/* ON reports that region was migrated out */
	DSNVM_NONEXIST_DR_NO,			/* ON reports non-exist DR_NO */
	DSNVM_INVALID_DRO,			/* ON reports invalid DRO */
	DSNVM_ON_PAGE_NOT_MAPPED,		/* ON reports a non-mapping page */
	DSNVM_CANNOT_MAKE_ENOUGH_REPLICA,
	DSNVM_COMMIT_XACT_ERROR,
	DSNVM_REQUEST_COMMIT_XACT_ERROR,
	DSNVM_NO_DATA_IN_REQUEST,
	DSNVM_REQ_AREA_DONT_MACTH,
	DSNVM_REPLY_FAIL_TO_MERGE,
	DSNVM_REPLY_KEEP_REPLICA_PAGE,
	DSNVM_REPLY_NO_LOG,
	DSNVM_REPLY_BUG,

	__NR_DSNVM_REPLY_STATUS
};


static inline char *dsnvm_status_string(unsigned int status)
{
	switch (status) {
	case DSNVM_NO_DATA_IN_REQUEST:		return "No data requests in commit xact";
	case DSNVM_REQ_AREA_DONT_MACTH:		return "nr_areas != (nr_reqs - 2)";
	case DSNVM_INVALID_OP:			return "Invalid operation";
	case DSNVM_REPLY_SUCCESS:		return "Operation succeed";
	case DSNVM_REPLY_INVALID:		return "Invalid parameters";
	case DSNVM_EPERM:			return "Operation not permitted";
	case DSNVM_EBUSY:			return "ON/CD reports resource busy";
	case DSNVM_EEXIST:			return "ON/CD reports file/region exists";
	case DSNVM_ENOMEM:			return "Out of memory";
	case DSNVM_ENOREGION:			return "ON reports so such region";
	case DSNVM_ENOENT:			return "CD reports no such file";
	case DSNVM_OPEN_NON_EXIST_FILE:		return "CD reports that dsnvm file does not exist";
	case DSNVM_OPEN_FILE_FAIL:		return "CD fail to open dsnvm file (without O_CREAT)";
	case DSNVM_CREAT_FILE_FAIL:		return "CD fail to create dsnvm file (with O_CREAT)";
	case DSNVM_ON_MIGRATED_TO_NEW_OWNER:	return "ON Region was migrated to another node";
	case DSNVM_NONEXIST_DR_NO:		return "ON reports non-exsit DR_NO";
	case DSNVM_INVALID_DRO:			return "ON reports invalid DRO (> DR_PAGE_NR) or might be partial region";
	case DSNVM_ON_PAGE_NOT_MAPPED:		return "ON reports a request into non-mapped NVM page (bug/eviction)";
	case DSNVM_CANNOT_MAKE_ENOUGH_REPLICA:	return "ON cannot make enough replicas at commit phase 4";
	case DSNVM_COMMIT_XACT_ERROR:		return "ON phase 2 commit error";
	case DSNVM_REQUEST_COMMIT_XACT_ERROR:	return "ON cannot allow commit request";
	case DSNVM_REPLY_LOG_FULL:		return "ON reports that running of log slots";
	case DSNVM_REPLY_PAGE_IN_OTHER_XACT:	return "ON reports that page in other xact";
	case DSNVM_REPLY_ON_REGION_MIGRATING_OUT: return "ON reports that a region is migrating out";
	case DSNVM_REPLY_FAIL_TO_MERGE:		return "New ON fail to merge dn/replica into new ON_REGION";
	case DSNVM_REPLY_KEEP_REPLICA_PAGE:	return "ON wants us to keep this replica page";
	case DSNVM_REPLY_NO_LOG:		return "ON can not find log";
	case DSNVM_REPLY_BUG:			return "Major bug in remote node";
	default:				return "Unknow status, BUG! Leak! Nerd!";
	}
}

/* Used in reply to indicate a tiny region info */
struct __region_info {
	unsigned long dr_no;
	unsigned int owner_id;
	DECLARE_BITMAP(dn_list, DSNVM_MAX_NODE);
};

/*
 * Just a struct to store address and len of some data
 */
typedef struct {
	unsigned long	vaddr;
	unsigned int	len;
} __attribute__((__packed__)) dsnvm_addr_len;

/*
 * Used by user-level programs to begin/commit xact
 */
struct xact_header{
	unsigned int	rep_degree;
	unsigned int	xact_id;
};

struct dr_no_dro {
	__u64	dr_no;
	__u32	dro;
};

/*
 * Well, as its name, it is a combination of:
 * @dr_no:
 * @dro:
 * @page_offset:
 *
 * This is a general purpose structure.
 */
struct dr_no_dro_page_offset {
	__u64	dr_no;
	__u32	dro;
	__u32	page_offset;
};

struct status_reply_msg {
	__u32			status;
};

struct max_reply_msg {
	char msg[DSNVM_PAGE_SIZE];
	int length;
};

/* XXX: hmm, the same with dsnvm_addr_len */
struct atomic_struct {
	void	*vaddr;
	size_t	len;
} __attribute__((__packed__));

struct status_and_data_reply_msg {
	__u32			status;
	union {
		struct __region_info	base[0];/* base of dr info arrary */
		char			data[0];
	};
};

struct dsnvm_request {
	__u32	op;
	__u64	dr_no;
	__u32	dro;

	union {
		unsigned char name[DSNVM_MAX_NAME];
	};
};

struct dsnvm_reply {
	__u32	status;
	__u32	nr_dr;	/* Number of DRs this file have */

	union {
		struct __region_info	base[0];/* base of dr info arrary */
		char			data[0];
	};
};

/*
 * dsnvm_request_open_file and dsnvm_reply_open_file are used
e* by DN/CD to handle open() file operation.
 */
struct dsnvm_request_open_file {
	__u32	op;
	unsigned char name[DSNVM_MAX_NAME];
};

/*
 * dsnvm_request_extend_file and dsnvm_reply_extend_file
 * are used by DN/CD to handle extend file region operation.
 */
struct dsnvm_request_extend_file {
	__u32	op;
	__u32	dr_index;
	unsigned char name[DSNVM_MAX_NAME];
};

struct dsnvm_reply_extend_file {
	__u32	status;
	__u32	owner_id;
	__u64	dr_no;
};

/*
 * dsnvm_request_machine_event and dsnvm_reply_machine_event are
 * used by CD to inform other online machines that a new machine
 * is going to be established.
 *
 * dsnvm_reply_machine_join is used by CD to respond to the machine
 * who send the machine join request, in which contains the bitmap
 * of current online machines.
 */
struct dsnvm_request_machine_event {
	__u32	op;
	__u32	node_id;
};

struct dsnvm_reply_machine_event {
	__u32	status;
};

struct dsnvm_request_machine_join {
	__u32	op;
	__u32	xact_mode;
	__u32	dr_page_nr_shift;
	__u32	dsnvm_max_regions_shift;
};

struct dsnvm_reply_machine_join {
	__u32	status;
	DECLARE_BITMAP(DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);
};

/*
 * dsnvm_request_free_replica_page and dsnvm_reply_free_replica_page
 * are used by DN to inform ON that a replica page is being evicted.
 */
struct dsnvm_request_free_replica_page {
	__u32	op;
	__u64	dr_no;
	__u32	dro;
};

struct dsnvm_reply_free_replica_page {
	__u32	status;
};

/*
 * dsnvm_request_page_fetch and dsnvm_reply_page_fetch are used by
 * DN to fetch page from remote ON.
 */
struct dsnvm_request_page_fetch {
	__u32	op;
	__u64	dr_no;
	__u32	dro;
};

struct dsnvm_reply_page_fetch {
	__u32	status;
	char	data[DSNVM_PAGE_SIZE];
};

/*
 * Migration Related
 */
struct migrate_on_chunk_header {
	int		op;
	int		nr_pages;
	unsigned long	dr_no;
};

struct migrate_on_chunk_notify {
	int		op;
	unsigned long	dr_no;
	unsigned int	new_owner;

#ifdef __KERNEL__
	/* History stats */
	atomic_t	nr_page_fetch[DSNVM_MAX_NODE];
	atomic_t	nr_commit_total[DSNVM_MAX_NODE];
	atomic64_t	nr_commit_bytes_total[DSNVM_MAX_NODE];
#endif
};

/*
 * Translate a page offset into a dr index,
 * which is the index into a dsnvm file's dr array.
 */
static inline unsigned long pgoff_to_dr_index(unsigned long pgoff)
{
	return (pgoff / DR_PAGE_NR);
}

/* DR Offset belongs to: [0, DR_PAGE_NR) */
static inline bool DRO_VALID(unsigned int dro)
{
	if (dro >= DR_PAGE_NR)
		return false;
	else
		return true;
}

#endif /* _INCLUDE_DSNVM_COMMON_H_ */
