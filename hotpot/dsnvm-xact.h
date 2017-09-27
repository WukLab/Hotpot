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
 * This file describes definitions used by transaction handling.
 */

#ifndef _INCLUDE_DSNVM_XACT_H_
#define _INCLUDE_DSNVM_XACT_H_

#define DSNVM_MAX_XACT			2000

#define DSNVM_MAX_AREAS_IN_XACT		1024

#define DSNVM_LOG_NOT_TO_REPLAY		0x00000001
#define DSNVM_LOG_TO_REPLAY		0x00000002

/* ON Phase 1-2-3 */
#define DSNVM_LOG_PHASE_1_MIDDLE	0x00000010
#define DSNVM_LOG_PHASE_1_SUCCEED	0x00000020
#define DSNVM_LOG_PHASE_2_MIDDLE	0x00000040
#define DSNVM_LOG_PHASE_2_SUCCEED	0x00000080
#define DSNVM_LOG_PHASE_3_MIDDLE	0x00000100

/* Log in the committing node (CN) */
#define DSNVM_LOG_CN_BEGIN		0x00001000
#define DSNVM_LOG_CN_COMMIT		0x00002000

struct dsnvm_log_record {
	__s32				log_id;
	__s32				xact_id;
	__s32				sender_id;
	__s32				single_on;
	__s32				state;
	__s32				nr_areas;
	__s32				rep_degree;
	struct dr_no_dro_page_offset	*meta_for_areas;
	struct atomic_struct		data_areas[DSNVM_MAX_AREAS_IN_XACT];
};

static inline char *log_record_reply_string(struct dsnvm_log_record *log)
{
	int state = log->state & 0xf;

	switch (state) {
	case DSNVM_LOG_NOT_TO_REPLAY:	return "No Replay";
	case DSNVM_LOG_TO_REPLAY:	return "Replay";
	}
	return "Unknow reply state";
}

static inline char *log_record_phase_string(struct dsnvm_log_record *log)
{
	int state = log->state & ~0xf;	

	switch (state) {
	case DSNVM_LOG_PHASE_1_MIDDLE:	return "PHASE_1_MIDDLE";
	case DSNVM_LOG_PHASE_1_SUCCEED: return "PHASE_1_SUCCEED";
	case DSNVM_LOG_PHASE_2_MIDDLE:	return "PHASE_2_MIDDLE";
	case DSNVM_LOG_PHASE_2_SUCCEED:	return "PHASE_2_SUCCEED";
	case DSNVM_LOG_PHASE_3_MIDDLE:	return "PHASE_3_MIDDLE";
	case DSNVM_LOG_CN_BEGIN:	return "CN BEGIN-XACT";
	case DSNVM_LOG_CN_COMMIT:	return "CN COMMIT-XACT";
	}
	return "Unknown phase state";
}

struct dsnvm_commit_xact_id_request_header {
	__u32	op;
	__u64	xact_id;
};

struct dsnvm_reply_commit_xact_msg {
	__u32	op;
	__u64	xact_id;
	__u32	status;
};

struct dsnvm_commit_request_header {
	__u32	op;
	__u32	nr_reqs;
	__u32	xact_id;
};

struct dsnvm_commit_phase_two_status {
	int	finished_nodes;
	int	status[DSNVM_MAX_NODE];
};

struct dsnvm_replicate_page_request {
	__u32	op;
	__u64	dr_no;
	__u32	dro;
	char	data[DSNVM_PAGE_SIZE];
};

struct dsnvm_commit_repdegree_request_header {
	__u32	op;
	__u32	nr_reqs;
	__s32	rep_degree;
	__u64	xact_id;
};

int dsnvm_init_xact(void);

int dsnvm_handle_receive_coherence(int node_id, int nr_reqs,
				   struct atomic_struct *reqs,
				   char *output_buf, unsigned int *output_size);

int dsnvm_handle_request_commit_xact(int sender_id, int nr_reqs,
				     struct atomic_struct *reqs,
				     char *reply_addr, unsigned int *reply_len);

int dsnvm_handle_commit_xact(char *msg, char *reply_addr,
			     unsigned int *reply_len, int sender_id);

int dsnvm_handle_commit_xact_single_on(int sender_id, int nr_reqs,
				       struct atomic_struct *reqs,
				       char *reply_addr, unsigned int *reply_len);

int dsnvm_handle_free_replica_page(char *msg, char *reply_addr,
				   unsigned int *reply_len, int sender_id);

int dsnvm_handle_ack_commit_xact(char *msg, char *reply_addr,
				 unsigned int *reply_len, int sender_id,
				 bool revert);

int handle_mrsw_begin(char *send_msg, unsigned int send_msg_size,
		      char *reply_addr, unsigned int *reply_len, int sender_id);

int handle_mrsw_commit(char *send_msg, unsigned int send_msg_size,
		       char *reply_addr,
		       unsigned int *reply_len, int sender_id);

#endif /*_INCLUDE_DSNVM_XACT_H_ */
