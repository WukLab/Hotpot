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

#ifndef _INCLUDE_DSNVM_MIGRATE_H_
#define _INCLUDE_DSNVM_MIGRATE_H_

#define MAX_NR_PAGES_PER_REQUEST	100

extern bool enable_migration;

int migrate_on_chunk(unsigned long dr_no, unsigned int new_owner);
int handle_migrate_on_chunk(int sender_id, int nr_reqs, struct atomic_struct *reqs,
			    char *output_buf, unsigned int *output_size, bool no_page);

int handle_migrate_on_chunk_finished_notify(char *msg, char *reply_addr,
					    unsigned int *reply_len, int sender_id);

int init_dsnvm_migrated(void);
void stop_dsnvm_migrated(void);

/**
 * Proxy for ON_REGION chunk that was migrated out before
 *
 * @dr_no:	the data region number
 * @new_owner:	the new owner of this region
 * @c_time:	creation time of this proxy
 * @next:	next proxy in the list
 */
struct on_region_proxy {
	unsigned long		dr_no;
	unsigned int		new_owner;
	struct timespec		c_time;
	struct list_head	next;
};

/**
 * proxy_find_new_owner
 * @dr_no: dr_no to search in the proxy list
 *
 * RETURN:
 *	the node id of the new owner if found
 *	0 on failure
 */
unsigned int proxy_find_new_owner(unsigned long dr_no);

void proxy_exit(void);

#endif /* _INCLUDE_DSNVM_MIGRATE_H_ */
