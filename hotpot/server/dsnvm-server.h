#ifndef _INCLUDE_DSNVM_SERVER_H_
#define _INCLUDE_DSNVM_SERVER_H_

#include <string.h>
#include "../dsnvm-helper.h"
#include "../dsnvm-common.h"

/*
 * Metadata of Central Dispatcher:
 *   filename+offset -> DR_No+ON_ID+{a list of DNs that have ever opened the file} 
 */

/*
 * about dsnvm_server_file->regions
 * 1) Use array just for now. It is not feasible if file size is too large
 * 2) Considering link subarrays
 */

/*
 * If you want to go with latest CD optimization, enable it through the next line.
 * This optimization should help post-receive.
 */
//#define USING_CD_OPTIMIZATION_0103

struct cd_region_info {
	unsigned long		dr_no;
	unsigned int		owner_id;

	/* A list of DNs that have opened the file */
	DECLARE_BITMAP(dn_list, DSNVM_MAX_NODE);
};

struct dsnvm_server_file {
	unsigned char		name[DSNVM_MAX_NAME];
	unsigned int		flags;
	struct cd_region_info	regions[DSNVM_MAX_REGIONS];
	DECLARE_BITMAP(dr_map, DSNVM_MAX_REGIONS);
	struct list_head	next;
};

void init_dsnvm_server(void);

#define DSNVM_BUG(format...)						\
do {									\
	printf("----------------[ cut here ]----------------\n");	\
	printf("DSNVM BUG: at %s:%d %s()!\n",				\
		__FILE__, __LINE__, __func__);				\
	printf(format);							\
	putchar('\n');							\
} while (0);

#define DSNVM_WARN(format...)						\
do {									\
	printf("----------------[ cut here ]----------------\n");	\
	printf("DSNVM WARNING: at %s:%d %s()!\n",			\
		__FILE__, __LINE__, __func__);				\
	printf(format);							\
	putchar('\n');							\
} while (0);

#define dsnvm_log(format...)				\
do {							\
	printf("DSNVM LOG: at %s:%d/%s!\n",		\
		__FILE__, __LINE__, __func__);		\
	printf(format);					\
	putchar('\n');					\
} while (0);

#endif /* _INCLUDE_DSNVM_SERVER_H_ */
