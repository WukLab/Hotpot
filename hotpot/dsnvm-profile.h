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

#ifndef _INCLUDE_DSNVM_PROFILE_H_
#define _INCLUDE_DSNVM_PROFILE_H_

#include <linux/time.h>

#ifdef DSNVM_PROFILE

#define DEFINE_PROFILE_TS(t1, t2, t3)	\
	struct timespec t1 = {0, 0}, t2 = {0, 0}, t3 = {0, 0};

#define __START_PROFILE(t_start)		\
do {						\
	getnstimeofday(&t_start);		\
} while (0)

#define __END_PROFILE(t_start, t_end, t_diff)	\
do {						\
	getnstimeofday(&t_end);			\
	t_diff = timespec_sub(t_end, t_start);	\
} while (0)

#define __PROFILE_PRINTK(format...)		\
	pr_crit(format)

#else
#define DEFINE_PROFILE_TS(t1, t2, t3)
#define __START_PROFILE(t1) do {} while (0)
#define __END_PROFILE(t1, t2, t3) do {} while (0)
#define __PROFILE_PRINTK(format...) do {} while (0)
#endif /* DSNVM_PROFILE */
#endif /* _INCLUDE_DSNVM_PROFILE_H_ */
