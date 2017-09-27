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
 * This file describes helper functions necessary for persistence.
 */

#include <asm/processor.h>
#include <linux/bitops.h>

/*
 * clflush, clwb, clflush_opt only ensure that dirty cache line is flushed out
 * of cache. Among its way to persistency, we still have volatile ring buffer,
 * memory controller buffer. This clflush etc. instructuons are not sufficient
 * to promise persistency.
 *
 * Though PCOMMIT was designed for this purpose, but are unavailable on most of
 * our commodity servers. Recently, Linux kernel chose not to use pcommit anymore,
 * instead, they use some device defined interface. Check this topic:
 * https://lkml.org/lkml/2016/7/9/139
 */

static inline bool SUPPORT_PCOMMIT(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(0x07, &eax, &ebx, &ecx, &edx);

	return test_bit(22, (unsigned long *)&ebx);
}

static inline bool SUPPORT_CLWB(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(0x07, &eax, &ebx, &ecx, &edx);

	return test_bit(24, (unsigned long *)&ebx);
}

static inline bool SUPPORT_CLFLUSHOPT(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(0x07, &eax, &ebx, &ecx, &edx);

	return test_bit(23, (unsigned long *)&ebx);
}

static inline void dsnvm_clflush(volatile void *__p)
{
	asm volatile (
		"clflush %0"
		: "+m" (*(volatile char *)__p)
	);
}

#define dsnvm_mb() 	asm volatile ("mfence" ::: "memory")
#define dsnvm_rmb()	asm volatile ("lfence" ::: "memory")
#define dsnvm_wmb()	asm volatile ("sfence" ::: "memory")

/*
 * Flush buffer from cache to memory. After this function completes the data
 * pointed to by 'vaddr' has been accepted to memory.
 *
 * However, this function does NOT guarantee that it will be durable to
 * persistent memory. PCOMMIT is needed in Intel platform for this.
 */
static inline void dsnvm_flush_buffer(void *vaddr, unsigned int size)
{
	unsigned long clflush_mask = boot_cpu_data.x86_clflush_size - 1;
	void *vend = vaddr + size;
	void *p;

	for (p = (void *)((unsigned long)vaddr & ~clflush_mask); p < vend;
	     p += boot_cpu_data.x86_clflush_size) {
		dsnvm_clflush(p);
	}

	dsnvm_wmb();
}
