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
 * This file describes things used by Data Nodes (DN).
 */

#ifndef _INCLUDE_DSNVM_DN_H_
#define _INCLUDE_DSNVM_DN_H_

#include <linux/kref.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>

#define _DN_REGION_ACCESSED	0
#define _DN_REGION_DIRTY	1
#define _DN_REGION_COMMITTED	2
#define _DN_REGION_PREFETCH	3

#define DN_REGION_ACCESSED	(1U << _DN_REGION_ACCESSED)
#define DN_REGION_DIRTY		(1U << _DN_REGION_DIRTY)
#define DN_REGION_COMMITTED	(1U << _DN_REGION_COMMITTED)
#define DN_REGION_PREFETCH	(1U << _DN_REGION_PREFETCH)

struct dn_region_info {
	unsigned long		dr_no;
	unsigned int		owner_id;
	unsigned int		flag;

	/*
	 * mapping[] are PFNs of DSNVM pages that are used in PTEs,
	 * which may equal to coherent_mapping[] if the page has not
	 * been written to and diverges if it was written to.
	 *
	 * coherent_mapping[] are PFNs of DSNVM pages that are not used
	 * in PTEs, which always store the committed coherent pages.
	 * Those pages are fetched from ON.
	 *
	 * If a page is fetched from ON and has not been written to,
	 * then (mapping[dro] == coherent_mapping[dro]). Once it is
	 * written to and caught by dsnvm_pfn_mkwrite, then the mapping[dro]
	 * will points to the newly allocated COW page, coherent_mapping[dro]
	 * remain unchanged.
	 */
	unsigned long		mapping[DR_PAGE_NR];
	unsigned long		coherent_mapping[DR_PAGE_NR];
	spinlock_t		page_lock[DR_PAGE_NR];

	/*
	 * This bitmap is mainly for synchronization between concurrent
	 * faults. It can be used to check valid mapping, too.
	 */
	DECLARE_BITMAP(mapping_valid, DR_PAGE_NR);

	/*
	 * This bitmap is mainly for synchronization between concurrent
	 * pfn_mkwrite. (Gosh, fault handler should also use this!)
	 */
	DECLARE_BITMAP(pfn_mkwrite_busy, DR_PAGE_NR);

	/* These are inited at alloc time */
	spinlock_t		region_lock;
	struct kref		region_ref;
	struct hlist_node	hlist;

	/*
	 * For recovery: if this DN or even ON failed,
	 * it can be used to talk with others DNs or
	 * even promote this DN to ON.
	 *
	 * Set at open() time.
	 */
	DECLARE_BITMAP(other_dn_list, DSNVM_MAX_NODE);
};

#define FILE_VALID_MAGIC	0xdeadbeef

/*
 * This structure represents a runtime mmap'ed dsnvm file.
 * It describes the context of this dsnvm file. Also, it is
 * a per-thread resource, created during dsnvm_open and freed
 * during dsnvm_release.
 */
struct dsnvm_client_file {
	int			valid;
	unsigned char		name[DSNVM_MAX_NAME];

	/*
	 * The same as vma attributes, describe
	 * runtime virtual memory information.
	 */
	unsigned long		vm_start;
	unsigned long		vm_end;
	unsigned long		vm_pgoff;
	unsigned long		vm_flags;

	/*
	 * Indicate the DR range which
	 * is mapped by mmap() call.
	 */
	unsigned long		dr_start;
	unsigned long		dr_end;

	/*
	 * If vm_end is not aligned to last DR's end
	 */
	unsigned int		partial_end;
	spinlock_t		lock;

	/*
	 * XXX: Maybe malloc only the mmaped's region info
	 * That should save us a lot of memory
	 */
	struct dn_region_info	regions[DSNVM_MAX_REGIONS];
	struct vm_area_struct	*vma;
};

int dsnvm_get_faulting_page(struct vm_area_struct *, unsigned long, int);

#define for_each_mmaped_region(i, region, file)			\
	for (i = file->dr_start, region = &file->regions[i];	\
	    i <= file->dr_end;					\
	    i++, region++)

static inline unsigned long dsnvm_file_pages(struct dsnvm_client_file *f)
{
	return (f->vm_end - f->vm_start) >> PAGE_SHIFT;
}

static inline unsigned long dsnvm_file_drs(struct dsnvm_client_file *f)
{
	return f->dr_end - f->dr_start + 1;
}

static inline struct dsnvm_client_file *DSNVM_FILE(struct vm_area_struct *vma)
{
	/* in case a vma without file attached is passed in */
	if (unlikely(!vma->vm_file)) {
		return NULL;
	}
	return vma->vm_file->private_data;
}

static inline unsigned long DR_INDEX(struct dn_region_info *r,
				     struct dsnvm_client_file *f)
{
	return (unsigned long)(r - &f->regions[0]);
}

/* Check if DR belongs to mmap's range */
static inline bool DR_MMAPED(struct dn_region_info *r,
			    struct dsnvm_client_file *f)
{
	unsigned long index = DR_INDEX(r, f);
	if (f->dr_start <= index)
		if (index <= f->dr_end)
			return true;
	return false;
}

/* Virtual address --> Region info */
static inline struct dn_region_info *
get_dn_region(struct dsnvm_client_file *f, unsigned long vaddr)
{
	unsigned long pgoff;
	unsigned long dr_index;

	/* from the very start of file */
	pgoff = ((vaddr & PAGE_MASK) - f->vm_start) >> PAGE_SHIFT;
	pgoff += f->vm_pgoff;

	dr_index = pgoff_to_dr_index(pgoff);
	return &f->regions[dr_index];
}

/* Virtual address --> DR Offset */
static inline unsigned int virt_to_dro(unsigned long vaddr,
				       struct dsnvm_client_file *f)
{
	unsigned long pgoff;

	pgoff = ((vaddr & PAGE_MASK) - f->vm_start) >> PAGE_SHIFT;
	pgoff += f->vm_pgoff;

	return pgoff % DR_PAGE_NR;
}

/*
 * BIG FAT NOTE:
 *
 * Always pass predefined flag macros such as
 * _DN_REGION_DIRTY to the following functions.
 */

/*
 * This function is atomic and may not be reordered.
 * Use __dn_region_set_flag if you do not need atomic.
 */
static inline void dn_region_set_flag(struct dn_region_info *r,
				      unsigned int flagbit)
{
	set_bit(flagbit, (unsigned long *)&r->flag);
}

/*
 * Unlike dn_region_set_flag(), this function is non-atomic and may be
 * reordered. If it's called on the same region of memory simultaneously,
 * the effect may be that only one operation succeeds.
 */
static inline void __dn_region_set_flag(struct dn_region_info *r,
					unsigned int flagbit)
{
	__set_bit(flagbit, (unsigned long *)&r->flag);
}

/*
 * dn_region_clear_flag() is atomic and may not be reordered. However, it does
 * not contain a memory barrier, so if it is used for locking purposes, you
 * should call smp_mb__before_atomic() and/or smp_mb__after_atomic() in order
 * to ensure changes are visible on other processors.
 */
static inline void dn_region_clear_flag(struct dn_region_info *r,
					unsigned int flagbit)
{
	clear_bit(flagbit, (unsigned long *)&r->flag);
}

static inline void __dn_region_clear_flag(struct dn_region_info *r,
					  unsigned int flagbit)
{
	__clear_bit(flagbit, (unsigned long *)&r->flag);
}

/* non-atomic and can be reordered */
static inline int dn_region_test_flag(struct dn_region_info *r,
				       unsigned int flagbit)
{
	return test_bit(flagbit, (unsigned long *)&r->flag);
}

/*
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int dn_region_test_and_clear_flag(struct dn_region_info *r,
						unsigned int flagbit)
{
	return test_and_clear_bit(flagbit, (unsigned long *)&r->flag);
}

/*
 * This operation is non-atomic and can be reordered. If two examples
 * of this operation race, one can appear to succeed but actually fail.
 * You must protect multiple accesses with a lock. The operation is
 * performed atomically with respect to the local CPU, but not other CPUs.
 */
static inline int __dn_region_test_and_clear_flag(struct dn_region_info *r,
						  unsigned int flagbit)
{
	return __test_and_clear_bit(flagbit, (unsigned long *)&r->flag);
}

/**
 * dn_region_test_mapping
 *
 * Test if a mapping between DR_NO+DRO --> PFN is valid.
 * Mainly used to synchronize between concurrent faults.
 */
static inline int dn_region_test_mapping_valid(struct dn_region_info *r,
					       unsigned int dro)
{
	return test_bit(dro, r->mapping_valid);
}

static inline void dn_region_set_mapping_valid(struct dn_region_info *r,
					       unsigned int dro)
{
	set_bit(dro, r->mapping_valid);
}

static inline void dn_region_clear_mapping_valid(struct dn_region_info *r,
						 unsigned int dro)
{
	clear_bit(dro, r->mapping_valid);
}

/*
 * Check if a region is owned by myself
 * @r: dn_region_info
 */
#define REGION_IS_LOCAL(r) ((r)->owner_id == DSNVM_LOCAL_ID)

void dn_region_set_coherent_mapping(struct dn_region_info *, unsigned int, unsigned long, bool);
void dn_region_set_mapping(struct dn_region_info *, unsigned int, unsigned long);
unsigned long dn_region_clear_mapping(struct dn_region_info *, unsigned int);

void free_dn_regions(struct dsnvm_client_file *);
int dn_region_handle_fault(struct dn_region_info *, unsigned int, unsigned long, int);
int extend_one_region(struct dsnvm_client_file *, int);

/* Manipulate the dn_region hashtable */
int __must_check ht_add_dn_region(struct dn_region_info *new);
int ht_remove_dn_region(unsigned long dr_no);
struct dn_region_info *ht_get_dn_region(unsigned long dr_no);
void ht_put_dn_region(struct dn_region_info *r);

#endif /* _INCLUDE_DSNVM_DN_H_ */
