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

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <asm/tlbflush.h>

#include "dsnvm.h"
#include "dsnvm-vm.h"

#if 0
#define DSNVM_PROFILE
#endif
#include "dsnvm-profile.h"

struct pfn_spec {
	unsigned long	pfn;
	bool		is_new;
};

/*
 * For DN==ON and DN==RN case:
 * It should be okay to just return pfn here. Because we are not updating
 * metadata here and PTE is not persistent. If we got crashed between here
 * and dn_region_handle_fault(), that should be okay, because on_page_info
 * metadata is not updated.
 */
static __always_inline struct pfn_spec get_local_pfn(struct dn_region_info *r,
						     unsigned int dro,
						     int is_write)
{
	struct pfn_spec pfn_spec;

	WARN_ON(REGION_IS_LOCAL(r) && REGION_IS_REPLICA(r));

	if (!is_write) {
		/*
		 * Data Node == Owner Node case
		 * which should be normal with ON live migration
		 */
		if (likely(REGION_IS_LOCAL(r))) {
			unsigned long pfn;
			struct on_region_info *on_region;

			on_region = ht_get_on_region(r->dr_no);
			if (unlikely(!on_region)) {
				DSNVM_BUG("ERROR: can not find ON_REGION (dr_no: %lu)", r->dr_no);
				pfn_spec.pfn = 0;
				return pfn_spec;
			}

			pfn = on_region->mapping[dro].local_pfn;
			put_on_region(on_region);

			if (unlikely(!pfn_is_dsnvm(pfn))) {
				DSNVM_BUG("ERROR: ON pfn: %lu is not valid", pfn);
				pfn_spec.pfn = 0;
				return pfn_spec;
			}

			pfn_spec.pfn = pfn;
			pfn_spec.is_new = false;

			return pfn_spec;
		}

		/*
		 * Data Node == Replica Node case
		 */
		if (REGION_IS_REPLICA(r)) {
			unsigned long pfn;
			struct replica_region_info *replica_region;

			replica_region = ht_get_replica_region(r->dr_no);
			if (unlikely(!replica_region)) {
				DSNVM_BUG("removed in this period?");
				pfn_spec.pfn = 0;
				return pfn_spec;
			}

			pfn = replica_region->mapping[dro];
			ht_put_replica_region(replica_region);

			if (unlikely(!pfn_is_dsnvm(pfn))) {
				/*
				 * The case where only a few pages were created
				 * within this REPLICA_REGION. We still need to allocate
				 * a new local DSNVM page and ask remote ON for data.
				 */
				if (likely(pfn == 0))
					goto alloc_new;
				else {
					DSNVM_BUG("ERROR: RN pfn: %lu is not valid", pfn);
					pfn_spec.pfn = 0;
					return pfn_spec;
				}
			}

			pfn_spec.pfn = pfn;
			pfn_spec.is_new = false;

			return pfn_spec;
		}
	}

alloc_new:
	/*
	 * Allocate a new DSNVM page iff:
	 * 1) Write fault
	 * 2) Read fault, with !REGION_IS_LOCAL && !REGION_IS_REPLICA
	 * 3) Read fault, with REGION_IS_REPLICA && !pfn_is_dsnvm(pfn)
	 */
	pfn_spec.is_new = true;
	pfn_spec.pfn = alloc_dsnvm_page_pfn();

	return pfn_spec;
}

static inline void free_local_pfn(struct pfn_spec pfn_spec)
{
	if (pfn_spec.is_new)
		free_dsnvm_page_pfn(pfn_spec.pfn);
}

static __always_inline int dsnvm_vm_insert_pfn(struct vm_area_struct *vma,
					       unsigned long addr,
					       unsigned long pfn,
					       bool is_write,
					       bool again)
{
	pgprot_t pgprot;
	pte_t *pte, entry;
	spinlock_t *ptl = NULL;
	int ret = 0;

	pte = dsnvm_get_locked_pte(vma->vm_mm, addr, &ptl);

	if (unlikely(!pte_none(*pte))) {
		/* The pte was inserted by this thread,
		 * doing this again because of migration. */
		if (likely(again))
			goto insert;

		/* Concurrent page fault */
		ret = -EBUSY;
		goto out;
	}

insert:
	pgprot = vma->vm_page_prot;
	if (is_write)
		pgprot_val(pgprot) |= (pgprotval_t)_PAGE_RW;
	else
		pgprot_val(pgprot) &= ~(pgprotval_t)_PAGE_RW;

	entry = pte_mkspecial(pfn_pte(pfn, pgprot));
	set_pte_at(vma->vm_mm, addr, pte, entry);

out:
	pte_unmap_unlock(pte, ptl);
	return ret;
}

/*
 * We enter with non-exclusive mmap_sem, this allows concurrent faults.
 * For each single DSNVM page, we should ask ON for data only once. So,
 * if concurrent faults happened, we must catch it as early as possible.
 *
 * Our solution here is: Instead of using per-page spinlock, a per-page bit
 * is used to sync between multiple CPUs. With dsnvm_vm_insert_pfn's help,
 * we could know which CPU wins in a concurrent faults. The winner CPU is
 * responsible for asking ON for data or update ON region metadata if it
 * is the DN==ON case. Other CPUs just waiting on the line, once mapping
 * valid bit is set, they are free to go.
 */
int dsnvm_get_faulting_page(struct vm_area_struct *vma,
			    unsigned long vaddr, int is_write)
{
	struct dsnvm_client_file *f = DSNVM_FILE(vma);
	unsigned int dro = virt_to_dro(vaddr, f);
	struct dn_region_info *r;
	unsigned long pfn;
	struct dsnvm_page *page;
	pte_t *page_table;
	int ret;
	bool again;
	struct pfn_spec pfn_spec;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	count_dsnvm_event(DSNVM_GET_FAULTING_PAGE_RUN);

	r = get_dn_region(f, vaddr);
	if (unlikely(!DR_MMAPED(r, f))) {
		DSNVM_BUG();
		return VM_FAULT_SIGBUS;
	}

	again = false;
retry:
	pfn_spec = get_local_pfn(r, dro, is_write);
	pfn = pfn_spec.pfn;
	if (unlikely(!pfn))
		return VM_FAULT_SIGBUS;
	page = pfn_to_dsnvm_page(pfn);

	__START_PROFILE(t_start);
	ret = dsnvm_vm_insert_pfn(vma, vaddr, pfn, is_write, again);
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("dsnvm_vm_insert_pfn latency: %lld ns", timespec_to_ns(&t_diff));

	if (unlikely(ret == -EBUSY)) {
		/*
		 * Okay, another CPU wins. Note that we must wait for the
		 * winner CPU finish the data and metadata updating before
		 * back to userspace.
		 */
		count_dsnvm_event(DSNVM_PGFAULT_CONCURRENT);
		free_local_pfn(pfn_spec);

		while (unlikely(!dn_region_test_mapping_valid(r, dro)))
			cpu_relax();

		return VM_FAULT_NOPAGE;
	} else if (unlikely(ret == -ENOMEM)) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	} else {
		if (unlikely(ret)) {
			DSNVM_BUG();
			return VM_FAULT_SIGBUS;
		}
	}

	/* Update local metadata and fetch remote page if any */
	__START_PROFILE(t_start);
	ret = dn_region_handle_fault(r, dro, pfn, is_write);
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("dn_region_handle_fault latency: %lld ns", timespec_to_ns(&t_diff));

	if (unlikely(ret)) {
		/* The case where a remote ON_REGION was migrated to us */
		if (likely(ret == -EAGAIN)) {
			count_dsnvm_event(DSNVM_PF_RARE_RETRY);
			free_local_pfn(pfn_spec);
			again = true;
			goto retry;
		}

		/*
		 * Failed to load data. Not sure if VM_FAULT_SIGBUS
		 * will kill the whole thread group now. So still
		 * set the bit to end other CPU's waiting anyway.
		 */
		dn_region_set_mapping_valid(r, dro);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	lock_dsnvm_page(page);
	page_table = dsnvm_get_pte(vma->vm_mm, vma, vaddr);
	if (dsnvm_page_add_rmap(page, page_table, vma))
		DSNVM_BUG();

	if (pfn_spec.is_new) {
		if (is_write)
			DSNVM_SetPageDirty(page);
		else
			DSNVM_SetPageCommitted(page);
		lru_add_inactive(page);
	}
	unlock_dsnvm_page(page);

	/*
	 * If the first operation is read, then it is a coherent mapping, both
	 * mapping[] and coherent_mapping[] are set. If the first operation is
	 * write then this DN does not have a coherent mapping, so only mapping[]
	 * is set and coherent_mapping[] is set to 0.
	 *
	 * Also note that, mapping_valid is set after this call, so other CPUs
	 * waiting on the line are free to go now. This feature is proved to be
	 * multi-thread safe.
	 */
	dn_region_set_coherent_mapping(r, dro, pfn, !is_write);

	return VM_FAULT_NOPAGE;

out:
	free_local_pfn(pfn_spec);
	return ret;
}

static int dsnvm_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned long vaddr = (unsigned long)vmf->virtual_address & PAGE_MASK;
	int is_write = vmf->flags & FAULT_FLAG_WRITE;
	int retval;

	DSNVM_PRINTK_VM("[pid %u] [cpu %d]: %s fault at [%#016lx]",
		current->pid, smp_processor_id(),
		is_write? "write" : "read", vaddr);

	retval = dsnvm_get_faulting_page(vma, vaddr, is_write);

	count_dsnvm_event(DSNVM_PGFAULT);
	if (is_write)
		count_dsnvm_event(DSNVM_PGFAULT_WRITE);
	else
		count_dsnvm_event(DSNVM_PGFAULT_READ);

	return retval;
}

static __always_inline int dsnvm_vm_switch_pfn(struct vm_area_struct *vma,
					       unsigned long addr,
					       unsigned long new_pfn)
{
	struct mm_struct *mm = vma->vm_mm;
	pgprot_t pgprot;
	pte_t *pte, entry;
	spinlock_t *ptl = NULL;
	int ret = 0;

	pte = dsnvm_get_locked_pte(mm, addr, &ptl);

	pgprot = vma->vm_page_prot;
	pgprot_val(pgprot) |= (pgprotval_t)_PAGE_RW;

	entry = pte_mkspecial(pfn_pte(new_pfn, pgprot));
	set_pte_at(mm, addr, pte, entry);

#ifdef DSNVM_KERNEL_EXPORT_TLB_FLUSH
	flush_tlb_page(vma, addr);
#endif

	pte_unmap_unlock(pte, ptl);
	return ret;
}

/*
 * Three cases:
 * 1) DN==ON (REGION_IS_LOCAL), PTE points to ON page
 * 2) DN==RN (REGION_IS_REPLICA), PTE points to RN page
 * 3) Coherence page, PTE points to committed DN page
 */
static int dsnvm_pfn_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned long vaddr = (unsigned long)vmf->virtual_address & PAGE_MASK;
	struct dsnvm_client_file *f = DSNVM_FILE(vma);
	struct dn_region_info *r;
	struct dsnvm_page *old_page, *new_page;
	unsigned long old_pfn, new_pfn;
	unsigned int dro;
	int ret;
	pte_t *page_table;

	DSNVM_PRINTK_VM("[pid %u] [cpu %d]: pfn_mkwrite at [%#016lx]",
		current->pid, smp_processor_id(), vaddr);

	count_dsnvm_event(DSNVM_COW);

	dro = virt_to_dro(vaddr, f);
	r = get_dn_region(f, vaddr);
	if (unlikely(!DR_MMAPED(r, f))) {
		DSNVM_BUG();
		return VM_FAULT_SIGBUS;
	}

	if (unlikely(test_and_set_bit(dro, r->pfn_mkwrite_busy))) {
		/*
		 * Alright, there is a concurrent pfn_mkwrite winner already.
		 * Wait till the winner finish all stuff and clear busy bit.
		 */
		count_dsnvm_event(DSNVM_CONCURRENT_COW);
		while (unlikely(test_bit(dro, r->pfn_mkwrite_busy)))
			cpu_relax();
		return 0;
	}

	/*
	 * Allocate a new DSNVM page and switch PTE to let it points to this
	 * new DSNVM page. Note that the PTE is made writable.
	 */
	new_pfn = alloc_dsnvm_page_pfn();
	if (unlikely(!new_pfn))
		return VM_FAULT_SIGBUS;
	new_page = pfn_to_dsnvm_page(new_pfn);

	ret = dsnvm_vm_switch_pfn(vma, vaddr, new_pfn);
	if (unlikely(ret)) {
		free_dsnvm_page_pfn(new_pfn);
		DSNVM_BUG();
		return VM_FAULT_SIGBUS;
	}

	page_table = dsnvm_get_pte(vma->vm_mm, vma, vaddr);

	/*
	 * Compete with dsnvm_begin_xact
	 */
	spin_lock(&r->page_lock[dro]);

	old_pfn = r->mapping[dro];
	old_page = pfn_to_dsnvm_page(old_pfn);
	if (unlikely(!pfn_is_dsnvm(old_pfn))) {
		spin_unlock(&r->page_lock[dro]);
		free_dsnvm_page_pfn(new_pfn);
		DSNVM_BUG();
		return VM_FAULT_SIGBUS;
	}

	lock_dsnvm_page(old_page);
	dsnvm_page_remove_rmap(old_page, page_table, vma);
	unlock_dsnvm_page(old_page);

	/*
	 * BIG FAT NOTE:
	 * Mark the new COW DSNVM page as dirty. If the original DSNVM page is
	 * in transaction, then the new page should be marked as inxact as well.
	 */
	lock_dsnvm_page(new_page);
	__DSNVM_SetPageDirty(new_page);
	if (DSNVM_PageInxact(old_page))
		__DSNVM_SetPageInxact(new_page);
	if (dsnvm_page_add_rmap(new_page, page_table, vma))
		DSNVM_BUG();
	unlock_dsnvm_page(new_page);

	/* Update region metadata */
	r->mapping[dro] = new_pfn;
	dsnvm_flush_buffer(&r->mapping[dro], sizeof(r->mapping[dro]));

	spin_unlock(&r->page_lock[dro]);

	/*
	 * LRU lists:
	 * The COW page is inserted into inactive LRU list
	 * and the old page is marked accessed so it will be move between
	 * active and inactive lists properly.
	 */
	lru_add_inactive(new_page);
	mark_dsnvm_page_accessed(old_page);

	memcpy((void *)dsnvm_page_to_virt(new_page),
	       (void *)dsnvm_page_to_virt(old_page),
	       DSNVM_PAGE_SIZE);

	/*
	 * Clear busy bit, so waiting CPUs are free to go.
	 */
	clear_bit(dro, r->pfn_mkwrite_busy);

	WARN_ON(REGION_IS_LOCAL(r) && REGION_IS_REPLICA(r));
	if (REGION_IS_LOCAL(r))
		count_dsnvm_event(DSNVM_OWNER_COW);
	else if (REGION_IS_REPLICA(r))
		count_dsnvm_event(DSNVM_REPLICA_COW);
	else
		count_dsnvm_event(DSNVM_COHERENCE_COW);

	return 0;
}

const struct vm_operations_struct dsnvm_vm_ops = {
	.fault		= dsnvm_vma_fault,
	.pfn_mkwrite	= dsnvm_pfn_mkwrite,
};
