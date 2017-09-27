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

#ifndef _INCLUDE_DSNVM_VM_H_
#define _INCLUDE_DSNVM_VM_H_

#include <linux/mm.h>
#include <linux/bug.h>
#include <linux/compiler.h>

/*
 * No alloc version.
 * Be sure all page table are present when you call this.
 * If not sure, use the alloc version below.
 */
static __always_inline pte_t *
dsnvm_get_pte_no_alloc(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (unlikely(pgd_none(*pgd)))
		BUG();

	pud = pud_offset(pgd, addr);
	if (unlikely(pud_none(*pud)))
		BUG();

	pmd = pmd_offset(pud, addr);
	if (unlikely(pmd_none(*pmd)))
		BUG();

	pte = pte_offset_map(pmd, addr);
	if (unlikely(pte_none(*pte)))
		BUG();
	
	return pte;
}

/*
 * Since dsnvm_get_faulting_page() will be invoked directly by xact code,
 * hence we MUST use xxx_alloc here to manually allocate new page tables.
 * Note that we need to EXPORT those alloc functions manually from kernel.
 */
static __always_inline pte_t *
dsnvm_get_pte(struct mm_struct *mm, struct vm_area_struct *vma,
	      unsigned long addr)
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_alloc(mm, pgd, addr);
	if (pud) {
		pmd_t *pmd = pmd_alloc(mm, pud, addr);
		if (pmd) {
			BUG_ON(pmd_trans_huge(*pmd));
			return pte_alloc_map(mm, vma, pmd, addr);
		}
	}
	BUG();
	return NULL;
}

static __always_inline pte_t *
dsnvm_get_locked_pte(struct mm_struct *mm, unsigned long addr, spinlock_t **ptl)
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_alloc(mm, pgd, addr);
	if (pud) {
		pmd_t *pmd = pmd_alloc(mm, pud, addr);
		if (pmd) {
			BUG_ON(pmd_trans_huge(*pmd));
			return pte_alloc_map_lock(mm, pmd, addr, ptl);
		}
	}
	BUG();
	return NULL;
}

#endif /* _INCLUDE_DSNVM_VM_H_ */
