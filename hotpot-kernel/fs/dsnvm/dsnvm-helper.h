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

#ifndef _INCLUDE_DSNVM_HELPER_H_
#define _INCLUDE_DSNVM_HELPER_H_

#ifdef __KERNEL__
#error	"This file provides a similar feeling of kernel coding while you are"
	"writing userspace code. Please do not include it in kernel C files!"
#endif

/*
 * Part 0 - Basic
 */

#define __used			__attribute__((__used__))

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y)	((typeof(x))((y)-1))
#define round_up(x, y)		((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)	((x) & ~__round_mask(x, y))

/* Along with strict type-checking */
#define min(x, y)				\
({						\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2;		\
})

#define max(x, y)				\
({						\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2;		\
})

typedef unsigned long long	u64;
typedef signed long long	s64;
typedef unsigned int		u32;
typedef signed int		s32;
typedef unsigned short		u16;
typedef signed short		s16;
typedef unsigned char		u8;
typedef signed char		s8;

typedef unsigned long long	__u64;
typedef signed long long	__s64;
typedef unsigned int		__u32;
typedef signed int		__s32;
typedef unsigned short		__u16;
typedef signed short		__s16;
typedef unsigned char		__u8;
typedef signed char		__s8;

typedef unsigned long		size_t;

#ifndef bool
#define bool int
#endif

#ifndef false
#define false   (0)
#endif

#ifndef true
#define true    (!(false))
#endif

#define barrier() asm volatile("": : :"memory")

static inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8 *)res = *(volatile __u8 *)p; break;
	case 2: *(__u16 *)res = *(volatile __u16 *)p; break;
	case 4: *(__u32 *)res = *(volatile __u32 *)p; break;
	case 8: *(__u64 *)res = *(volatile __u64 *)p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

static inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile __u8 *)p = *(__u8 *)res; break;
	case 2: *(volatile __u16 *)p = *(__u16 *)res; break;
	case 4: *(volatile __u32 *)p = *(__u32 *)res; break;
	case 8: *(volatile __u64 *)p = *(__u64 *)res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

#define READ_ONCE(x)						\
({								\
	union {							\
		typeof(x) __val;				\
		char __c[1];					\
	} __u;							\
	__read_once_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;						\
})

#define WRITE_ONCE(x, val)					\
({								\
	union {							\
		typeof(x) __val;				\
		char __c[1];					\
	} __u = { .__val = (val) };				\
	__write_once_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;						\
})

#define ACCESS_ONCE(x)						\
({								\
	typeof(x) __var = (typeof(x)) 0;			\
	*(volatile typeof(x) *)&(x);				\
})

/*
 * Part 1 - Bitops
 *
 * These have to be done with inline assembly: that way the bit-setting
 * is guaranteed to be atomic. All bit operations return 0 if the bit
 * was cleared before the operation and != 0 if it was not.
 *
 * Bit 0 is the LSB of addr; bit 32 is the LSB of (addr+1).
 */

/* Anyway, assume x86_64 */
#define BITS_PER_LONG			64
#define BIT_WORD(nr)			((nr) / BITS_PER_LONG)
#define DIV_ROUND_UP(n,d)		(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)		DIV_ROUND_UP(nr, 8*sizeof(long))
#define DECLARE_BITMAP(name, bits)	unsigned long name[BITS_TO_LONGS(bits)]

#define ADDR (*(volatile long *) addr)

#if 1
# define LOCK_PREFIX ""
#else
# define LOCK_PREFIX "lock; "
#endif 

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void set_bit(int nr, volatile unsigned long * addr)
{
	asm volatile (
		LOCK_PREFIX "btsl %1,%0"
		: "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
}

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void __set_bit(long nr, volatile unsigned long *addr)
{
	asm volatile (
		"bts %1,%0"
		: "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.
 */
static inline void clear_bit(int nr, volatile unsigned long * addr)
{
	asm volatile (
		LOCK_PREFIX "btrl %1,%0"
		: "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
}

static inline void __clear_bit(long nr, volatile unsigned long *addr)
{
	asm volatile (
		"btr %1,%0"
		: "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit(int nr, volatile unsigned long * addr)
{
	int oldbit;

	asm volatile (
		LOCK_PREFIX "btrl %2,%1\n\t"
		"sbbl %0,%0"
		: "=r" (oldbit), "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
	return oldbit;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail. You must protect multiple accesses with a lock.
 *
 * Note: the operation is performed atomically with respect to
 * the local CPU, but not other CPUs. Portable code should not
 * rely on this behaviour.
 */
static inline int __test_and_clear_bit(long nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile (
		"btr %2,%1\n\t"
		"sbb %0,%0"
		: "=r" (oldbit), "+m" (ADDR)
		: "Ir" (nr)
	);
	return oldbit;
}

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile (
		LOCK_PREFIX "btsl %2,%1\n\t"
		"sbbl %0,%0"
		: "=r" (oldbit), "+m" (ADDR)
		: "Ir" (nr)
		: "memory"
	);
	return oldbit;
}

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_set_bit(long nr, volatile unsigned long *addr)
{
	int oldbit;

	asm (
		"bts %2,%1\n\t"
		"sbb %0,%0"
		: "=r" (oldbit), "+m" (ADDR)
		: "Ir" (nr)
	);
	return oldbit;
}

static inline int constant_test_bit(int nr, const volatile unsigned long *addr)
{
	return ((1UL << (nr & 31)) & (addr[nr >> 5])) != 0;
}

static inline int variable_test_bit(int nr, const volatile unsigned long * addr)
{
	int oldbit;

	asm volatile (
		"btl %2,%1\n\t"
		"sbbl %0,%0"
		: "=r" (oldbit)
		: "m" (ADDR), "Ir" (nr)
	);
	return oldbit;
}

#define test_bit(nr,addr)			\
(						\
	__builtin_constant_p(nr) ?		\
	constant_test_bit((nr),(addr)) :	\
	variable_test_bit((nr),(addr))		\
)

#undef ADDR

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	asm volatile (
		"rep; bsf %1,%0"
		: "=r" (word)
		: "rm" (word)
	);
	return word;
}

/**
 * ffz - find first zero bit in word
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static inline unsigned long ffz(unsigned long word)
{
	asm volatile (
		"rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word)
	);
	return word;
}

/* Find the first cleared bit in a memory region. */
static inline unsigned long find_first_zero_bit(const unsigned long *addr,
						unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

/* Find the first set bit in a memory region. */
static inline unsigned long find_first_bit(const unsigned long *addr,
					   unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}

/*
 * This is a common helper function for find_next_bit and
 * find_next_zero_bit.  The difference is the "invert" argument, which
 * is XORed with each fetched word before searching it for one bits.
 */
static unsigned long _find_next_bit(const unsigned long *addr,
		unsigned long nbits, unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 *
 * Returns the bit number for the next set bit
 * If no bits are set, returns @size.
 */
static inline unsigned long find_next_bit(const unsigned long *addr,
					  unsigned long size,
					  unsigned long offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 *
 * Returns the bit number of the next zero bit
 * If no bits are zero, returns @size.
 */
static inline unsigned long find_next_zero_bit(const unsigned long *addr,
					       unsigned long size,
					       unsigned long offset)
{
	return _find_next_bit(addr, size, offset, ~0UL);
}

#define for_each_set_bit(bit, addr, size)				\
	for ((bit) = find_first_bit((addr), (size));			\
	     (bit) < (size);						\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size)				\
	for ((bit) = find_first_zero_bit((addr), (size));		\
	     (bit) < (size);						\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

static inline void bitmap_copy(unsigned long *dst,
			       const unsigned long *src,
			       unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src;
	else {
		unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memcpy(dst, src, len);
	}
}

static inline void bitmap_set(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_set >= 0) {
		*p |= mask_to_set;
		nr -= bits_to_set;
		bits_to_set = BITS_PER_LONG;
		mask_to_set = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		*p |= mask_to_set;
	}
}

static inline void bitmap_clear(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_clear >= 0) {
		*p &= ~mask_to_clear;
		nr -= bits_to_clear;
		bits_to_clear = BITS_PER_LONG;
		mask_to_clear = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
		*p &= ~mask_to_clear;
	}
}
/*
 * Part 2 - List
 */

struct list_head {
	struct list_head *next, *prev;
};

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)

#undef container_of
#define container_of(ptr, type, member)				\
({								\
	const typeof(((type *)0)->member) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type,member));	\
})

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	prev->next = new;
	next->prev = new;
	new->next = next;
	new->prev = prev;
}

static inline void __list_del(struct list_head *prev,
			      struct list_head *next)
{
	prev->next = next;
	next->prev = prev;
}

/**
 * list_add - add a new entry after head
 * @new: new entry to be added
 * @head: list head to add it after
 */
static inline void list_add(struct list_head *new,
			    struct list_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * list_add_tail - add a new entry to tail
 * @new: new entry to be added
 * @head: list head to add it before
 */
static inline void list_add_tail(struct list_head *new,
				 struct list_head *head)
{
	__list_add(new, head->prev, head);
}

/**
 * list_del - delete a entry from list
 * @entry: entry to be deleted
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

/**
 * list_del_init - deletes entry from list and reinitialized it
 * @entry: the element to delete from the list
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

/**
 * list_replace - replace old entry by new one
 * @old: the element to be replaced
 * @new: the new element to insert
 */
static inline void list_replace(struct list_head *old,
				struct list_head *new)
{
	old->prev->next = new;
	old->next->prev = new;
	new->prev = old->prev;
	new->next = old->next;
}

/**
 * list_replace_init - replace old by new and reinitialized old
 * @old: the element to be replaced
 * @new: the new element to insert
 */
static inline void list_replace_init(struct list_head *old,
				     struct list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void list_move(struct list_head *list,
			     struct list_head *head)
{
	list_del(list);
	list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
	list_del(list);
	list_add_tail(list, head);
}

/**
 * list_is_last - test whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_last(const struct list_head *list,
			       const struct list_head *head)
{
	return list->next == head;
}

/**
 * list_empty - test whether a list is empty
 * @head: the list to test
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &(struct list_head) pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
		container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_for_each_entry - iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))

/**
 * list_for_each - iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#endif /* _INCLUDE_DSNVM_HELPER_H_ */
