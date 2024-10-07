/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 *
 * This header is included before the format. It contains definitions
 * that are required to compile the format. The header order is:
 *  pt_defs.h
 *  fmt_XX.h
 *  pt_common.h
 */
#ifndef __GENERIC_PT_DEFS_H
#define __GENERIC_PT_DEFS_H

#include <linux/generic_pt/common.h>

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/limits.h>
#include <linux/bug.h>
#include <linux/kconfig.h>
#include "pt_log2.h"

/* Header self-compile default defines */
#ifndef pt_write_attrs
typedef u64 pt_vaddr_t;
typedef u64 pt_oaddr_t;
#endif

struct pt_table_p;

enum {
	PT_VADDR_MAX = sizeof(pt_vaddr_t) == 8 ? U64_MAX : U32_MAX,
	PT_VADDR_MAX_LG2 = sizeof(pt_vaddr_t) == 8 ? 64 : 32,
	PT_OADDR_MAX = sizeof(pt_oaddr_t) == 8 ? U64_MAX : U32_MAX,
	PT_OADDR_MAX_LG2 = sizeof(pt_oaddr_t) == 8 ? 64 : 32,
};

/*
 * When in debug mode we compile all formats with all features. This allows the
 * kunit to test the full matrix.
 */
#if IS_ENABLED(CONFIG_DEBUG_GENERIC_PT)
#undef PT_SUPPORTED_FEATURES
#define PT_SUPPORTED_FEATURES UINT_MAX
#endif

/*
 * The format instantiation can have features wired off or on to optimize the
 * code gen. Supported features are just a reflection of what the current set of
 * kernel users want to use.
 */
#ifndef PT_SUPPORTED_FEATURES
#define PT_SUPPORTED_FEATURES 0
#endif

#ifndef PT_FORCE_ENABLED_FEATURES
#define PT_FORCE_ENABLED_FEATURES 0
#endif

#define PT_GRANLE_SIZE (1 << PT_GRANULE_LG2SZ)

/*
 * Language used in Generic Page Table
 *  va: The input address to the page table
 *  oa: The output address from the page table.
 *  leaf: A entry that results in an output address. Ie a page pointer
 *  start/end: An open range, eg [0,0) refers to no VA
 *  start/last: An inclusive closed range, eg [0,0] refers to the VA 0
 *  common: The generic page table container struct pt_common
 *  level: The number of table hops from the lowest leaf. Level 0
 *         is always a table of only leaves of the least significant VA bits
 *  top_level: The inclusive highest level of the table. A two level table
 *             has a top level of 1.
 *  table: A linear array of entries representing the translation items for that
 *         level.
 *  index: The position in a table of an element: item = table[index]
 *  item: A single position in a table
 *  entry: A single element in a table. If contiguous pages are not supported
 *         then item and entry are the same thing, otherwise entry refers to the
 *         all the items that comprise a single contiguous translation.
 *  item/entry_size: The number of bytes of VA the table translates for.
 *              If the item is a table entry then the next table covers
 *              this size. If the entry is an output address then the
 *              full OA is: OA | (VA % entry_size)
 *  contig_count: The number of consecutive items fused into a single OA.
 *                item_size * contig_count is the size of that translation.
 *  lg2: Indicates the value is encoded as log2, ie 1<<x is the actual value.
 *       Normally the compiler is fine to optimize divide and mod with log2
 *       values automatically when inlining, however if the values are not
 *       constant expressions it can't. So we do it by hand, we want to avoid
 *       64 bit divmod.
 */

/* Returned by pt_load_entry() and for_each_pt_level_item() */
enum pt_entry_type {
	PT_ENTRY_EMPTY,
	PT_ENTRY_TABLE,
	/* Entry is valid and returns an output address */
	PT_ENTRY_OA,
};

struct pt_range {
	struct pt_common *common;
	struct pt_table_p *top_table;
	pt_vaddr_t va;
	pt_vaddr_t last_va;
	u8 top_level;
	u8 max_vasz_lg2;
};

/*
 * Similar to xa_state, this records information about an in progress parse at a
 * single level.
 */
struct pt_state {
	struct pt_range *range;
	struct pt_table_p *table;
	struct pt_table_p *table_lower;
	u64 entry;
	enum pt_entry_type type;
	unsigned short index;
	unsigned short end_index;
	u8 level;
};

/*
 * Try to install a new table pointer. The locking methodology requires this to
 * be atomic, multiple threads can race to install a pointer, the losing threads
 * will fail the atomic and return false. They should free any memory and
 * reparse the table level again.
 */
#if !IS_ENABLED(CONFIG_GENERIC_ATOMIC64)
static inline bool pt_table_install64(u64 *entryp, u64 table_entry,
				      u64 old_entry)
{

	/*
	 * Ensure the zero'd table content itself is visible before its PTE can
	 * be, be careful about !SMP
	 */
	if (!IS_ENABLED(CONFIG_SMP))
		dma_wmb();
	return try_cmpxchg64_release(entryp, &old_entry, table_entry);
}
#endif

static inline bool pt_table_install32(u32 *entryp, u32 table_entry,
				      u32 old_entry)
{
	/*
	 * Ensure the zero'd table content itself is visible before its PTE can
	 * be, be careful about !SMP
	 */
	if (!IS_ENABLED(CONFIG_SMP))
		dma_wmb();
	return try_cmpxchg_release(entryp, &old_entry, table_entry);
}

#define PT_SUPPORTED_FEATURE(feature_nr) (PT_SUPPORTED_FEATURES & BIT(feature_nr))

static inline bool pt_feature(const struct pt_common *common,
			      unsigned int feature_nr)
{
	if (PT_FORCE_ENABLED_FEATURES & BIT(feature_nr))
		return true;
	if (!PT_SUPPORTED_FEATURE(feature_nr))
		return false;
	return common->features & BIT(feature_nr);
}

static inline bool pts_feature(const struct pt_state *pts,
			       unsigned int feature_nr)
{
	return pt_feature(pts->range->common, feature_nr);
}

/*
 * PT_WARN_ON is used for invariants that the kunit should be checking can't
 * happen.
 */
#if IS_ENABLED(CONFIG_DEBUG_GENERIC_PT)
#define PT_WARN_ON WARN_ON
#else
static inline bool PT_WARN_ON(bool condition)
{
	return false;
}
#endif

/* These all work on the VA type */
#define log2_to_int(a_lg2) log2_to_int_t(pt_vaddr_t, a_lg2)
#define log2_to_max_int(a_lg2) log2_to_max_int_t(pt_vaddr_t, a_lg2)
#define log2_div(a, b_lg2) log2_div_t(pt_vaddr_t, a, b_lg2)
#define log2_div_eq(a, b, c_lg2) log2_div_eq_t(pt_vaddr_t, a, b, c_lg2)
#define log2_mod(a, b_lg2) log2_mod_t(pt_vaddr_t, a, b_lg2)
#define log2_mod_eq_max(a, b_lg2) log2_mod_eq_max_t(pt_vaddr_t, a, b_lg2)
#define log2_set_mod(a, val, b_lg2) log2_set_mod_t(pt_vaddr_t, a, val, b_lg2)
#define log2_set_mod_max(a, b_lg2) log2_set_mod_max_t(pt_vaddr_t, a, b_lg2)
#define log2_mul(a, b_lg2) log2_mul_t(pt_vaddr_t, a, b_lg2)
#define log2_ffs(a) log2_ffs_t(pt_vaddr_t, a)
#define log2_fls(a) log2_fls_t(pt_vaddr_t, a)
#define log2_ffz(a) log2_ffz_t(pt_vaddr_t, a)

/*
 * The full va (fva) versions permit the lg2 value to be == PT_VADDR_MAX_LG2 and
 * generate a useful defined result. The non fva versions will malfunction at
 * this extreme.
 */
static inline pt_vaddr_t fvalog2_div(pt_vaddr_t a, unsigned int b_lg2)
{
	if (PT_SUPPORTED_FEATURE(PT_FEAT_FULL_VA) && b_lg2 == PT_VADDR_MAX_LG2)
		return 0;
	return log2_div_t(pt_vaddr_t, a, b_lg2);
}

static inline pt_vaddr_t fvalog2_mod(pt_vaddr_t a, unsigned int b_lg2)
{
	if (PT_SUPPORTED_FEATURE(PT_FEAT_FULL_VA) && b_lg2 == PT_VADDR_MAX_LG2)
		return a;
	return log2_mod_t(pt_vaddr_t, a, b_lg2);
}

static inline bool fvalog2_div_eq(pt_vaddr_t a, pt_vaddr_t b,
				  unsigned int c_lg2)
{
	if (PT_SUPPORTED_FEATURE(PT_FEAT_FULL_VA) && c_lg2 == PT_VADDR_MAX_LG2)
		return true;
	return log2_div_eq_t(pt_vaddr_t, a, b, c_lg2);
}

static inline pt_vaddr_t fvalog2_set_mod(pt_vaddr_t a, pt_vaddr_t val,
					 unsigned int b_lg2)
{
	if (PT_SUPPORTED_FEATURE(PT_FEAT_FULL_VA) && b_lg2 == PT_VADDR_MAX_LG2)
		return val;
	return log2_set_mod_t(pt_vaddr_t, a, val, b_lg2);
}

static inline pt_vaddr_t fvalog2_set_mod_max(pt_vaddr_t a, unsigned int b_lg2)
{
	if (PT_SUPPORTED_FEATURE(PT_FEAT_FULL_VA) && b_lg2 == PT_VADDR_MAX_LG2)
		return PT_VADDR_MAX;
	return log2_set_mod_max_t(pt_vaddr_t, a, b_lg2);
}

/* These all work on the OA type */
#define oalog2_to_int(a_lg2) log2_to_int_t(pt_oaddr_t, a_lg2)
#define oalog2_to_max_int(a_lg2) log2_to_max_int_t(pt_oaddr_t, a_lg2)
#define oalog2_div(a, b_lg2) log2_div_t(pt_oaddr_t, a, b_lg2)
#define oalog2_div_eq(a, b, c_lg2) log2_div_eq_t(pt_oaddr_t, a, b, c_lg2)
#define oalog2_mod(a, b_lg2) log2_mod_t(pt_oaddr_t, a, b_lg2)
#define oalog2_mod_eq_max(a, b_lg2) log2_mod_eq_max_t(pt_oaddr_t, a, b_lg2)
#define oalog2_set_mod(a, val, b_lg2) log2_set_mod_t(pt_oaddr_t, a, val, b_lg2)
#define oalog2_set_mod_max(a, b_lg2) log2_set_mod_max_t(pt_oaddr_t, a, b_lg2)
#define oalog2_mul(a, b_lg2) log2_mul_t(pt_oaddr_t, a, b_lg2)
#define oalog2_ffs(a) log2_ffs_t(pt_oaddr_t, a)
#define oalog2_fls(a) log2_fls_t(pt_oaddr_t, a)
#define oalog2_ffz(a) log2_ffz_t(pt_oaddr_t, a)

#define pt_cur_table(pts, type) ((type *)((pts)->table))

static inline uintptr_t _pt_top_set(struct pt_table_p *table_mem,
				    unsigned int top_level)
{
	return top_level | (uintptr_t)table_mem;
}

static inline void pt_top_set(struct pt_common *common,
			      struct pt_table_p *table_mem,
			      unsigned int top_level)
{
	WRITE_ONCE(common->top_of_table, _pt_top_set(table_mem, top_level));
}

static inline void pt_top_set_level(struct pt_common *common,
				    unsigned int top_level)
{
	pt_top_set(common, NULL, top_level);
}

static inline unsigned int pt_top_get_level(const struct pt_common *common)
{
	return READ_ONCE(common->top_of_table) % (1 << PT_TOP_LEVEL_BITS);
}

#endif
