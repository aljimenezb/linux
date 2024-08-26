/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#include "kunit_iommu.h"
#include "pt_iter.h"
#include <linux/iommu.h>
#include <linux/io-pgtable.h>

#ifndef PT_KUNIT_IO_PGTBL_DYNAMIC_TOP
#define PT_KUNIT_IO_PGTBL_DYNAMIC_TOP 0
#endif

struct kunit_iommu_cmp_priv {
	/* Generic PT version */
	struct kunit_iommu_priv fmt;

	/* IO pagetable version */
	struct io_pgtable_ops *pgtbl_ops;
	struct io_pgtable_cfg *fmt_memory;
	struct pt_iommu_table ref_table;
};

#if IS_ENABLED(CONFIG_IOMMU_PT_KUNIT_BENCHMARK)

#define LOOPS 10000

#define START_TIMER(id)	ktime_t start_##id = ktime_get()

#define STOP_TIMER(id) ktime_to_ns(ktime_sub(ktime_get(), start_##id))

typedef void (*benchmark_fn_t)(struct kunit *test, void *test_args,
			       unsigned int pgsz_lg2);

struct map_unmap_test_cfg {
	unsigned int iopte_cnt;
	pt_vaddr_t pgsize_bitmap;
	struct cmp_benchmark_results *cmp_results;
	const char *desc;
};

enum pt_impl_type {
	GENPT_IMPL,
	IOPT_IMPL,
	PT_IMPL_TYPE_MAX,
};

struct benchmark_times {
	ktime_t avg_time;
	ktime_t max_time;
	ktime_t min_time;
};

struct cmp_benchmark_results {
	struct benchmark_times map_timing[PT_IMPL_TYPE_MAX];
	struct benchmark_times unmap_timing[PT_IMPL_TYPE_MAX];
};

#endif

struct compare_tables {
	struct kunit *test;
	struct pt_range ref_range;
	struct pt_table_p *ref_table;
};

static int __compare_tables(struct pt_range *range, void *arg,
			    unsigned int level, struct pt_table_p *table)
{
	struct pt_state pts = pt_init(range, level, table);
	struct compare_tables *cmp = arg;
	struct pt_state ref_pts =
		pt_init(&cmp->ref_range, level, cmp->ref_table);
	struct kunit *test = cmp->test;
	int ret;

	for_each_pt_level_item(&pts) {
		u64 entry, ref_entry;

		cmp->ref_range.va = range->va;
		ref_pts.index = pts.index;
		pt_load_entry(&ref_pts);

		entry = pt_kunit_cmp_mask_entry(&pts);
		ref_entry = pt_kunit_cmp_mask_entry(&ref_pts);

		/*if (entry != 0 || ref_entry != 0)
			printk("Check %llx Level %u index %u ptr %px refptr %px: %llx (%llx) %llx (%llx)\n",
			       pts.range->va, pts.level, pts.index,
			       pts.table,
			       ref_pts.table,
			       pts.entry, entry,
			       ref_pts.entry, ref_entry);*/

		KUNIT_ASSERT_EQ(test, pts.type, ref_pts.type);
		KUNIT_ASSERT_EQ(test, entry, ref_entry);
		if (entry != ref_entry)
			return 0;

		if (pts.type == PT_ENTRY_TABLE) {
			cmp->ref_table = ref_pts.table_lower;
			ret = pt_descend(&pts, arg, __compare_tables);
			if (ret)
				return ret;
		}

		/* Defeat contiguous entry aggregation */
		pts.type = PT_ENTRY_EMPTY;
	}

	return 0;
}

static void compare_tables(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	struct pt_range range = pt_top_range(priv->common);
	struct compare_tables cmp = {
		.test = test,
	};
	struct pt_state pts = pt_init_top(&range);
	struct pt_state ref_pts;

	pt_iommu_setup_ref_table(&cmp_priv->ref_table, cmp_priv->pgtbl_ops);
	cmp.ref_range =
		pt_top_range(common_from_iommu(&cmp_priv->ref_table.iommu));
	ref_pts = pt_init_top(&cmp.ref_range);
	KUNIT_ASSERT_EQ(test, pts.level, ref_pts.level);

	cmp.ref_table = ref_pts.table;
	KUNIT_ASSERT_EQ(test, pt_walk_range(&range, __compare_tables, &cmp), 0);
}

static void test_cmp_init(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(cmp_priv->pgtbl_ops)->cfg;

	/* Fixture does the setup */
	KUNIT_ASSERT_NE(test, priv->info.pgsize_bitmap, 0);

	/* pt_iommu has a superset of page sizes (ARM supports contiguous) */
	KUNIT_ASSERT_EQ(test,
			priv->info.pgsize_bitmap & pgtbl_cfg->pgsize_bitmap,
			pgtbl_cfg->pgsize_bitmap);

	/* Empty compare works */
	compare_tables(test);
}

static void do_cmp_map(struct kunit *test, pt_vaddr_t va, pt_oaddr_t pa,
		       pt_oaddr_t len, unsigned int prot)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	const struct pt_iommu_ops *ops = priv->iommu->ops;
	size_t mapped;
	int ret;

	/* This lacks pagination, must call with perfectly aligned everything */
	if (sizeof(unsigned long) == 8) {
		KUNIT_ASSERT_EQ(test, va % len, 0);
		KUNIT_ASSERT_EQ(test, pa % len, 0);
	}

	mapped = 0;
	ret = ops->map_range(priv->iommu, va, pa, len, prot, GFP_KERNEL,
			     &mapped, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, mapped, len);

	mapped = 0;
	ret = cmp_priv->pgtbl_ops->map_pages(cmp_priv->pgtbl_ops, va, pa, len,
					     1, prot, GFP_KERNEL, &mapped);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, mapped, len);
}

static void do_cmp_unmap(struct kunit *test, pt_vaddr_t va, pt_vaddr_t len)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	const struct pt_iommu_ops *ops = priv->iommu->ops;
	size_t ret;

	if (sizeof(unsigned long) != 4)
		KUNIT_ASSERT_EQ(test, va % len, 0);

	ret = ops->unmap_range(priv->iommu, va, len, NULL);
	KUNIT_ASSERT_EQ(test, ret, len);
	ret = cmp_priv->pgtbl_ops->unmap_pages(cmp_priv->pgtbl_ops, va, len, 1,
					       NULL);
	KUNIT_ASSERT_EQ(test, ret, len);
}

#if IS_ENABLED(CONFIG_IOMMU_PT_KUNIT_BENCHMARK)

static inline void compute_map_timing_stats(struct cmp_benchmark_results *entry,
				 unsigned int iterations)
{
	struct benchmark_times *map_timing =
		(struct benchmark_times *)entry->map_timing;
	struct benchmark_times *unmap_timing =
		(struct benchmark_times *)&entry->unmap_timing;

	map_timing[GENPT_IMPL].avg_time =
		div64_ul(map_timing[GENPT_IMPL].avg_time, iterations);

	map_timing[IOPT_IMPL].avg_time =
		div64_ul(map_timing[IOPT_IMPL].avg_time, iterations);

	unmap_timing[GENPT_IMPL].avg_time =
		div64_ul(unmap_timing[GENPT_IMPL].avg_time, iterations);

	unmap_timing[IOPT_IMPL].avg_time =
		div64_ul(unmap_timing[IOPT_IMPL].avg_time, iterations);
}

static inline size_t iommu_pgsize_eq(pt_vaddr_t pgsize_bitmap, pt_vaddr_t va,
                                  pt_oaddr_t pa, size_t size, size_t *count)
{
        unsigned int pgsize_idx, pgsize_idx_next;
        unsigned long pgsizes;
        size_t offset, pgsize, pgsize_next;
        unsigned long addr_merge = pa | va;

        /* Page sizes supported by the hardware and small enough for @size */
        pgsizes = pgsize_bitmap & GENMASK(__fls(size), 0);

        /* Constrain the page sizes further based on the maximum alignment */
        if (likely(addr_merge))
                pgsizes &= GENMASK(__ffs(addr_merge), 0);

        /* Make sure we have at least one suitable page size */
        BUG_ON(!pgsizes);

        /* Pick the biggest page size remaining */
        pgsize_idx = __fls(pgsizes);
        pgsize = BIT(pgsize_idx);
        if (!count)
                return pgsize;

        /* Find the next biggest support page size, if it exists */
        pgsizes = pgsize_bitmap & ~GENMASK(pgsize_idx, 0);
        if (!pgsizes)
                goto out_set_count;

        pgsize_idx_next = __ffs(pgsizes);
        pgsize_next = BIT(pgsize_idx_next);

        /*
         * There's no point trying a bigger page size unless the virtual
         * and physical addresses are similarly offset within the larger page.
         */
        if ((va ^ pa) & (pgsize_next - 1))
                goto out_set_count;

        /* Calculate the offset to the next page size alignment boundary */
        offset = pgsize_next - (addr_merge & (pgsize_next - 1));

        /*
         * If size is big enough to accommodate the larger page, reduce
         * the number of smaller pages.
         */
        if (offset + pgsize_next <= size)
                size = offset;

out_set_count:
        *count = size >> pgsize_idx;
        return pgsize;
}

static noinline int __iommu_map_eq(struct kunit_iommu_cmp_priv *cmp_priv,
				   unsigned long iova, phys_addr_t paddr,
				   size_t size)
{
        struct kunit_iommu_priv *genpt_priv = &cmp_priv->fmt;
	struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(cmp_priv->pgtbl_ops)->cfg;
	pt_vaddr_t pgsize_bitmap = genpt_priv->safe_pgsize_bitmap &
				   pgtbl_cfg->pgsize_bitmap;
	unsigned int prot = (IOMMU_READ | IOMMU_WRITE);
	unsigned int min_pagesz;
	int ret = 0;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(pgsize_bitmap);

	/*
	 * both the virtual address and the physical one, as well as
	 * the size of the mapping, must be aligned (at least) to the
	 * size of the smallest page supported by the hardware
	 */
	if (!IS_ALIGNED(iova | paddr | size, min_pagesz))
		return -EINVAL;

	while (size) {
		size_t pgsize, count, mapped = 0;

                pgsize = iommu_pgsize_eq(pgsize_bitmap, iova, paddr, size, &count);

		ret = cmp_priv->pgtbl_ops->map_pages(cmp_priv->pgtbl_ops, iova,
						     paddr, pgsize, count, prot,
						     GFP_KERNEL, &mapped);
		/*
		 * Some pages may have been mapped, even if an error occurred,
		 * so we should account for those so they can be unmapped.
		 */
		size -= mapped;

		if (ret)
			break;

		iova += mapped;
		paddr += mapped;
	}

	return ret;
}

static inline void update_min_time(ktime_t *cur_min, ktime_t delta)
{
	if (likely(*cur_min))
		*cur_min = min_t(ktime_t, *cur_min, delta);
	else
		*cur_min = delta;
}

static inline void update_max_time(ktime_t *cur_max, ktime_t delta)
{
	*cur_max = max_t(ktime_t, *cur_max, delta);
}

static inline void update_measurements(struct benchmark_times *timing, ktime_t delta)
{
	timing->avg_time += delta;

	update_max_time(&timing->max_time, delta);

	update_min_time(&timing->min_time, delta);
}

static void time_map_pages(struct kunit *test, pt_vaddr_t va, pt_oaddr_t pa,
			   pt_vaddr_t len, struct benchmark_times *map_timing)
{

	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	const struct pt_iommu_ops *ops = priv->iommu->ops;

	ktime_t delta;
	unsigned int prot = (IOMMU_READ | IOMMU_WRITE);
	size_t mapped = 0;
	int ret_map;

	START_TIMER(genpt);
	ret_map = ops->map_range(priv->iommu, va, pa, len, prot, GFP_KERNEL,
				 &mapped, NULL);
	delta = STOP_TIMER(genpt);

	update_measurements(&map_timing[GENPT_IMPL], delta);

	KUNIT_EXPECT_EQ(test, ret_map, 0);
	KUNIT_EXPECT_EQ(test, mapped, len);
	/*
	 * Emulate overhead from the iommu common code before calling io pgtbl
	 * operations. i.e.
	 *
	 * iommu_map()
	 *      __iommu_map()
	 *              iommu_pgsize()
	 * For now, assume Non-present table entries are not cached, i.e.
	 * there is no overhead in iommu_map() due to calling:
	 * iotlb_sync_map()-->domain_flush_np_cache().
	 */
	START_TIMER(iopt);

	ret_map = __iommu_map_eq(cmp_priv, va, pa, len);

	delta = STOP_TIMER(iopt);

	update_measurements(&map_timing[IOPT_IMPL], delta);

	KUNIT_EXPECT_EQ(test, ret_map, 0);

        /*
         * TODO: verify that the requested length was completely mapped. Easy
         * but perhaps not needed since other tests confirm it already.
         */
        //KUNIT_EXPECT_EQ(test, mapped, len);
}

static size_t noinline __iommu_unmap_eq(
	struct kunit_iommu_cmp_priv *cmp_priv, unsigned long iova, size_t size,
	struct iommu_iotlb_gather *iotlb_gather)
{
        struct kunit_iommu_priv *genpt_priv = &cmp_priv->fmt;
	struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(cmp_priv->pgtbl_ops)->cfg;
	pt_vaddr_t pgsize_bitmap = genpt_priv->safe_pgsize_bitmap &
				   pgtbl_cfg->pgsize_bitmap;
	size_t unmapped_page, unmapped = 0;
	unsigned int min_pagesz;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(pgsize_bitmap);

	/*
	 * The virtual address, as well as the size of the mapping, must be
	 * aligned (at least) to the size of the smallest page supported
	 * by the hardware
	 */
	if (!IS_ALIGNED(iova | size, min_pagesz))
		return 0;

	/*
	 * Keep iterating until we either unmap 'size' bytes (or more)
	 * or we hit an area that isn't mapped.
	 */
	while (unmapped < size) {
		size_t pgsize, count;

		pgsize = iommu_pgsize_eq(pgsize_bitmap, iova, iova, size - unmapped, &count);
		unmapped_page = cmp_priv->pgtbl_ops->unmap_pages(
			cmp_priv->pgtbl_ops, iova, pgsize, count, iotlb_gather);
		if (!unmapped_page)
			break;

		iova += unmapped_page;
		unmapped += unmapped_page;
	}
	return unmapped;
}

static void time_unmap_pages(struct kunit *test, pt_vaddr_t va, pt_vaddr_t len,
			     struct benchmark_times *unmap_timing)
{

	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	const struct pt_iommu_ops *ops = priv->iommu->ops;
	size_t ret_unmap;
	ktime_t delta;

	START_TIMER(genpt);
	ret_unmap = ops->unmap_range(priv->iommu, va, len, NULL);
	delta = STOP_TIMER(genpt);

	update_measurements(&unmap_timing[GENPT_IMPL], delta);

	KUNIT_EXPECT_EQ(test, ret_unmap, len);

	START_TIMER(iopt);
	ret_unmap = __iommu_unmap_eq(cmp_priv, va, len, NULL);
	delta = STOP_TIMER(iopt);

	update_measurements(&unmap_timing[IOPT_IMPL], delta);

	KUNIT_EXPECT_EQ(test, ret_unmap, len);
}

/*
 * Test {un}map_pages(), no mem allocation.
 */
static void do_map_unmap_benchmark(struct kunit *test,
				   void *test_args,
				   unsigned int pgsz_lg2)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *genpt_priv = &cmp_priv->fmt;

	struct map_unmap_test_cfg *test_case = test_args;

	struct pt_range top_range = pt_top_range(cmp_priv->fmt.common);
	struct cmp_benchmark_results *benchmark_entry =
		&test_case->cmp_results[pgsz_lg2];

	struct benchmark_times *map_timing =
		(struct benchmark_times *)benchmark_entry->map_timing;
	struct benchmark_times *unmap_timing =
		(struct benchmark_times *)benchmark_entry->unmap_timing;

	unsigned int loops = 0;

	pt_vaddr_t test_va, len;
	pt_oaddr_t test_pa;

	/*
	 * Enforce minimum pgsize alignment requirement for pa/va.
	 * test_oa is initialized during test suite init.
	 */
	test_pa = oalog2_set_mod(genpt_priv->test_oa, 0, pgsz_lg2);
	test_va = ALIGN(top_range.va + genpt_priv->smallest_pgsz,
			log2_to_int(pgsz_lg2));

	/* If test case does not specify IOPTE count, assume 1 */
	if (!test_case->iopte_cnt)
		test_case->iopte_cnt = 1;

	len = test_case->iopte_cnt * log2_to_int(pgsz_lg2);
	/* Throw away first mapping to avoid timing memory allocation */
	time_map_pages(test, test_va, test_pa, len, map_timing);
	time_unmap_pages(test, test_va, len, unmap_timing);
	memset(benchmark_entry, 0, sizeof(*benchmark_entry));

	/* FIXME, I noticed these do memory allocations anyhow, so something is
	 * wrong */

	/* Timing loop */
	for (loops = 0; loops < LOOPS; loops++) {

		/* map_pages() benchmark */
		time_map_pages(test, test_va, test_pa, len, map_timing);

		/* unmap_pages() benchmark */
		time_unmap_pages(test, test_va, len, unmap_timing);

		/*
		 * TODO: Ensure that va does not exceed valid range.
		 * PA overflows a lot faster since OA_MAX is 52 bits.
		 * Ultimately there is no need to increase PA and the
		 * incremental VAs can all be mapped to same PA.
		 * TODO: Implement fair increment of PA/VA
		 */
	}

	/*
	 * Calculate avg duration for both implementations.
	 * TODO: use MEASURE_{} macros to improve readability.
	 */
	compute_map_timing_stats(benchmark_entry, loops);
}

static inline void test_on_valid_pgsize(struct kunit *test, benchmark_fn_t fn,
				void *test_args, pt_vaddr_t pgsize_bitmap)
{
	unsigned int pgsz_lg2;

	for (pgsz_lg2 = 0; pgsz_lg2 != PT_VADDR_MAX_LG2; pgsz_lg2++) {

		/* Skip unsupported page sizes */
		if (!(pgsize_bitmap & log2_to_int(pgsz_lg2)))
			 continue;

		fn(test, test_args, pgsz_lg2);
	}
}

#define REPORT_BANNER_STR(op)						\
	"\n" op " \npgsz,genpt,iopt,min_genpt,min_iopt,max_genpt,max_iopt\n"

#define REPORT_FMT_STR	"%u, %lld, %lld, %lld, %lld, %lld, %lld\n"

#define REPORT_PARAM_LIST						\
	idx, result[GENPT_IMPL].avg_time, result[IOPT_IMPL].avg_time,	\
	result[GENPT_IMPL].min_time, result[IOPT_IMPL].min_time,	\
	result[GENPT_IMPL].max_time, result[IOPT_IMPL].max_time		\

static void report_timing_results(struct kunit *test, pt_vaddr_t pgsize_bitmap,
				  struct cmp_benchmark_results *cmp_results)
{
	/*
	 * Now all the timing results have been populated, output them in CSV
	 * format for plotting.
	 */
	kunit_info(test, REPORT_BANNER_STR("map_pages"));
	for (int idx = 0; idx < PT_VADDR_MAX_LG2; idx++) {
		if (!(pgsize_bitmap & BIT(idx)))
			continue;

		struct benchmark_times *result =
			(struct benchmark_times *)cmp_results[idx].map_timing;

		pr_info(REPORT_FMT_STR, REPORT_PARAM_LIST);
	}

	kunit_info(test, REPORT_BANNER_STR("unmap_pages"));
	for (int idx = 0; idx < PT_VADDR_MAX_LG2; idx++) {
		if (!(pgsize_bitmap & BIT(idx)))
			continue;

		struct benchmark_times *result =
			(struct benchmark_times *)cmp_results[idx].unmap_timing;

		pr_info(REPORT_FMT_STR, REPORT_PARAM_LIST);
	}

	memset(cmp_results, 0, sizeof(*cmp_results));
}

struct map_unmap_test_cfg NS(map_unmap_tests)[] = {
	{
		.iopte_cnt = 1,
		.desc = "Single IOPTE",
	},
	{
		.iopte_cnt = 256,
		.pgsize_bitmap = (SZ_4K | SZ_2M | SZ_1G),
		.desc = "256 IOPTE",
	},
};

/*
 * Benchmark map/unmap various combinations defined by NS(map_unmap_tests) list.
 * This test is a clear candidate for the parameterized testing support offered
 * by Kunit framework, but that facility is already in use for testing of format
 * specific features, so set this up manually.
 */
static void test_map_unmap_benchmark(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *genpt_priv = &cmp_priv->fmt;

	/*
	 * Use safe pgsize_bitmap determined during test initialization as
	 * baseline, and restrict the pgsizes if required by specific tests.
	 */
	pt_vaddr_t pgsize_bitmap = genpt_priv->safe_pgsize_bitmap;

	/*
	 * Allocate array of struct commpare_timings holding PT_VADDR_MAX_LG2
	 * entries for comparison benchmarks. Entries for unsupported pagesizes
	 * are wasted, so this can be optimized.
	 */
	struct cmp_benchmark_results *cmp_results =
		kunit_kzalloc(test, sizeof(*cmp_results) * PT_VADDR_MAX_LG2,
				GFP_KERNEL);

	for (unsigned int i = 0; i < ARRAY_SIZE(NS(map_unmap_tests)); i++) {

		/* Restrict supported pagesizes if test case requests it */
		if (NS(map_unmap_tests)[i].pgsize_bitmap)
			pgsize_bitmap &= NS(map_unmap_tests)[i].pgsize_bitmap;

		NS(map_unmap_tests)[i].cmp_results = cmp_results;

		test_on_valid_pgsize(test, do_map_unmap_benchmark,
				     &NS(map_unmap_tests)[i],
				     pgsize_bitmap);

		kunit_info(test, "\nTest case: %s\n",
			   NS(map_unmap_tests)[i].desc);

		report_timing_results(test, pgsize_bitmap, cmp_results);
	}
}
#endif

static void test_cmp_one_map(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	struct pt_range range = pt_top_range(priv->common);
	struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(cmp_priv->pgtbl_ops)->cfg;
	const pt_oaddr_t addr =
		oalog2_mod(0x74a71445deadbeef, priv->common->max_oasz_lg2);
	pt_vaddr_t pgsize_bitmap = priv->safe_pgsize_bitmap &
				   pgtbl_cfg->pgsize_bitmap;
	pt_vaddr_t cur_va;
	unsigned int prot = 0;
	unsigned int pgsz_lg2;

	/*
	 * Check that every prot combination at every page size level generates
	 * the same data in page table.
	 */
	for (prot = 0; prot <= (IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE |
				IOMMU_NOEXEC | IOMMU_MMIO);
	     prot++) {
		/* Page tables usually cannot represent inaccessible memory */
		if (!(prot & (IOMMU_READ | IOMMU_WRITE)))
			continue;

		/* Try every supported page size */
		cur_va = range.va + priv->smallest_pgsz * 256;
		for (pgsz_lg2 = 0; pgsz_lg2 != PT_VADDR_MAX_LG2; pgsz_lg2++) {
			pt_vaddr_t len = log2_to_int(pgsz_lg2);

			if (!(pgsize_bitmap & len))
				continue;

			cur_va = ALIGN(cur_va, len);
			do_cmp_map(test, cur_va,
				   oalog2_set_mod(addr, 0, pgsz_lg2), len,
				   prot);
			compare_tables(test);
			cur_va += len;
		}

		cur_va = range.va + priv->smallest_pgsz * 256;
		for (pgsz_lg2 = 0; pgsz_lg2 != PT_VADDR_MAX_LG2; pgsz_lg2++) {
			pt_vaddr_t len = log2_to_int(pgsz_lg2);

			if (!(pgsize_bitmap & len))
				continue;

			cur_va = ALIGN(cur_va, len);
			do_cmp_unmap(test, cur_va, len);
			compare_tables(test);
			cur_va += len;
		}
	}
}

static void test_cmp_high_va(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	unsigned int max_vasz_lg2;
	pt_vaddr_t last;

	if (PT_KUNIT_IO_PGTBL_DYNAMIC_TOP)
		max_vasz_lg2 = priv->common->max_vasz_lg2;
	else
		max_vasz_lg2 = pt_top_range(priv->common).max_vasz_lg2;

	last = fvalog2_set_mod_max(pt_full_va_prefix(priv->common),
				   max_vasz_lg2);
	/*
	 * Map the very end of the page VA space. This triggers increase on
	 * AMDv1. io_pgtable_ops uses an unsigned long for the va instead
	 * of dma_addr_t, so it truncates when it shouldn't.
	 */
	if (sizeof(unsigned long) == 4 && last >= U32_MAX)
		last = (u32)last;
	do_cmp_map(test, last - (priv->smallest_pgsz - 1), 0,
		   priv->smallest_pgsz, IOMMU_READ | IOMMU_WRITE);
	compare_tables(test);
}

/*
 * Check what happens when a large page is split. iopt always unmaps the full
 * page. Test every pairing of mapping a large page and unmapping the start
 * using every smaller page size.
 */
static void test_cmp_unmap_split(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct io_pgtable_ops *iopt_ops = cmp_priv->pgtbl_ops;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;
	const struct pt_iommu_ops *ops = priv->iommu->ops;
	struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(iopt_ops)->cfg;
	struct pt_range top_range = pt_top_range(priv->common);
	pt_vaddr_t pgsize_bitmap = priv->safe_pgsize_bitmap &
				   pgtbl_cfg->pgsize_bitmap;
	unsigned int pgsz_lg2;
	unsigned int count = 0;

	if (IS_ENABLED(PT_KUNIT_UNMAP_EXACT))
		kunit_skip(test, "Old implementation requires exact unmap, can't test");

	for (pgsz_lg2 = 0; pgsz_lg2 != PT_VADDR_MAX_LG2; pgsz_lg2++) {
		pt_vaddr_t base_len = log2_to_int(pgsz_lg2);
		unsigned int next_pgsz_lg2;

		if (!(pgsize_bitmap & base_len))
			continue;

		for (next_pgsz_lg2 = pgsz_lg2 + 1;
		     next_pgsz_lg2 != PT_VADDR_MAX_LG2; next_pgsz_lg2++) {
			pt_vaddr_t next_len = log2_to_int(next_pgsz_lg2);
			pt_vaddr_t vaddr = top_range.va;
			pt_oaddr_t paddr = 0;
			size_t genpt_unmapped;
			size_t iopt_unmapped;

			if (!(pgsize_bitmap & next_len))
				continue;

			do_cmp_map(test, vaddr, paddr, next_len,
				   IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
			compare_tables(test);

			genpt_unmapped = ops->unmap_range(priv->iommu, vaddr,
							  base_len, NULL);

			iopt_unmapped = iopt_ops->unmap_pages(
				cmp_priv->pgtbl_ops, vaddr, base_len, 1, NULL);
			compare_tables(test);

			KUNIT_ASSERT_EQ(test, genpt_unmapped, iopt_unmapped);
			KUNIT_ASSERT_EQ(test, genpt_unmapped, next_len);

			count++;
		}
	}

	if (count == 0)
		kunit_skip(test, "Test needs two page sizes");
}

static int pt_kunit_iommu_cmp_init(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv;
	struct kunit_iommu_priv *priv;
	int ret;

	test->priv = cmp_priv = kzalloc(sizeof(*cmp_priv), GFP_KERNEL);
	if (!cmp_priv)
		return -ENOMEM;
	priv = &cmp_priv->fmt;

	ret = pt_kunit_priv_init(test, priv);
	if (ret)
		goto err_priv;

	/* io-pgtable uses unsigned long for passing the IOVA, not dma_addr_t */
	if (pt_top_range(priv->common).va >= ULONG_MAX) {
		kunit_skip(test,
			   "This configuration cannot be tested on 32 bit");
		return -EOPNOTSUPP;
	}

	cmp_priv->pgtbl_ops = pt_iommu_alloc_io_pgtable(
		&priv->cfg, priv->dummy_dev, &cmp_priv->fmt_memory);
	if (cmp_priv->pgtbl_ops == ERR_PTR(-EOPNOTSUPP)) {
		cmp_priv->pgtbl_ops = NULL;
		kunit_skip(test,
			   "io-pgtable does not support this configuration");
		return -EOPNOTSUPP;
	}
	if (!cmp_priv->pgtbl_ops) {
		ret = -ENOMEM;
		goto err_fmt_table;
	}

	cmp_priv->ref_table = priv->fmt_table;
	return 0;

err_fmt_table:
	pt_iommu_deinit(priv->iommu);
err_priv:
	kfree(test->priv);
	test->priv = NULL;
	return ret;
}

static void pt_kunit_iommu_cmp_exit(struct kunit *test)
{
	struct kunit_iommu_cmp_priv *cmp_priv = test->priv;
	struct kunit_iommu_priv *priv = &cmp_priv->fmt;

	if (!test->priv)
		return;

	if (cmp_priv->pgtbl_ops) {
		free_io_pgtable_ops(cmp_priv->pgtbl_ops);
		pt_iommu_free_pgtbl_cfg(cmp_priv->fmt_memory);
	}
	pt_iommu_deinit(priv->iommu);
	kfree(test->priv);
}

static struct kunit_case cmp_test_cases[] = {
	KUNIT_CASE_FMT(test_cmp_init),
	KUNIT_CASE_FMT(test_cmp_one_map),
	KUNIT_CASE_FMT(test_cmp_high_va),
	KUNIT_CASE_FMT(test_cmp_unmap_split),
#if IS_ENABLED(CONFIG_IOMMU_PT_KUNIT_BENCHMARK)
	KUNIT_CASE_FMT(test_map_unmap_benchmark),
#endif
	{},
};

static struct kunit_suite NS(cmp_suite) = {
	.name = __stringify(NS(iommu_cmp_test)),
	.init = pt_kunit_iommu_cmp_init,
	.exit = pt_kunit_iommu_cmp_exit,
	.test_cases = cmp_test_cases,
};
kunit_test_suites(&NS(cmp_suite));
