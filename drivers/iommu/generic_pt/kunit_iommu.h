/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __GENERIC_PT_KUNIT_IOMMU_H
#define __GENERIC_PT_KUNIT_IOMMU_H

#define GENERIC_PT_KUNIT 1
#include <kunit/device.h>
#include <kunit/test.h>
#include "pt_iter.h"

#define pt_iommu_table_cfg CONCATENATE(pt_iommu_table, _cfg)
#define pt_iommu_init CONCATENATE(CONCATENATE(pt_iommu_, PTPFX), init)
int pt_iommu_init(struct pt_iommu_table *fmt_table,
		  const struct pt_iommu_table_cfg *cfg, gfp_t gfp);

#ifndef pt_iommu_free_pgtbl_cfg
#define pt_iommu_free_pgtbl_cfg(cfg)
#endif

/* The format can provide a list of configurations it would like to test */
#ifdef kunit_fmt_cfgs
static const void *kunit_pt_gen_params_cfg(const void *prev, char *desc)
{
	uintptr_t cfg_id = (uintptr_t)prev;

	cfg_id++;
	if (cfg_id >= ARRAY_SIZE(kunit_fmt_cfgs) + 1)
		return NULL;
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s_cfg_%u",
		 __stringify(PTPFX_RAW), (unsigned int)(cfg_id - 1));
	return (void *)cfg_id;
}
#define KUNIT_CASE_FMT(test_name) \
	KUNIT_CASE_PARAM(test_name, kunit_pt_gen_params_cfg)
#else
#define KUNIT_CASE_FMT(test_name) KUNIT_CASE(test_name)
#endif

#define KUNIT_ASSERT_NO_ERRNO(test, ret)                                       \
	KUNIT_ASSERT_EQ_MSG(test, ret, 0, KUNIT_SUBSUBTEST_INDENT "errno %pe", \
			    ERR_PTR(ret))

#define KUNIT_ASSERT_NO_ERRNO_FN(test, fn, ret)                          \
	KUNIT_ASSERT_EQ_MSG(test, ret, 0,                                \
			    KUNIT_SUBSUBTEST_INDENT "errno %pe from %s", \
			    ERR_PTR(ret), fn)

/*
 * When the test is run on a 32 bit system dma_addr_t can be 32 bits. This cause
 * the iommu op signatures to be restricted to 32 bits. Meaning the test has to
 * be mindful not to create any VA's over the 32 bit limit. Reduce the scope of
 * the testing as the main purpose of checking on full 32 bit is to look for
 * 32bitism in the core code. Run the test on i386 with X86_PAE=y to get the
 * full coverage.
 */
#define IS_32BIT (sizeof(dma_addr_t) == 4)

struct kunit_iommu_priv {
	struct pt_iommu_table fmt_table;
	spinlock_t top_lock;
	struct device *dummy_dev;
	struct pt_iommu *iommu;
	struct pt_common *common;
	struct pt_iommu_table_cfg cfg;
	struct pt_iommu_info info;
	unsigned int smallest_pgsz_lg2;
	pt_vaddr_t smallest_pgsz;
	unsigned int largest_pgsz_lg2;
	pt_oaddr_t test_oa;
	pt_vaddr_t safe_pgsize_bitmap;
};

static void pt_kunit_change_top(struct pt_iommu *iommu_table,
				phys_addr_t top_paddr, unsigned int top_level)
{
}

static spinlock_t *pt_kunit_get_top_lock(struct pt_iommu *iommu_table)
{
	struct kunit_iommu_priv *priv = container_of(
		iommu_table, struct kunit_iommu_priv, fmt_table.iommu);

	return &priv->top_lock;
}

static const struct pt_iommu_flush_ops pt_kunit_flush_ops = {
	.change_top = &pt_kunit_change_top,
	.get_top_lock = &pt_kunit_get_top_lock,
};

static int pt_kunit_priv_init(struct kunit *test, struct kunit_iommu_priv *priv)
{
	unsigned int va_lg2sz;
	int ret;

	/* Enough so the memory allocator works */
	priv->dummy_dev = kunit_device_register(test, "pt_kunit_dev");
	if (IS_ERR(priv->dummy_dev))
		return PTR_ERR(priv->dummy_dev);
	set_dev_node(priv->dummy_dev, NUMA_NO_NODE);

	spin_lock_init(&priv->top_lock);

#ifdef kunit_fmt_cfgs
	priv->cfg = kunit_fmt_cfgs[((uintptr_t)test->param_value) - 1];
	/*
	 * The format can set a list of features that the kunit_fmt_cfgs
	 * controls, other features are default to on.
	 */
	priv->cfg.common.features |= PT_SUPPORTED_FEATURES &
				     (~KUNIT_FMT_FEATURES);
#else
	priv->cfg.common.features = PT_SUPPORTED_FEATURES;
#endif

	/* Defaults, for the kunit*/
	if (!priv->cfg.common.hw_max_vasz_lg2)
		priv->cfg.common.hw_max_vasz_lg2 = PT_MAX_VA_ADDRESS_LG2;
	if (!priv->cfg.common.hw_max_oasz_lg2)
		priv->cfg.common.hw_max_oasz_lg2 =
			pt_max_output_address_lg2(NULL);

	/* DMA flushing can't be tested using the kunit device */
	priv->cfg.common.features &= ~BIT(PT_FEAT_DMA_INCOHERENT);
	priv->fmt_table.iommu.nid = NUMA_NO_NODE;
	priv->fmt_table.iommu.iommu_device = priv->dummy_dev;
	priv->fmt_table.iommu.hw_flush_ops = &pt_kunit_flush_ops;

	ret = pt_iommu_init(&priv->fmt_table, &priv->cfg, GFP_KERNEL);
	if (ret)
		return ret;
	priv->iommu = &priv->fmt_table.iommu;
	priv->common = common_from_iommu(&priv->fmt_table.iommu);

	if (IS_32BIT && pt_top_range(priv->common).va >= U32_MAX) {
		kunit_skip(test,
			   "This configuration cannot be tested on 32 bit");
		return -EOPNOTSUPP;
	}

	priv->iommu->ops->get_info(priv->iommu, &priv->info);

	/*
	 * size_t is used to pass the mapping length, it can be 32 bit, truncate
	 * the pagesizes so we don't use large sizes.
	 */
	priv->info.pgsize_bitmap = (size_t)priv->info.pgsize_bitmap;

	priv->smallest_pgsz_lg2 = log2_ffs(priv->info.pgsize_bitmap);
	priv->smallest_pgsz = log2_to_int(priv->smallest_pgsz_lg2);
	priv->largest_pgsz_lg2 =
		log2_fls((dma_addr_t)priv->info.pgsize_bitmap) - 1;

	priv->test_oa = oalog2_mod(0x74a71445deadbeef,
				   pt_max_output_address_lg2(priv->common));

	/*
	 * We run out of VA space if the mappings get too big, make something
	 * smaller that can safely pass throug dma_addr_t API.
	 */
	va_lg2sz = priv->common->max_vasz_lg2;
	if (IS_32BIT && va_lg2sz > 32)
		va_lg2sz = 32;
	priv->safe_pgsize_bitmap =
		log2_mod(priv->info.pgsize_bitmap, va_lg2sz - 1);

	return 0;
}

#endif
