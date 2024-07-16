/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __GENERIC_PT_IOMMU_H
#define __GENERIC_PT_IOMMU_H

#include <linux/generic_pt/common.h>
#include <linux/mm_types.h>

struct iommu_iotlb_gather;
struct pt_iommu_ops;
struct pt_iommu_flush_ops;

/**
 * DOC: IOMMU Radix Page Table
 *
 * The iommu implementation of the Generic Page Table provides an ops struct
 * that is useful to go with an iommu_domain to serve the DMA API, IOMMUFD and
 * the generic map/unmap interface.
 *
 * This interface uses a caller provided locking approach. The caller must have
 * a VA range lock concept that prevents concurrent threads from calling ops on
 * the same VA. Generally the range lock must be at least as large as a single
 * map call.
 */

/**
 * struct pt_iommu - Base structure for iommu page tables
 *
 * The format specific struct will include this as the first member.
 */
struct pt_iommu {
	/**
	 * @ops - Function pointers to access the API
	 */
	const struct pt_iommu_ops *ops;
	/**
	 * @hw_flush_ops - Function pointers provided by the HW driver to flush
	 * HW caches after changes to the page table.
	 */
	const struct pt_iommu_flush_ops *hw_flush_ops;

	/**
	 * @nid - Node ID to use for table memory allocations. This defaults to
	 * dev_to_node(iommu_device). The iommu driver may want to set the NID
	 * to the device's NID, if there are multiple table walkers.
	 */
	int nid;
	/* private: */
	/* Write lock for pt_common top_of_table */
	spinlock_t table_lock;
	struct device *iommu_device;
};

/**
 * struct pt_iommu_info - Details about the iommu page table
 *
 * Returned from pt_iommu_ops->get_info()
 */
struct pt_iommu_info {
	/**
	 * @pgsize_bitmap - A bitmask where each set bit indicates
	 * a page size that can be natively stored in the page table.
	 */
	u64 pgsize_bitmap;
};

struct pt_iommu_ops {
	/**
	 * map_pages() - Install translation for an IOVA range
	 * @iommu_table: Table to manipulate
	 * @iova: IO virtual address to start
	 * @paddr: Physical/Output address to start
	 * @len: Length of the range starting from @iova
	 * @prot: A bitmap of IOMMU_READ/WRITE/CACHE/NOEXEC/MMIO
	 * @gfp: GFP flags for any memory allocations
	 * @gather: Gather struct that must be flushed on return
	 *
	 * The range starting at IOVA will have paddr installed into it. The
	 * rage is automatically segmented into optimally sized table entries,
	 * and can have any valid alignment.
	 *
	 * On error the caller will probably want to invoke unmap on the range
	 * from iova up to the amount indicated by @mapped to return the table
	 * back to an unchanged state.
	 *
	 * Context: The caller must hold a write range lock that includes
	 * the whole range.
	 *
	 * Returns: -ERRNO on failure, 0 on success. The number of bytes of VA
	 * that were mapped are added to @mapped, @mapped is not zerod first.
	 */
	int (*map_pages)(struct pt_iommu *iommu_table, dma_addr_t iova,
			 phys_addr_t paddr, dma_addr_t len, unsigned int prot,
			 gfp_t gfp, size_t *mapped,
			 struct iommu_iotlb_gather *iotlb_gather);

	/**
	 * unmap_pages() - Make a range of IOVA empty/not present
	 * @iommu_table: Table to manipulate
	 * @iova: IO virtual address to start
	 * @len: Length of the range starting from @iova
	 * @gather: Gather struct that must be flushed on return
	 *
	 * unmap_pages() will remove translation created by map_pages().
	 * It cannot subdivide a mapping created by map_pages(),
	 * so it should be called with IOVA ranges that match those passed
	 * to map_pages. The IOVA range can aggregate contiguous map_pages() calls
	 * so long as no individual range is split.
	 *
	 * Context: The caller must hold a write range lock that includes
	 * the whole range.
	 *
	 * Returns: Number of bytes of VA unmapped. iova + res will be the
	 * point unmapping stopped.
	 */
	size_t (*unmap_pages)(struct pt_iommu *iommu_table, dma_addr_t iova,
			      dma_addr_t len,
			      struct iommu_iotlb_gather *iotlb_gather);

	/**
	 * cut_mapping() - Split a mapping
	 * @iommu_table: Table to manipulate
	 * @iova: IO virtual address to cut at
	 * @gfp: GFP flags for any memory allocations
	 *
	 * If map was used on [iova_a, iova_b] then unmap must be used on the
	 * same interval. When called twice this is useful to unmap a portion of
	 * a larger mapping.
	 *
	 * cut_mapping() changes the page table so that umap of both:
	 *    [iova_a, iova_c - 1]
	 *    [iova_c, iova_b]
	 * will work.
	 *
	 * In practice this is done by breaking up large pages into smaller
	 * pages so that no large page crosses iova_c.
	 *
	 * cut_mapping() works to ensure all page sizes that don't cross the cut
	 * remain at the optimal sizes.
	 *
	 * Context: The caller must hold a write range lock that includes the
	 * entire range used with the map that contains iova.
	 *
	 * Returns: -ERRNO on failure, 0 on success.
	 */
	int (*cut_mapping)(struct pt_iommu *iommu_table, dma_addr_t cut_iova,
			   gfp_t gfp);

	/**
	 * iova_to_phys() - Return the output address for the given IOVA
	 * @iommu_table: Table to query
	 * @iova: IO virtual address to query
	 *
	 * Determine the output address from the given IOVA. @iova may have any
	 * alignment, the returned physical will be adjusted with any sub page
	 * offset.
	 *
	 * Context: The caller must hold a read range lock that includes @iova.
	 *
	 * Return: 0 if there is no translation for the given iova.
	 */
	phys_addr_t (*iova_to_phys)(struct pt_iommu *iommu_table,
				    dma_addr_t iova);

	/**
	 * get_info() - Return the pt_iommu_info structure
	 * @iommu_table: Table to query
	 *
	 * Return some basic static information about the page table.
	 */
	void (*get_info)(struct pt_iommu *iommu_table,
			 struct pt_iommu_info *info);

	/**
	 * deinit() - Undo a format specific init operation
	 * @iommu_table: Table to destroy
	 *
	 * Release all of the memory. The caller must have already removed the
	 * table from all HW access and all caches.
	 */
	void (*deinit)(struct pt_iommu *iommu_table);
};

struct pt_iommu_flush_ops {
	/**
	 * flush_all() - Clear all caches related to this table. Any gather can
	 * be concluded by calling flush_all.
	 */
	void (*flush_all)(struct pt_iommu *iommu_table);
};


static inline void pt_iommu_deinit(struct pt_iommu *iommu_table)
{
	iommu_table->ops->deinit(iommu_table);
}

/**
  * struct pt_iommu_cfg - Common configuration values for all formats
  */
struct pt_iommu_cfg {
	/**
	 * @iommu_device - Device pointer used for any DMA cache flushing when
	 * PT_FEAT_DMA_INCOHERENT.
	 */
	struct device *iommu_device;
	/**
	 * @domain - Initialize the page table related members for this domain
	 * pointer.
	 */
	struct iommu_domain *domain;
	/**
	 * @features - Features required. Only these features will be turned on.
	 * The feature list should reflect what the IOMMU HW is capable of.
	 */
	unsigned int features;
	/**
	 * @hw_max_vasz_lg2 - Maximum VA the IOMMU HW can support. This will
	 * imply the top level of the table.
	 */
	u8 hw_max_vasz_lg2;
	/**
	 * @hw_max_oasz_lg2 - Maximum OA the IOMMU HW can support. The format
	 * might select a lower maximum OA.
	 */
	u8 hw_max_oasz_lg2;
};

#endif
