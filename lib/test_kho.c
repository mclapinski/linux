// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test module for KHO
 * Copyright (c) 2025 Microsoft Corporation.
 *
 * Authors:
 *   Saurabh Sengar <ssengar@microsoft.com>
 *   Mike Rapoport <rppt@kernel.org>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kexec_handover.h>

#include <net/checksum.h>

#define KHO_TEST_COMPAT "kho-test-v1"

static long max_mem = SZ_1G;
// module_param(max_mem, long, 0644);

/*
 * When exhaust_lowmem is set, the test will first allocate pages to
 * exhaust lower physical memory, forcing subsequent test allocations
 * to come from higher physical addresses. This helps trigger bugs
 * related to CONFIG_DEFERRED_STRUCT_PAGE_INIT where struct pages for
 * high memory may not be initialized when KHO tries to access them.
 */
static bool exhaust_lowmem;
module_param(exhaust_lowmem, bool, 0644);

static bool second;
module_param(second, bool, 0644);

static bool third;
module_param(third, bool, 0644);

struct kho_test_state {
	unsigned int nr_folios;
	struct folio **folios;
	phys_addr_t *folios_info;
	struct kho_vmalloc folios_info_phys;
	int nr_folios_preserved;
	struct folio *fdt;
	__wsum csum;
};

/*
 * 0 - first boot early alloc
 * 1 - first boot late alloc
 */
struct kho_superstate {
	struct kho_test_state kho_test_state;
	const char *kho_test_fdt;
	int kho_test_magic;
};

static struct kho_superstate kho_superstate[] = {
	{{}, "kho_test0", 0x4b484f20},
	{{}, "kho_test1", 0x4b484f21},
	{{}, "kho_test2", 0x4b484f22},
	{{}, "kho_test3", 0x4b484f23},
};

static void kho_test_unpreserve_data(struct kho_test_state *state)
{
	for (int i = 0; i < state->nr_folios_preserved; i++)
		kho_unpreserve_folio(state->folios[i]);

	kho_unpreserve_vmalloc(&state->folios_info_phys);
	vfree(state->folios_info);
}

static int kho_test_preserve_data(struct kho_test_state *state)
{
	struct kho_vmalloc folios_info_phys;
	phys_addr_t *folios_info;
	int err;

	folios_info = vmalloc_array(state->nr_folios, sizeof(*folios_info));
	if (!folios_info)
		return -ENOMEM;

	err = kho_preserve_vmalloc(folios_info, &folios_info_phys);
	if (err)
		goto err_free_info;

	state->folios_info_phys = folios_info_phys;
	state->folios_info = folios_info;

	for (int i = 0; i < state->nr_folios; i++) {
		struct folio *folio = state->folios[i];
		unsigned int order = folio_order(folio);

		folios_info[i] = virt_to_phys(folio_address(folio)) | order;
		err = kho_preserve_folio(folio);
		if (err)
			goto err_unpreserve;
		state->nr_folios_preserved++;
	}

	return 0;

err_unpreserve:
	/*
	 * kho_test_unpreserve_data frees folio_info, bail out immediately to
	 * avoid double free
	 */
	kho_test_unpreserve_data(state);
	return err;

err_free_info:
	vfree(folios_info);
	return err;
}

static int kho_test_prepare_fdt(struct kho_superstate *superstate, ssize_t fdt_size)
{
	struct kho_test_state *state = &superstate->kho_test_state;
	const char compatible[] = KHO_TEST_COMPAT;
	unsigned int magic = superstate->kho_test_magic;
	void *fdt = folio_address(state->fdt);
	int err;

	err = fdt_create(fdt, fdt_size);
	err |= fdt_finish_reservemap(fdt);
	err |= fdt_begin_node(fdt, "");
	err |= fdt_property(fdt, "compatible", compatible, sizeof(compatible));
	err |= fdt_property(fdt, "magic", &magic, sizeof(magic));

	err |= fdt_begin_node(fdt, "data");
	err |= fdt_property(fdt, "nr_folios", &state->nr_folios,
			    sizeof(state->nr_folios));
	err |= fdt_property(fdt, "folios_info", &state->folios_info_phys,
			    sizeof(state->folios_info_phys));
	err |= fdt_property(fdt, "csum", &state->csum, sizeof(state->csum));
	err |= fdt_end_node(fdt);

	err |= fdt_end_node(fdt);
	err |= fdt_finish(fdt);

	return err;
}

static int kho_test_preserve(struct kho_superstate *superstate)
{
	ssize_t fdt_size;
	int err;
	struct kho_test_state *state = &superstate->kho_test_state;

	fdt_size = state->nr_folios * sizeof(phys_addr_t) + PAGE_SIZE;
	state->fdt = folio_alloc(GFP_KERNEL, get_order(fdt_size));
	if (!state->fdt)
		return -ENOMEM;

	err = kho_preserve_folio(state->fdt);
	if (err)
		goto err_free_fdt;

	err = kho_test_preserve_data(state);
	if (err)
		goto err_unpreserve_fdt;

	err = kho_test_prepare_fdt(superstate, fdt_size);
	if (err)
		goto err_unpreserve_data;

	err = kho_add_subtree(superstate->kho_test_fdt, folio_address(state->fdt),
			      fdt_totalsize(folio_address(state->fdt)));
	if (err)
		goto err_unpreserve_data;

	return 0;

err_unpreserve_data:
	kho_test_unpreserve_data(state);
err_unpreserve_fdt:
	kho_unpreserve_folio(state->fdt);
err_free_fdt:
	folio_put(state->fdt);
	return err;
}
static struct folio **kho_test_exhaust_lowmem(unsigned long *nr_exhaust)
{
	struct folio **exhaust_folios;
	unsigned long max_exhaust;
	unsigned long count = 0;
	phys_addr_t highest_phys = 0;

	*nr_exhaust = 0;

	max_exhaust = SZ_2G >> PAGE_SHIFT;

	exhaust_folios = kvmalloc_array(max_exhaust, sizeof(*exhaust_folios),
					GFP_KERNEL);
	if (!exhaust_folios) {
		pr_warn("Failed to allocate exhaust folio array\n");
		return NULL;
	}

	/*
	 * Allocate order-0 pages to fragment and exhaust low memory.
	 * We intentionally don't use higher orders to maximize fragmentation.
	 */
	while (count < max_exhaust) {
		struct folio *folio;
		phys_addr_t phys;

		folio = folio_alloc(GFP_KERNEL | __GFP_NORETRY | __GFP_NOWARN, 0);
		if (!folio)
			break;

		phys = folio_pfn(folio) << PAGE_SHIFT;
		if (phys > highest_phys)
			highest_phys = phys;

		exhaust_folios[count++] = folio;
	}

	pr_info("Exhausted %lu pages, highest phys addr: 0x%llx\n",
		count, (unsigned long long)highest_phys);

	*nr_exhaust = count;
	return exhaust_folios;
}

static void kho_test_release_exhaust(struct folio **exhaust_folios,
				     unsigned long nr_exhaust)
{
	unsigned long i;

	if (!exhaust_folios)
		return;

	for (i = 0; i < nr_exhaust; i++)
		folio_put(exhaust_folios[i]);

	kvfree(exhaust_folios);
}

static int kho_test_generate_data(struct kho_test_state *state)
{
	struct folio **exhaust_folios = NULL;
	unsigned long nr_exhaust = 0;
	phys_addr_t min_phys = ~0ULL;
	phys_addr_t max_phys = 0;
	size_t alloc_size = 0;
	__wsum csum = 0;

	if (exhaust_lowmem) {
		exhaust_folios = kho_test_exhaust_lowmem(&nr_exhaust);
		if (!exhaust_folios)
			pr_warn("Low memory exhaustion failed, continuing anyway\n");
	}

	while (alloc_size < max_mem) {
		int order = get_random_u32() % NR_PAGE_ORDERS;
		struct folio *folio;
		unsigned int size;
		phys_addr_t phys;
		void *addr;

		/*
		 * Since get_order() rounds up, make sure that actual
		 * allocation is smaller so that we won't exceed max_mem
		 */
		if (alloc_size + (PAGE_SIZE << order) > max_mem) {
			order = get_order(max_mem - alloc_size);
			if (order)
				order--;
		}
		size = PAGE_SIZE << order;

		folio = folio_alloc(GFP_ATOMIC, order);
		if (!folio)
			goto err_free_folios;

		phys = folio_pfn(folio) << PAGE_SHIFT;
		if (phys < min_phys)
			min_phys = phys;
		if (phys > max_phys)
			max_phys = phys;

		state->folios[state->nr_folios++] = folio;
		addr = folio_address(folio);
		get_random_bytes(addr, size);
		csum = csum_partial(addr, size, csum);
		alloc_size += size;
	}

	kho_test_release_exhaust(exhaust_folios, nr_exhaust);

	pr_info("Allocated %u folios, phys range: 0x%llx - 0x%llx\n",
		state->nr_folios, (unsigned long long)min_phys,
		(unsigned long long)max_phys);

	state->csum = csum;
	return 0;

err_free_folios:
	kho_test_release_exhaust(exhaust_folios, nr_exhaust);
	for (int i = 0; i < state->nr_folios; i++)
		folio_put(state->folios[i]);
	state->nr_folios = 0;
	return -ENOMEM;
}

extern struct kho_scratch *kho_scratch;
extern unsigned int kho_scratch_cnt;

static int kho_test_alloc(struct kho_test_state *state)
{
	struct folio **folios;
	unsigned long max_nr;
	int err;

	max_nr = max_mem >> PAGE_SHIFT;

	folios = kvmalloc_objs(*state->folios, max_nr);
	if (!folios)
		return -ENOMEM;
	state->folios = folios;

	err = kho_test_generate_data(state);
	if (err)
		goto err_free_folios;

	return 0;

err_free_folios:
	kvfree(folios);
	return err;
}

static int kho_test_save(int nr)
{
	struct kho_test_state *state = &kho_superstate[nr].kho_test_state;
	int err;

	err = kho_test_alloc(state);
	if (err)
		return err;

	return kho_test_preserve(&kho_superstate[nr]);
}

static int kho_test_restore_data(const void *fdt, int node)
{
	const struct kho_vmalloc *folios_info_phys;
	const unsigned int *nr_folios;
	phys_addr_t *folios_info;
	const __wsum *old_csum;
	__wsum csum = 0;
	int len;

	node = fdt_path_offset(fdt, "/data");

	nr_folios = fdt_getprop(fdt, node, "nr_folios", &len);
	if (!nr_folios || len != sizeof(*nr_folios))
		return -EINVAL;

	old_csum = fdt_getprop(fdt, node, "csum", &len);
	if (!old_csum || len != sizeof(*old_csum))
		return -EINVAL;

	folios_info_phys = fdt_getprop(fdt, node, "folios_info", &len);
	if (!folios_info_phys || len != sizeof(*folios_info_phys))
		return -EINVAL;

	folios_info = kho_restore_vmalloc(folios_info_phys);
	if (!folios_info)
		return -EINVAL;

	for (int i = 0; i < *nr_folios; i++) {
		unsigned int order = folios_info[i] & ~PAGE_MASK;
		phys_addr_t phys = folios_info[i] & PAGE_MASK;
		unsigned int size = PAGE_SIZE << order;
		struct folio *folio;

		folio = kho_restore_folio(phys);
		if (!folio)
			break;

		if (folio_order(folio) != order)
			break;

		csum = csum_partial(folio_address(folio), size, csum);
		folio_put(folio);
	}

	vfree(folios_info);

	if (csum != *old_csum)
		return -EINVAL;

	return 0;
}

static int kho_test_restore(phys_addr_t fdt_phys, int m)
{
	void *fdt = phys_to_virt(fdt_phys);
	const unsigned int *magic;
	int node, len, err;

	node = fdt_path_offset(fdt, "/");
	if (node < 0)
		return -EINVAL;

	if (fdt_node_check_compatible(fdt, node, KHO_TEST_COMPAT))
		return -EINVAL;

	magic = fdt_getprop(fdt, node, "magic", &len);
	if (!magic || len != sizeof(*magic))
		return -EINVAL;

	if (*magic != m)
		return -EINVAL;

	err = kho_test_restore_data(fdt, node);
	if (err)
		return err;

	return 0;
}

static int kho_test_early_alloc(void)
{
	if (third)
		return 0;
	else if (second)
		return kho_test_alloc(&kho_superstate[2].kho_test_state);
	else
		return kho_test_alloc(&kho_superstate[0].kho_test_state);
}
core_initcall(kho_test_early_alloc);

static int kho_test_restore_super(int nr)
{
	phys_addr_t fdt_phys;
	int err;

	err = kho_retrieve_subtree(kho_superstate[nr].kho_test_fdt, &fdt_phys, NULL);
	if (err) {
		pr_err("failed to retrieve %s FDT: %d\n", kho_superstate[nr].kho_test_fdt, err);
		return err;
	}
	err = kho_test_restore(fdt_phys, kho_superstate[nr].kho_test_magic);
	if (err)
		pr_err("KHO restore failed\n");
	else
		pr_info("KHO restore succeeded\n");

	return err;
}

static int check_cma(void)
{
	for (int i = 0; i < kho_scratch_cnt; i++) {
		unsigned long base_pfn = PHYS_PFN(kho_scratch[i].addr);
		unsigned long count = kho_scratch[i].size >> PAGE_SHIFT;
		unsigned long pfn;

		for (pfn = base_pfn; pfn < base_pfn + count;
		     pfn += pageblock_nr_pages)
			if (get_pageblock_migratetype(pfn_to_page(pfn)) != MIGRATE_CMA) {
				pr_err("KHO wrong migratetype\n");
				return 1;
			}
	}
	return 0;
}

static int __init kho_test_init(void)
{
	int err;

	if (!kho_is_enabled())
		return 0;

	if (check_cma())
		return 1;

	if (third) {
		err = kho_test_restore_super(2);
		err |= kho_test_restore_super(3);
	} else if (second) {
		err = kho_test_restore_super(0);
		err |= kho_test_restore_super(1);

		err |= kho_test_preserve(&kho_superstate[2]);
		err |= kho_test_save(3);
	} else {
		err = kho_test_preserve(&kho_superstate[0]);
		err |= kho_test_save(1);
	}
	return err;
}
module_init(kho_test_init);

// static void kho_test_cleanup(struct kho_test_state *state)
// {
// 	kho_remove_subtree(folio_address(state->fdt));
// 	for (int i = 0; i < state->nr_folios; i++)
// 		folio_put(state->folios[i]);

// 	kvfree(state->folios);
// 	vfree(state->folios_info);
// 	folio_put(state->fdt);
// }

static void __exit kho_test_exit(void)
{
	// kho_test_cleanup();
}
module_exit(kho_test_exit);

MODULE_AUTHOR("Mike Rapoport <rppt@kernel.org>");
MODULE_DESCRIPTION("KHO test module");
MODULE_LICENSE("GPL");
