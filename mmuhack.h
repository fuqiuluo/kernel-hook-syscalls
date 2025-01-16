#ifndef DAAT_MMUHACK_H
#define DAAT_MMUHACK_H

#include <asm/pgtable.h>

static struct mm_struct *init_mm_ptr = NULL;
static void (*my_update_mapping_prot)(phys_addr_t phys, uintptr_t virt, phys_addr_t size, pgprot_t prot);
static uintptr_t start_rodata, end_rodata;
#define section_size  (end_rodata - start_rodata)

#define TAKE_STOP_MACHINE_FOR_CHANGED_RODATA_PERMISSION 0

/**
 * These two modes do not fix the extra PTE FLAGS,
 * and higher version kernels may cause kernel crashes
 */
#define PRD_MODE_V1 0 /* via set_memory_ro/set_memory_rw */
#define PRD_MODE_V2 1 /* via update_mapping_prot */

#define PRD_MODE_V3 2 /* via hack pte */

static struct vm_struct* (*my_find_vm_area)(const void* addr);
static s32 (*my_set_memory_rw)(uintptr_t addr, s32 num_pages);
static s32 (*my_set_memory_ro)(uintptr_t addr, s32 num_pages);

extern s32 init_memhack(void);
extern pte_t *page_from_virt(uintptr_t addr);

extern s32 protect_rodata_memory(s32 mode, u32 nr);

extern s32 unprotect_rodata_memory(s32 mode, u32 nr);

#endif //DAAT_MMUHACK_H
