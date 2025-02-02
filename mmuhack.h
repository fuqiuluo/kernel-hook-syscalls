#ifndef DAAT_MMUHACK_H
#define DAAT_MMUHACK_H

#include <asm/pgtable.h>

static struct mm_struct *init_mm_ptr = NULL;
static void (*my_update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
static unsigned long start_rodata, end_rodata;
#define section_size  (end_rodata - start_rodata)

#define PRD_MDOE_V1 0 /* via set_memory_ro/set_memory_rw (需 CONFIG_STRICT_KERNEL_RWX 未启用) */
#define PRD_MODE_V2 1 /* via update_mapping_prot （CONFIG_STRICT_KERNEL_RWX关闭状态或者CONFIG_DEBUG_SET_MODULE_RONX开启）*/
#define PRD_MODE_V3 2 /* via hack pte */

static struct vm_struct* (*my_find_vm_area)(const void* addr);
static int (*my_set_memory_rw)(unsigned long addr, int num_pages);
static int (*my_set_memory_ro)(unsigned long addr, int num_pages);

extern int init_memhack(void);
extern pte_t *page_from_virt(uintptr_t addr);

extern int protect_rodata_memory(int mode, int nr);

extern int unprotect_rodata_memory(int mode, int nr);

#endif //DAAT_MMUHACK_H
