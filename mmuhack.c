#include <linux/kallsyms.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include "mmuhack.h"
#include "kallsyms.h"
#include <linux/ftrace.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <linux/mm.h> // For PAGE_SIZE
#include <linux/version.h>
#include <linux/vmalloc.h>

// https://github.com/perillamint/hideroot/blob/b0d7834/mmuhack.c
// https://github.com/3intermute/arm64_silent_syscall_hook/blob/master/set_page_flags.c#L48

#define PAGE_ALIGN_BOTTOM(addr) (PAGE_ALIGN(addr) - PAGE_SIZE) //aligns the memory address to bottom of the page boundary
#define NUM_PAGES_BETWEEN(low, high) (((PAGE_ALIGN_BOTTOM(high) - PAGE_ALIGN_BOTTOM(low)) / PAGE_SIZE) + 1)

int init_memhack(void) {
    my_update_mapping_prot = (void *) my_kallsyms_lookup_name("update_mapping_prot");
    start_rodata = (unsigned long) my_kallsyms_lookup_name("__start_rodata");
    end_rodata = (unsigned long) my_kallsyms_lookup_name("__init_begin");

    if (end_rodata == 0) {
        end_rodata = (unsigned long) my_kallsyms_lookup_name("__end_rodata");
    }

    printk("[daat] update_mapping_prot: 0x%lx, start_rodata: 0x%lx, end_rodata: 0x%lx.\n",
           (unsigned long) my_update_mapping_prot, start_rodata, end_rodata);

    if (my_update_mapping_prot == 0) {
        printk("[daat] update_mapping_prot not found.\n");
        return -1;
    }

    if (start_rodata == 0 || end_rodata == 0) {
        printk("[daat] start_rodata or end_rodata not found.\n");
        return -1;
    }

    my_set_memory_ro = (void *) my_kallsyms_lookup_name("set_memory_ro");
    if (my_set_memory_ro == NULL) {
        printk(KERN_ERR "[daat] Could not find `set_memory_ro`\n");
        return -1;
    }

    my_set_memory_rw = (void *) my_kallsyms_lookup_name("set_memory_rw");
    if (my_set_memory_rw == NULL) {
        printk(KERN_ERR "[daat] Could not find `set_memory_rw`\n");
        return -1;
    }

    my_find_vm_area = (void *) my_kallsyms_lookup_name("find_vm_area");
    if (my_find_vm_area == NULL) {
        printk(KERN_ERR "[daat] Could not find `find_vm_area`\n");
        return -1;
    }
    return 0;
}

pte_t *page_from_virt(uintptr_t addr) {
    if ((unsigned long) addr & (PAGE_SIZE - 1)) {
        addr = addr + PAGE_SIZE & ~(PAGE_SIZE - 1);
    }

    pr_info("[daat] page_from_virt called with addr: 0x%llx\n", (unsigned long long) addr);
    if (!init_mm_ptr) {
        init_mm_ptr = (struct mm_struct *) my_kallsyms_lookup_name("init_mm");
    }

    pgd_t * pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return NULL;
    }
    // return if pgd is entry is here

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return NULL;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return NULL;
    }

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) {
        return NULL;
    }

    pr_debug("[daat] page_from_virt succes, virt (0x%llx), ptep @ %llx", (unsigned long long) addr,
             (unsigned long long) ptep);

    return ptep;
}

static inline void my_set_pte_at(struct mm_struct *mm,
                                unsigned long __always_unused addr,
                                pte_t *ptep, pte_t pte)
{
    typedef void (*f__sync_icache_dcache)(pte_t pteval);
    typedef void (*f_mte_sync_tags)(pte_t pte, unsigned int nr_pages);

    static f__sync_icache_dcache __sync_icache_dcache = NULL;
    static f_mte_sync_tags mte_sync_tags = NULL;

    if (__sync_icache_dcache == NULL) {
        __sync_icache_dcache = (f__sync_icache_dcache) my_kallsyms_lookup_name("__sync_icache_dcache");
    }

    if (mte_sync_tags == NULL) {
        mte_sync_tags = (f_mte_sync_tags) my_kallsyms_lookup_name("mte_sync_tags");
    }

    if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
        __sync_icache_dcache(pte);

    /*
     * If the PTE would provide user space access to the tags associated
     * with it then ensure that the MTE tags are synchronised.  Although
     * pte_access_permitted() returns false for exec only mappings, they
     * don't expose tags (instruction fetches don't check tags).
     */
    if (system_supports_mte() && pte_access_permitted(pte, false) &&
        !pte_special(pte) && pte_tagged(pte))
        mte_sync_tags(pte, 1);

    __check_safe_pte_update(mm, ptep, pte);
    __set_pte(ptep, pte);
}

int protect_rodata_memory(int mode, int nr) {
    unsigned long addr = (unsigned long) ((((unsigned long )find_syscall_table()) + nr) & PAGE_MASK);
    if (mode == PRD_MDOE_V1) {
        int result = my_set_memory_ro(addr, 1);
        if (result != 0) {
            printk(KERN_ERR "[daat] Failed to set memory to read-only mode\n");
            return -1;
        }
    }
    if (mode == PRD_MODE_V2) {
        my_update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
    }
    if (mode == PRD_MODE_V3) {
        pte_t* ptep = page_from_virt(addr);
        if (!pte_valid(READ_ONCE(*ptep))) {
            printk(KERN_INFO "[daat] failed to get ptep from 0x%lx\n", addr);
            return -2;
        }
        pte_t pte;
        pte = READ_ONCE(*ptep);
        pte = pte_wrprotect(pte);
        //把pte页表项写入硬件页表钟
        my_set_pte_at(init_mm_ptr, addr, ptep, pte);
        //页表更新 和 TLB 刷新之间保持正确的映射关系
        //为了保持一致性，必须确保页表的更新和 TLB 的刷新是同步的
        __flush_tlb_kernel_pgtable(addr);
    }
    return 0;
}

int unprotect_rodata_memory(int mode, int nr) {
    unsigned long addr = (unsigned long) ((((unsigned long )find_syscall_table()) + nr) & PAGE_MASK);
    if (mode == PRD_MDOE_V1) {
        struct vm_struct *area = my_find_vm_area((void *) addr);
        if (area == NULL) {
            printk(KERN_ERR "[daat] Could not find vm area\n");
            return -1;
        }
        area->flags |= VM_ALLOC;

        int result = my_set_memory_rw(addr, 1);
        if (result != 0) {
            printk(KERN_ERR "[daat] Failed to set memory to read/write mode\n");
            return -1;
        }
    }
    if (mode == PRD_MODE_V2) {
        my_update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
    }
    if (mode == PRD_MODE_V3) {
        pte_t* ptep = page_from_virt(addr);
        if (!pte_valid(READ_ONCE(*ptep))) {
            printk(KERN_INFO "[daat] failed to get ptep from 0x%lx\n", addr);
            return -2;
        }
        pte_t pte;
        pte = READ_ONCE(*ptep);
        //清除pte的可读属性位
        //设置pte的可写属性位
        pte = pte_mkwrite_novma(pte);
        //把pte页表项写入硬件页表钟
        my_set_pte_at(init_mm_ptr, addr, ptep, pte);
        //页表更新 和 TLB 刷新之间保持正确的映射关系
        //为了保持一致性，必须确保页表的更新和 TLB 的刷新是同步的
        __flush_tlb_kernel_pgtable(addr);
    }
    return 0;
}