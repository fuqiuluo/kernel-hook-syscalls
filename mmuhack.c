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
#include <linux/moduleloader.h>
#include <linux/stop_machine.h>
#if defined(CONFIG_ARM64) || defined(CONFIG_AARCH64)
#include <linux/pgtable.h>
#endif

// https://github.com/perillamint/hideroot/blob/b0d7834/mmuhack.c
// https://github.com/3intermute/arm64_silent_syscall_hook/blob/master/set_page_flags.c#L48

#define PAGE_ALIGN_BOTTOM(addr) (PAGE_ALIGN(addr) - PAGE_SIZE) //aligns the memory address to bottom of the page boundary
#define NUM_PAGES_BETWEEN(low, high) (((PAGE_ALIGN_BOTTOM(high) - PAGE_ALIGN_BOTTOM(low)) / PAGE_SIZE) + 1)

/*static void (*my_flush_module_init_free_work)(void);*/

s32 init_memhack(void) {
    my_update_mapping_prot = (void *) my_kallsyms_lookup_name("update_mapping_prot");
    start_rodata = (uintptr_t) my_kallsyms_lookup_name("__start_rodata");
    end_rodata = (uintptr_t ) my_kallsyms_lookup_name("__init_begin");

//    if (end_rodata == 0) {
//        end_rodata = (uintptr_t) my_kallsyms_lookup_name("__end_rodata");
//    }

    printk("[daat] update_mapping_prot: 0x%lx, start_rodata: 0x%lx, end_rodata: 0x%lx.\n",
           (uintptr_t) my_update_mapping_prot, start_rodata, end_rodata);

    if (my_update_mapping_prot == 0) {
        printk("[daat] update_mapping_prot not found.\n");
        //return -1;
    }

    if (start_rodata == 0 || end_rodata == 0) {
        printk("[daat] start_rodata or end_rodata not found.\n");
        //return -1;
    }

    my_set_memory_ro = (void *) my_kallsyms_lookup_name("set_memory_ro");
    if (my_set_memory_ro == NULL) {
        printk(KERN_ERR "[daat] Could not find `set_memory_ro`\n");
        //return -1;
    }

    my_set_memory_rw = (void *) my_kallsyms_lookup_name("set_memory_rw");
    if (my_set_memory_rw == NULL) {
        printk(KERN_ERR "[daat] Could not find `set_memory_rw`\n");
        //return -1;
    }

    my_find_vm_area = (void *) my_kallsyms_lookup_name("find_vm_area");
    if (my_find_vm_area == NULL) {
        printk(KERN_ERR "[daat] Could not find `find_vm_area`\n");
        //return -1;
    }

//    my_flush_module_init_free_work = (void *) my_kallsyms_lookup_name("flush_module_init_free_work");
//    if (my_flush_module_init_free_work == NULL) {
//        printk(KERN_ERR "[daat] Could not find `flush_module_init_free_work`\n");
//    }

    return 0;
}

pte_t *page_from_virt(uintptr_t addr) {
    if ((uintptr_t) addr & (PAGE_SIZE - 1)) {
        addr = addr + PAGE_SIZE & ~(PAGE_SIZE - 1);
    }

    pr_info("[daat] page_from_virt called with addr: 0x%lx\n", (uintptr_t) addr);
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

    pr_debug("[daat] page_from_virt succes, virt (0x%lx), ptep @ %lx", (uintptr_t) addr, (uintptr_t) ptep);

    return ptep;
}

s32 mark_kernel_rodata_rw(void* unused) {
    my_update_mapping_prot(__pa_symbol(start_rodata), (uintptr_t)start_rodata, section_size, PAGE_KERNEL);
    return 0;
}

s32 mark_kernel_rodata_ro(void* unused) {
    my_update_mapping_prot(__pa_symbol(start_rodata), (uintptr_t)start_rodata, section_size, PAGE_KERNEL_RO);
    return 0;
}

static inline void my_set_pte_at(struct mm_struct *mm,
                                uintptr_t __always_unused addr,
                                pte_t *ptep, pte_t pte)
{
#ifdef CONFIG_X86_64
    set_pte(ptep, pte);
#else
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

#if !defined(PTE_UXN)
#define PTE_UXN			(_AT(pteval_t, 1) << 54)	/* User XN */
#endif
#if !defined(pte_user_exec)
#define pte_user_exec(pte)	(!(pte_val(pte) & PTE_UXN))
#endif

    if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
        __sync_icache_dcache(pte);

    /*
     * If the PTE would provide user space access to the tags associated
     * with it then ensure that the MTE tags are synchronised.  Although
     * pte_access_permitted() returns false for exec only mappings, they
     * don't expose tags (instruction fetches don't check tags).
     */


#if !defined(pte_tagged)
#define pte_tagged(pte)		((pte_val(pte) & PTE_ATTRINDX_MASK) == \
    PTE_ATTRINDX(MT_NORMAL_TAGGED))
#endif

    if (system_supports_mte() && pte_access_permitted(pte, false) &&
        !pte_special(pte) && pte_tagged(pte))
        mte_sync_tags(pte, 1);

    __check_safe_pte_update(mm, ptep, pte);
    __set_pte(ptep, pte);
#endif
}

s32 protect_rodata_memory(s32 mode, u32 nr) {
    if (mode == PRD_MODE_V1) {
        u64 pages = section_size;
        if ((uintptr_t)start_rodata & (PAGE_SIZE-1)) {
            printk(KERN_ERR "[daat] start_rodata is not page aligned\n");
            start_rodata = start_rodata & PAGE_MASK;
        } else if ((unsigned long)section_size & (PAGE_SIZE-1)) {
            printk(KERN_ERR "[daat] section_size is not page aligned\n");
        }
        pages = PAGE_ALIGN(section_size) / PAGE_SIZE;

        if (my_set_memory_ro == 0) {
            printk(KERN_ERR "[daat] Could not find `set_memory_ro`\n");
            return -1;
        }
        set_vm_flush_reset_perms((void*) start_rodata);
        s32 result = my_set_memory_ro(start_rodata, pages >> PAGE_SHIFT);
        if (result != 0) {
            printk(KERN_ERR "[daat] Failed to set memory to read-only mode\n");
            return -1;
        }
    }
    if (mode == PRD_MODE_V2) {
        if (my_update_mapping_prot == 0) {
            printk(KERN_ERR "[daat] Could not find `update_mapping_prot`\n");
            return -1;
        }

        if (TAKE_STOP_MACHINE_FOR_CHANGED_RODATA_PERMISSION) {
            stop_machine(mark_kernel_rodata_ro, NULL, NULL);
        } else {
            mark_kernel_rodata_ro(NULL);
        }
    }
    if (mode == PRD_MODE_V3) {
        uintptr_t addr = (uintptr_t) ((uintptr_t) find_syscall_table() + nr & PAGE_MASK);
        pte_t* ptep = page_from_virt(addr);
#ifdef CONFIG_X86_64
#if !defined(PTE_VALID)
    #define PTE_VALID		(_AT(pteval_t, 1) << 0)
#endif
        if (!(!!(pte_val(READ_ONCE(*ptep)) & PTE_VALID))) {
            printk(KERN_INFO "[daat] failed to get ptep from 0x%lx\n", addr);
            return -2;
        }
        pte_t pte;
        pte = READ_ONCE(*ptep);
        pte = pte_wrprotect(pte);
        my_set_pte_at(init_mm_ptr, addr, ptep, pte);

        __flush_tlb_one_kernel(addr); // x64
        //  error: implicit declaration of function 'flush_tlb_one_kernel' [-Werror,-Wimplicit-function-declaration]??
#else
        if (!pte_valid(READ_ONCE(*ptep))) { // arm64
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
        __flush_tlb_kernel_pgtable(addr); // arm64
#endif
    }
    return 0;
}

s32 unprotect_rodata_memory(s32 mode, u32 nr) {
    if (mode == PRD_MODE_V1) {
        u64 pages = section_size;
        if ((uintptr_t) start_rodata & (PAGE_SIZE-1)) {
            printk(KERN_ERR "[daat] start_rodata is not page aligned\n");
            return -2;
        } else if ((uintptr_t) section_size & (PAGE_SIZE-1)) {
            printk(KERN_ERR "[daat] section_size is not page aligned\n");
            return -2;
        }
        start_rodata = start_rodata & PAGE_MASK;
        pages = PAGE_ALIGN(section_size) / PAGE_SIZE;

        if(my_set_memory_rw == 0) {
            printk(KERN_ERR "[daat] Could not find `set_memory_rw`\n");
            return -1;
        } else if(my_find_vm_area == 0) {
            printk(KERN_ERR "[daat] Could not find `find_vm_area`\n");
            return -1;
        }
        struct vm_struct *area = my_find_vm_area((void *) start_rodata);
        if (area == NULL) {
            printk(KERN_ERR "[daat] Could not find vm area\n");
            return -1;
        }
        area->flags |= VM_ALLOC;

        set_vm_flush_reset_perms((void*) start_rodata);
        int result = my_set_memory_rw(start_rodata, pages >> PAGE_SHIFT);
        if (result != 0) {
            printk(KERN_ERR "[daat] Failed to set memory to read/write mode\n");
            return -1;
        }
    }
    if (mode == PRD_MODE_V2) {
        if (my_update_mapping_prot == 0) {
            printk(KERN_ERR "[daat] Could not find `update_mapping_prot`\n");
            return -1;
        }

        if (TAKE_STOP_MACHINE_FOR_CHANGED_RODATA_PERMISSION) {
            stop_machine(mark_kernel_rodata_rw, NULL, NULL);
        } else {
            mark_kernel_rodata_rw(NULL);
        }
    }
    if (mode == PRD_MODE_V3) {
        uintptr_t addr = (uintptr_t) ((uintptr_t) find_syscall_table() + nr & PAGE_MASK);
        pte_t* ptep = page_from_virt(addr);

#ifdef CONFIG_X86_64
#if !defined(PTE_VALID)
    #define PTE_VALID		(_AT(pteval_t, 1) << 0)
#endif
        if (!(!!(pte_val(READ_ONCE(*ptep)) & PTE_VALID))) {
            printk(KERN_INFO "[daat] failed to get ptep from 0x%lx\n", addr);
            return -2;
        }
        //struct vm_struct *area = my_find_vm_area((void *) addr);

        pte_t pte;
        pte = READ_ONCE(*ptep);
        pte = pte_mkwrite(pte); // high version -> pte_t pte_mkwrite(pte_t pte, struct vm_area_struct *vma)
        my_set_pte_at(init_mm_ptr, addr, ptep, pte);

        __flush_tlb_one_kernel(addr); // x64
#else
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
        __flush_tlb_kernel_pgtable(addr); // arm64
#endif
    }
    return 0;
}