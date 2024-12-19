#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/highuid.h>
#include <linux/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

#include "mydaat.h"
#include "kprobe_all.h"
#include "mmuhack.h"
#include "kallsyms.h"

static int __init daat_init(void) {
    //pmd_t pmd_backup[100] = {0, };
    printk(KERN_INFO "[daat] hello kernel!\n");

    if(kprobe_init() != 0) {
        printk(KERN_ERR "[daat] kprobe_init failed\n");
        return -1;
    }

    if(init_memhack() != 0) {
        printk(KERN_ERR "[daat] init_memhack failed\n");
        return -1;
    }

    int ret = unprotect_rodata_memory(PRD_MODE_V3, __NR_mkdirat);
    if (ret != 0) {
        printk(KERN_ERR "[daat] unprotect_rodata_memory failed\n");
        return -1;
    }

    ret = protect_rodata_memory(PRD_MODE_V3, __NR_mkdirat);
    if (ret != 0) {
        printk(KERN_ERR "[daat] protect_rodata_memory failed\n");
        return -1;
    }

    return 0;
}

static void __exit daat_exit(void) {
    printk(KERN_INFO "[daat] goodbye kernel!\n");

    kprobe_exit();
}

module_init(daat_init);
module_exit(daat_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/daat");
MODULE_VERSION("1.0");
