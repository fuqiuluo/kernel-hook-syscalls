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

typedef long (*syscall_fn_t)(const struct pt_regs* regs);
static syscall_fn_t prototype_mkdir;

asmlinkage long custom_mkdir(const struct pt_regs* regs) {
    int ret;
    char filename[512] = {0};
    char __user *pathname = (char*)regs->regs[1];
    ret = (int) prototype_mkdir(regs);
    printk("[daat] hook mkdir sys_call\n");
    if(copy_from_user(filename, pathname, sizeof(filename)))
        return -1;
    printk("[daat] file name = %s\n", filename);
    return ret;
}

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

    prototype_mkdir = (syscall_fn_t) find_syscall_table()[__NR_mkdirat];
    printk(KERN_INFO "[daat] original mkdirat: 0x%lx\n", (unsigned long) prototype_mkdir);

    find_syscall_table()[__NR_mkdirat] = (unsigned long)custom_mkdir;

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

    int ret = unprotect_rodata_memory(PRD_MODE_V3, __NR_mkdirat);
    if (ret != 0) {
        printk(KERN_ERR "[daat] unprotect_rodata_memory failed\n");
    }
    find_syscall_table()[__NR_mkdirat] = (unsigned long)prototype_mkdir;
    ret = protect_rodata_memory(PRD_MODE_V3, __NR_mkdirat);
    if (ret != 0) {
        printk(KERN_ERR "[daat] protect_rodata_memory failed\n");
    }
}

module_init(daat_init);
module_exit(daat_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/daat");
MODULE_VERSION("1.0");
