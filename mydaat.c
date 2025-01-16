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
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/sched.h>

#include "syscalls.h"

static int __init daat_init(void) {
    printk(KERN_INFO "[daat] hello kernel!\n");

    if(init_daat() != 0) {
        printk(KERN_ERR "[daat] init_daat failed\n");
        return -1;
    }

    return 0;
}

static void __exit daat_exit(void) {
    printk(KERN_INFO "[daat] goodbye kernel!\n");

    if(exit_daat() != 0) {
        printk(KERN_ERR "[daat] exit_daat failed\n");
    }
}

module_init(daat_init);
module_exit(daat_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/kernel-syscalls-tracer");
MODULE_VERSION("1.0.1");
