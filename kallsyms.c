//
// Created by fuqiuluo on 24-12-10.
//

#include "kallsyms.h"
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

unsigned long *syscall_table;

unsigned long *find_syscall_table(void) {
    syscall_table = (unsigned long*)my_kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

unsigned long my_kallsyms_lookup_name(const char* symbol_name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) // 大于这个版本的内核已经没有kallsyms_lookup_name导出了
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        if(register_kprobe(&kp) < 0) {
            return 0;
        }
        lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    return lookup_name(symbol_name);
#else
    return kallsyms_lookup_name(symbol_name);
#endif
}
