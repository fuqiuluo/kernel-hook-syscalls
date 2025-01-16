//
// Created by fuqiuluo on 24-12-21.
//

#ifndef DAAT_SYSCALLS_H
#define DAAT_SYSCALLS_H

#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/highuid.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>

#include <linux/sched.h>

#include "mmuhack.h"
#include "kallsyms.h"

#define BREAK_KERNEL_MODE PRD_MODE_V3 /* 破坏内核使用的模式 */

typedef long (*syscall_fn_t)(const struct pt_regs* regs);

struct sys_call_hook {
    syscall_fn_t prototype_func;
    syscall_fn_t hook_func;
    bool hooked;
};

extern s32 init_daat(void);
extern s32 exit_daat(void);
extern s32 restore_syscall_table(void);
extern s32 inject_sys_call(u32 nr);

#endif //DAAT_SYSCALLS_H
