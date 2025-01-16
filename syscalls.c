//
// Created by fuqiuluo on 24-12-21.
//
#include <linux/vmalloc.h>
#include "syscalls.h"
#include "server.h"

#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF

static struct sys_call_hook sys_call_hooks[__NR_syscalls] __aligned(4096) = {
        [0 ... __NR_syscalls - 1] = {NULL, NULL, 0},
#include <asm/unistd.h>
};

#define pr_err_with_location(fmt, ...) \
    pr_err("[daat] %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define PUT_HOOK(syscall_name)  \
    int switch_##syscall_name = 0;     \
    sys_call_hooks[__NR_##syscall_name].prototype_func = (syscall_fn_t) find_syscall_table()[__NR_##syscall_name];  \
    sys_call_hooks[__NR_##syscall_name].hook_func = (syscall_fn_t) custom_##syscall_name;                           \
    sys_call_hooks[__NR_##syscall_name].hooked = switch_##syscall_name;

#define MODIFY_SYSCALL(syscall_name) {                \
    s32 ret = unprotect_rodata_memory(BREAK_KERNEL_MODE, __NR_##syscall_name); \
    if (ret != 0) {                                  \
        printk(KERN_ERR "[daat] unprotect_rodata_memory failed\n"); \
        return -1;                                    \
    }                                                 \
    sys_call_hooks[__NR_##syscall_name].prototype_func = (syscall_fn_t) find_syscall_table()[__NR_##syscall_name]; \
    find_syscall_table()[__NR_##syscall_name] = (uintptr_t)custom_##syscall_name; \
    ret = protect_rodata_memory(BREAK_KERNEL_MODE, __NR_##syscall_name); \
    if (ret != 0) {                                  \
        printk(KERN_ERR "[daat] protect_rodata_memory failed\n"); \
        return -1;                                    \
    }                                                 \
}

#define RESTORE_SYSCALL(syscall_name) {               \
    s32 ret = unprotect_rodata_memory(BREAK_KERNEL_MODE, __NR_##syscall_name); \
    if (ret != 0) {                                  \
        printk(KERN_ERR "[daat] unprotect_rodata_memory failed\n");      \
    }                                                 \
    find_syscall_table()[__NR_##syscall_name] = (uintptr_t)sys_call_hooks[__NR_##syscall_name].prototype_func; \
    ret = protect_rodata_memory(BREAK_KERNEL_MODE, __NR_##syscall_name); \
    if (ret != 0) {                                  \
        printk(KERN_ERR "[daat] protect_rodata_memory failed\n"); \
    }                                                 \
}

void char_to_hex(const char *input, char *output, size_t length) {
    const char hex_digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        output[i * 2] = hex_digits[byte >> 4];
        output[i * 2 + 1] = hex_digits[byte & 0x0F];
    }
    output[length * 2] = '\0';
}

void fnla_put_referer(fnla_t fnla) {
    if(!fnla) {
        return;
    }
    fnla_put_s32(fnla, current->pid);
    kuid_t uid = current_uid();
    fnla_put_u32(fnla, uid.val);
}

asmlinkage long custom_io_setup(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_io_setup;

    s32 ret = (s32) hook->prototype_func(regs);

    u32 nr_events = (u32) regs->regs[0];
    void *ctxp = (void *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    fnla_put_referer(msg);
    fnla_put_u32(msg, nr_events);
    fnla_put_u64(msg, (uintptr_t) ctxp);
    fnla_put_s32(msg, ret);
    on_sys_call_end("io_setup", msg);
    fnla_free(msg);

    return ret;
}

asmlinkage long custom_io_destroy(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_io_destroy;

    s32 ret = (s32) hook->prototype_func(regs);
    // ctx_id is number?
    aio_context_t ctx_id = (aio_context_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    fnla_put_referer(msg);
    fnla_put_u64(msg, ctx_id);
    fnla_put_s32(msg, ret);
    on_sys_call_end("io_destroy", msg);
    fnla_free(msg);

    return ret;
}

asmlinkage long custom_io_submit(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_io_submit;

    s32 ret = (s32) hook->prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    fnla_put_referer(msg);
    // https://github.com/Atom-X-Devs/android_kernel_samsung_9611-m21/blob/64484a7d509be64ba4a9246983cf7b82acf1dadd/fs/aio.c#L1692
    aio_context_t ctx = (aio_context_t) regs->regs[0];
    fnla_put_u64(msg, ctx);
    s64 nr = (s64) regs->regs[1];
    fnla_put_s64(msg, nr);
    struct iocb __user *__user *iocbpp = (struct iocb __user *__user *) regs->regs[2];
    fnla_put_u64(msg, (uintptr_t) iocbpp);
    for (int i=0; i<nr; i++) {
        struct iocb __user *user_iocb;
        struct iocb tmp;

        if (__get_user(user_iocb, iocbpp + i)) {
            fnla_put_u32(msg, 1); // error
            continue;
        }

        if (copy_from_user(&tmp, user_iocb, sizeof(tmp))) {
            fnla_put_u32(msg, 2); // error
            continue;
        }

        fnla_put_u32(msg, 0);
        fnla_put_u64(msg, (uintptr_t) user_iocb);
        fnla_put_u64(msg, tmp.aio_data);
        fnla_put_u32(msg, tmp.aio_lio_opcode);
        fnla_put_s32(msg, tmp.aio_reqprio);
        fnla_put_u32(msg, tmp.aio_fildes);
        fnla_put_u64(msg, tmp.aio_buf);
        fnla_put_u64(msg, tmp.aio_nbytes);
        fnla_put_s64(msg, tmp.aio_offset);
        fnla_put_u64(msg, tmp.aio_reserved2);
        fnla_put_u32(msg, tmp.aio_flags);
        fnla_put_u32(msg, tmp.aio_resfd);
    }

    fnla_put_s32(msg, ret);
    on_sys_call_end("io_submit", msg);
    fnla_free(msg);

    return ret;
}

asmlinkage long custom_io_cancel(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_io_cancel;

    s32 ret = (s32) hook->prototype_func(regs);

    aio_context_t ctx = (aio_context_t) regs->regs[0];
    struct iocb __user *iocb = (struct iocb __user *) regs->regs[1];
    struct io_event __user *result = (struct io_event __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    fnla_put_referer(msg);
    fnla_put_u64(msg, ctx);
    fnla_put_u64(msg, (uintptr_t) iocb);
    fnla_put_u64(msg, (uintptr_t) result);
    fnla_put_s32(msg, ret);
    on_sys_call_end("io_cancel", msg);
    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_io_getevents(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_io_getevents;

    //       int syscall(SYS_io_getevents, aio_context_t ctx_id,
    //                   long min_nr, long nr, struct io_event *events,
    //                   struct timespec *timeout);
    s32 ret = (s32) hook->prototype_func(regs);

    aio_context_t ctx = (aio_context_t) regs->regs[0];
    s64 min_nr = (s64) regs->regs[1];
    s64 nr = (s64) regs->regs[2];
    struct io_event __user *events = (struct io_event __user *) regs->regs[3];

#if __BITS_PER_LONG != 32
    struct old_timespec32  __user *timeout = (struct old_timespec32  __user *) regs->regs[4];
    struct old_timespec32 tmp;
#else
    struct timespec __user *timeout = (struct timespec __user *) regs->regs[4];
    struct timespec tmp;
#endif
    if (timeout != NULL) {
        if (copy_from_user(&tmp, timeout, sizeof(tmp))) {
            pr_err_with_location("Failed to copy timeout\n");
            return ret;
        }
    } else {
        tmp.tv_sec = 0;
        tmp.tv_nsec = 0;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    fnla_put_referer(msg);
    fnla_put_u64(msg, ctx);
    fnla_put_s64(msg, min_nr);
    fnla_put_s64(msg, nr);
    fnla_put_u64(msg, (uintptr_t) events);

    fnla_put_u64(msg, (uintptr_t) timeout);
    fnla_put_s64(msg, tmp.tv_sec);
    fnla_put_s64(msg, tmp.tv_nsec);

    fnla_put_s32(msg, ret);
    on_sys_call_end("io_getevents", msg);
    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_setxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_setxattr;

    s32 ret = (s32) hook->prototype_func(regs);

    //  int setxattr(const char *path, const char *name,
    //                     const void value[.size],
    //                     size_t size, int flags);
    //  int lsetxattr(const char *path, const char *name,
    //                     const void value[.size],
    //                     size_t size, int flags);
    //  int fsetxattr(int fd, const char *name,
    //                     const void value[.size],
    //                     size_t size, int flags);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];

    // The content of the value may be binary data,
    // so it is not printed directly
    const void __user *value = (const void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];
    s32 flags = (s32) regs->regs[4];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(XATTR_NAME_MAX, GFP_KERNEL);
    size_t max_size = size > XATTR_SIZE_MAX ? XATTR_SIZE_MAX : size;

    /**
     * why vmalloc? because it is too large
     * 想在内核地址空间找到一个64k的连续空间，kmalloc是很难做到的
     */
    char* value_buf = vmalloc(max_size);

    if (path_buf == NULL ||
        name_buf == NULL ||
        value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p, value_buf: %p\n", path_buf, name_buf, value_buf);
        goto ret;
    }

    value_buf[0] = '\0';
    if (
            (path != NULL && copy_from_user(path_buf, path, PATH_MAX)) ||
            (name != NULL && copy_from_user(name_buf, name, XATTR_NAME_MAX)) ||
            (value != NULL && copy_from_user(value_buf, value, max_size))
    ) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    // The size of the value is limited to XATTR_SIZE_MAX
    //if(size > XATTR_SIZE_MAX) {
    //    return ret;
    //}
    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);

    fnla_put_u64(msg, (uintptr_t) path);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u32(msg, max_size);
    fnla_put_bytes(msg, value_buf, max_size);

    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);
    on_sys_call_end("setxattr", msg);
    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_lsetxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_lsetxattr;

    s32 ret = (s32) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    const void __user *value = (const void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];
    s32 flags = (s32) regs->regs[4];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(XATTR_NAME_MAX, GFP_KERNEL);
    size_t max_size = size > XATTR_SIZE_MAX ? XATTR_SIZE_MAX : size;
    char* value_buf = vmalloc(max_size);
    if(path_buf == NULL ||
        name_buf == NULL ||
        value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p, value_buf: %p\n", path_buf, name_buf, value_buf);
        goto ret;
    }

    value_buf[0] = '\0';
    if ((path != NULL && copy_from_user(path_buf, path, PATH_MAX)) ||
        (name != NULL && copy_from_user(name_buf, name, XATTR_NAME_MAX)) ||
        (value != NULL && copy_from_user(value_buf, value, max_size))) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);

    fnla_put_u64(msg, (uintptr_t) path);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u32(msg, max_size);
    fnla_put_bytes(msg, value_buf, max_size);

    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("lsetxattr", msg);
    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_fsetxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_fsetxattr;

    s32 ret = (s32) hook->prototype_func(regs);

    s32 fd = (int) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    const void __user *value = (const void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];
    s32 flags = (s32) regs->regs[4];

    char* name_buf = kzalloc(XATTR_NAME_MAX, GFP_KERNEL);
    size_t max_size = size > XATTR_SIZE_MAX ? XATTR_SIZE_MAX : size;
    char* value_buf = vmalloc(max_size);
    if (name_buf == NULL || value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, name_buf: %p, value_buf: %p\n", name_buf, value_buf);
        goto ret;
    }

    value_buf[0] = '\0';
    if ((name != NULL && copy_from_user(name_buf, name, XATTR_NAME_MAX)) ||
        (value != NULL && copy_from_user(value_buf, value, max_size))) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if(!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);

    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u32(msg, max_size);
    fnla_put_bytes(msg, value_buf, max_size);

    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fsetxattr", msg);

    fnla_free(msg);

    ret:
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_getxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_getxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    // #include <sys/xattr.h>
    //
    //       ssize_t getxattr(const char *path, const char *name,
    //                        void value[.size], size_t size);
    //       ssize_t lgetxattr(const char *path, const char *name,
    //                        void value[.size], size_t size);
    //       ssize_t fgetxattr(int fd, const char *name,
    //                        void value[.size], size_t size);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    void __user *value = (void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(XATTR_NAME_MAX, GFP_KERNEL);
    ssize_t value_len = ret > 0 ? ret : 1;
    char* value_buf = vmalloc(value_len);
    if(path_buf == NULL || name_buf == NULL || value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p, value_buf: %p\n", path_buf, name_buf, value_buf);
        goto ret;
    }

    if (copy_from_user(path_buf, path, PATH_MAX) ||
        copy_from_user(name_buf, name, XATTR_NAME_MAX) ||
        copy_from_user(value_buf, value, value_len)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);

    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);

    fnla_put_u32(msg, value_len);
    fnla_put_bytes(msg, value_buf, value_len);

    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);
    on_sys_call_end("getxattr", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_lgetxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_lgetxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    void __user *value = (void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(XATTR_NAME_MAX, GFP_KERNEL);
    ssize_t value_len = ret > 0 ? ret : 1;
    char* value_buf = vmalloc(value_len);
    if (path_buf == NULL || name_buf == NULL || value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p, value_buf: %p\n", path_buf, name_buf, value_buf);
        goto ret;
    }
    if (copy_from_user(path_buf, path, PATH_MAX)
        || copy_from_user(name_buf, name, XATTR_NAME_MAX)
        || copy_from_user(value_buf, value, value_len)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    fnla_put_referer(msg);

    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);

    fnla_put_u32(msg, value_len);
    fnla_put_bytes(msg, value_buf, value_len);

    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);
    on_sys_call_end("lgetxattr", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_fgetxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_fgetxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    int fd = (int) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    void __user *value = (void __user *) regs->regs[2];
    size_t size = (size_t) regs->regs[3];

    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    ssize_t value_len = ret > 0 ? ret : 1;
    char* value_buf = vmalloc(value_len);
    if(name_buf == NULL || value_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, name_buf: %p, value_buf: %p\n", name_buf, value_buf);
        goto ret;
    }
    if (copy_from_user(name_buf, name, PATH_MAX) ||
        copy_from_user(value_buf, value, value_len)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);

    fnla_put_s32(msg, fd);

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_u64(msg, (uintptr_t) value);

    fnla_put_u32(msg, value_len);
    fnla_put_bytes(msg, value_buf, value_len);

    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);
    on_sys_call_end("fgetxattr", msg);
    fnla_free(msg);

    ret:
    if (name_buf)
        kfree(name_buf);
    if (value_buf)
        vfree(value_buf);
    return ret;
}

asmlinkage long custom_listxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_listxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    char __user *list = (char __user *) regs->regs[1];
    /**
     * size 表示 list 指向的缓冲区大小（以字节为单位）
     * 如果 size 为 0 或 list 为 NULL，不会存储实际的扩展属性名称，而是返回扩展属性名称所需的缓冲区大小
     */
    size_t size = (size_t) regs->regs[2];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (copy_from_user(path_buf, path, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }
    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u64(msg, (uintptr_t) list);
    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);

    if (size != 0 && list != NULL && ret > 0) {
        char* list_buf = vmalloc(ret);
        if (list_buf == NULL) {
            pr_err_with_location("Failed to allocate list_buf\n");
            fnla_free(msg);
            goto ret;
        }
        if (copy_from_user(list_buf, list, ret)) {
            vfree(list_buf);
            fnla_free(msg);
            goto ret;
        }
        fnla_put_u32(msg, ret);
        fnla_put_bytes(msg, list_buf, ret);
        vfree(list_buf);
    }

    on_sys_call_end("listxattr", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    return ret;
}

asmlinkage long custom_llistxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_llistxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    char __user *list = (char __user *) regs->regs[1];
    size_t size = (size_t) regs->regs[2];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (copy_from_user(path_buf, path, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u64(msg, (uintptr_t) list);
    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);

    if (size != 0 && list != NULL && ret > 0) {
        char* list_buf = vmalloc(ret);
        if (list_buf == NULL) {
            pr_err_with_location("Failed to allocate list_buf\n");
            fnla_free(msg);
            goto ret;
        }
        if (copy_from_user(list_buf, list, ret)) {
            vfree(list_buf);
            fnla_free(msg);
            goto ret;
        }
        fnla_put_u32(msg, ret);
        fnla_put_bytes(msg, list_buf, ret);
        vfree(list_buf);
    }

    on_sys_call_end("llistxattr", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    return ret;
}

asmlinkage long custom_flistxattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_flistxattr;

    ssize_t ret = (ssize_t) hook->prototype_func(regs);

    s32 fd = (s32) regs->regs[0];
    char __user *list = (char __user *) regs->regs[1];
    size_t size = (size_t) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) list);
    fnla_put_u64(msg, size);

    fnla_put_s64(msg, ret);

    if (size != 0 && list != NULL && ret > 0) {
        char* list_buf = vmalloc(ret);
        if (list_buf == NULL) {
            pr_err_with_location("Failed to allocate list_buf\n");
            fnla_free(msg);
            return ret;
        }
        if (copy_from_user(list_buf, list, ret)) {
            vfree(list_buf);
            fnla_free(msg);
            return ret;
        }
        fnla_put_u32(msg, ret);
        fnla_put_bytes(msg, list_buf, ret);
        vfree(list_buf);
    }

    on_sys_call_end("flistxattr", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_removexattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_removexattr;

    s32 ret = (s32) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL || name_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p\n", path_buf, name_buf);
        goto ret;
    }
    if (copy_from_user(path_buf, path, PATH_MAX) ||
        copy_from_user(name_buf, name, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);

    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_s32(msg, ret);

    on_sys_call_end("removexattr", msg);

    fnla_free(msg);

    ret:
    if(path_buf)
        kfree(path_buf);
    if(name_buf)
        kfree(name_buf);
    return ret;
}

asmlinkage long custom_lremovexattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_lremovexattr;

    s32 ret = (s32) hook->prototype_func(regs);

    const char __user *path = (const char __user *) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL || name_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, path_buf: %p, name_buf: %p\n", path_buf, name_buf);
        goto ret;
    }

    if (copy_from_user(path_buf, path, PATH_MAX) ||
        copy_from_user(name_buf, name, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);

    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_s32(msg, ret);

    on_sys_call_end("lremovexattr", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    if (name_buf)
        kfree(name_buf);
    return ret;
}

asmlinkage long custom_fremovexattr(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_fremovexattr;

    s32 ret = (s32) hook->prototype_func(regs);

    s32 fd = (s32) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];

    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (name_buf == NULL) {
        pr_err_with_location("Failed to allocate tmp_buf, name_buf: %p\n", name_buf);
        goto ret;
    }

    if (copy_from_user(name_buf, name, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, fd);

    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));

    fnla_put_s32(msg, ret);

    on_sys_call_end("fremovexattr", msg);

    fnla_free(msg);

    ret:
    if (name_buf)
        kfree(name_buf);
    return ret;
}

asmlinkage long custom_getcwd(const struct pt_regs *regs) {
    struct sys_call_hook *hook = sys_call_hooks + __NR_getcwd;

    char __user* ret = (char*) hook->prototype_func(regs);

    char __user *buf = (char __user *) regs->regs[0];
    unsigned long size = regs->regs[1];

    char* buf_buf = NULL;
    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    if (buf == NULL && ret != NULL) {
        buf_buf = vmalloc(PATH_MAX);
        if (copy_from_user(buf_buf, ret, PATH_MAX)) {
            pr_err_with_location("Failed to copy_from_user\n");
            goto ret;
        }
        fnla_put_u32(msg, 0);
        fnla_put_u64(msg, (uintptr_t) ret);
        fnla_put_u32(msg, strlen(buf_buf));
        fnla_put_bytes(msg, buf_buf, strlen(buf_buf));
    } else if (ret != NULL) {
        buf_buf = vmalloc(size);
        if (copy_from_user(buf_buf, buf, size)) {
            pr_err_with_location("Failed to copy_from_user\n");
            goto ret;
        }
        fnla_put_u32(msg, 1);
        fnla_put_u64(msg, (uintptr_t) buf);
        fnla_put_u64(msg, size);

        fnla_put_u32(msg, strlen(buf_buf));
        fnla_put_bytes(msg, buf_buf, strlen(buf_buf));
        fnla_put_u64(msg, (uintptr_t) ret);
    } else {
        fnla_put_u32(msg, 2);
        fnla_put_u64(msg, (uintptr_t) buf);
        fnla_put_u64(msg, size);
        fnla_put_u64(msg, (uintptr_t) ret);
    }

    on_sys_call_end("getcwd", msg);

    fnla_free(msg);

    ret:
    if(buf_buf)
        vfree(buf_buf);
    return (long) ret;
}

asmlinkage long custom_lookup_dcookie(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_lookup_dcookie];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    u64 cookie = (u64) regs->regs[0];
    char __user *buf = (char *) regs->regs[1];
    size_t len = (size_t) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, cookie);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_u64(msg, len);
    fnla_put_s64(msg, ret);

    on_sys_call_end("lookup_dcookie", msg);

    fnla_free(msg);

    ret:
    return ret;
}

// asmlinkage long sys_eventfd(unsigned int count);
// asmlinkage long sys_eventfd2(unsigned int count, int flags);

#if defined(__NR_eventfd)
asmlinkage long custom_eventfd(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_eventfd];

    long ret = (long) hook.prototype_func(regs);
    u32 count = (u32) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, count);
    fnla_put_s64(msg, ret);

    on_sys_call_end("eventfd", msg);

    fnla_free(msg);

    return ret;
}
#endif

#if defined(__NR_eventfd2)
asmlinkage long custom_eventfd2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_eventfd2];

    long ret = (long) hook.prototype_func(regs);
    u32 count = (u32) regs->regs[0];
    s32 flags = (s32) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, count);
    fnla_put_s32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("eventfd2", msg);

    fnla_free(msg);

    return ret;
}
#endif

#if defined(__NR_epoll_create)
asmlinkage long custom_epoll_create(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_create];

    long ret = (long) hook.prototype_func(regs);
    s32 size = (s32) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, size);
    fnla_put_s64(msg, ret);

    on_sys_call_end("epoll_create", msg);

    fnla_free(msg);
    return ret;
}
#endif

asmlinkage long custom_epoll_create1(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_create1];

    long ret = (long) hook.prototype_func(regs);
    s32 flags = (s32) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("epoll_create1", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_epoll_ctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_ctl];

    /*
     * int epoll_ctl(int epfd, int op, int fd,
     *               struct epoll_event *_Nullable event);
     */
    s32 ret = (s32) hook.prototype_func(regs);
    s32 epfd = (s32) regs->regs[0];
    s32 op = (s32) regs->regs[1];
    s32 fd = (s32) regs->regs[2];
    struct epoll_event __user *event = (struct epoll_event __user *) regs->regs[3];

//    typedef union epoll_data {
//        void* ptr;
//        int fd;
//        uint32_t u32;
//        uint64_t u64;
//    } epoll_data_t;

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, epfd);
    fnla_put_s32(msg, op);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) event);

    if (event != NULL) {
        struct epoll_event event_buf;
        if (copy_from_user(&event_buf, event, sizeof(struct epoll_event))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
        fnla_put_u32(msg, event_buf.events);
        fnla_put_u64(msg, (u64) event_buf.data);
    }

    fnla_put_s32(msg, ret);

    on_sys_call_end("epoll_ctl", msg);

    fnla_free(msg);

    return ret;
}

/*
 * int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
 *
 * int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *_Nullable sigmask);
 *
 * int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *_Nullable timeout, const sigset_t *_Nullable sigmask);
 */
#if defined(__NR_epoll_wait)
asmlinkage long custom_epoll_wait(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_wait];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 epfd = (s32) regs->regs[0];
    struct epoll_event __user *events = (struct epoll_event __user *) regs->regs[1];
    s32 maxevents = (s32) regs->regs[2];
    s32 timeout = (s32) regs->regs[3];

    struct epoll_event *events_buf = vmalloc(maxevents * sizeof(struct epoll_event));
    if (events_buf == NULL) {
        pr_err_with_location("Failed to allocate events_buf\n");
        goto ret;
    }

    if (copy_from_user(events_buf, events, maxevents * sizeof(struct epoll_event))) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, epfd);
    fnla_put_u64(msg, (uintptr_t) events);
    fnla_put_s32(msg, maxevents);
    fnla_put_s32(msg, timeout);
    fnla_put_s32(msg, ret);

    if(ret > 0) {
        for (int i = 0; i < ret; i++) {
            fnla_put_u32(msg, events_buf[i].events);
            fnla_put_u64(msg, (u64) events_buf[i].data);
        }
    }

    on_sys_call_end("epoll_wait", msg);

    fnla_free(msg);

    ret:
    if (events_buf)
        vfree(events_buf);
    return ret;
}
#endif

#if defined(__NR_epoll_pwait)
asmlinkage long custom_epoll_pwait(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_pwait];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 epfd = (s32) regs->regs[0];
    struct epoll_event __user *events = (struct epoll_event __user *) regs->regs[1];
    s32 maxevents = (s32) regs->regs[2];
    s32 timeout = (s32) regs->regs[3];
    const sigset_t __user *sigmask = (const sigset_t __user *) regs->regs[4];

    struct epoll_event *events_buf = vmalloc(maxevents * sizeof(struct epoll_event));
    if (events_buf == NULL) {
        pr_err_with_location("Failed to allocate events_buf\n");
        goto ret;
    }

    if (copy_from_user(events_buf, events, maxevents * sizeof(struct epoll_event))) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    sigset_t sigmask_buf;
    if (sigmask != NULL) {
        if (copy_from_user(&sigmask_buf, sigmask, sizeof(sigset_t))) {
            pr_err_with_location("Failed to copy_from_user\n");
            goto ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, epfd);
    fnla_put_u64(msg, (uintptr_t) events);
    fnla_put_s32(msg, maxevents);
    fnla_put_s32(msg, timeout);
    fnla_put_u64(msg, (uintptr_t) sigmask);
    fnla_put_s32(msg, ret);

    if (ret > 0) {
        for (int i = 0; i < ret; i++) {
            fnla_put_u32(msg, events_buf[i].events);
            fnla_put_u64(msg, (u64) events_buf[i].data);
        }
    }

    if(sigmask != NULL) {
        fnla_put_bytes(msg, (char *) &sigmask_buf, sizeof(sigset_t));
    }

    on_sys_call_end("epoll_pwait", msg);

    fnla_free(msg);

    ret:
    if (events_buf)
        vfree(events_buf);
    return ret;
}
#endif

//  int dup(int oldfd);
//  int dup2(int oldfd, int newfd);
//
//  int dup3(int oldfd, int newfd, int flags);
asmlinkage long custom_dup(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_dup];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 old_fd = (s32) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, old_fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("dup", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__NR_dup2)
asmlinkage long custom_dup2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_dup2];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 oldfd = (s32) regs->regs[0];
    s32 newfd = (s32) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, oldfd);
    fnla_put_s32(msg, newfd);
    fnla_put_s32(msg, ret);
    on_sys_call_end("dup2", msg);
    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_dup3(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_dup3];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 oldfd = (s32) regs->regs[0];
    s32 newfd = (s32) regs->regs[1];
    s32 flags = (s32) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, oldfd);
    fnla_put_s32(msg, newfd);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("dup3", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fnctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_fcntl];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int cmd = (int) regs->regs[1];
    unsigned long arg = regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, arg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fnctl", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__NR_inotify_init)
asmlinkage long custom_inotify_init(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_inotify_init];

    s32 ret = (s32) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, ret);

    on_sys_call_end("inotify_init", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_inotify_init1(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_inotify_init1];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 flags = (s32) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);

    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("inotify_init1", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_inotify_add_watch(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_inotify_add_watch];

    s32 ret = (s32) hook.prototype_func(regs);
    s32 fd = (s32) regs->regs[0];
    const char __user *pathname = (const char __user *) regs->regs[1];
    u32 mask = (u32) regs->regs[2];

    char* pathname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (pathname_buf == NULL) {
        pr_err_with_location("Failed to allocate pathname_buf\n");
        goto ret;
    }
    if (copy_from_user(pathname_buf, pathname, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, strlen(pathname_buf));
    fnla_put_bytes(msg, pathname_buf, strlen(pathname_buf));
    fnla_put_u32(msg, mask);
    fnla_put_s32(msg, ret);

    on_sys_call_end("inotify_add_watch", msg);

    fnla_free(msg);

    ret:
    if(pathname_buf)
        kfree(pathname_buf);
    return ret;
}

asmlinkage long custom_inotify_rm_watch(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_inotify_rm_watch];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int wd = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, wd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("inotify_rm_watch", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_ioctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ioctl];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    unsigned int cmd = (unsigned int) regs->regs[1];
    unsigned long arg1 = regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, cmd);
    fnla_put_u64(msg, arg1);
    fnla_put_s32(msg, ret);

    on_sys_call_end("ioctl", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_ioprio_set(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ioprio_set];

    int ret = (int) hook.prototype_func(regs);
    int which = (int) regs->regs[0];
    int who = (int) regs->regs[1];
    int ioprio = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_s32(msg, who);
    fnla_put_s32(msg, ioprio);
    fnla_put_s32(msg, ret);

    on_sys_call_end("ioprio_set", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_ioprio_get(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ioprio_get];

    int ret = (int) hook.prototype_func(regs);
    int which = (int) regs->regs[0];
    int who = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_s32(msg, who);
    fnla_put_s32(msg, ret);

    on_sys_call_end("ioprio_get", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_flock(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_flock];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int cmd = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, cmd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("flock", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_mknodat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mknodat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    char __user *filename = (char *) regs->regs[1];
    umode_t mode = (umode_t) regs->regs[2];
    unsigned long dev = (unsigned long) regs->regs[3];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        goto ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if(!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_u32(msg, mode);
    fnla_put_u64(msg, dev);
    fnla_put_s32(msg, ret);

    on_sys_call_end("mknodat", msg);

    fnla_free(msg);

    ret:
    if(filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_mkdirat(const struct pt_regs *regs) {
    struct sys_call_hook* hook = sys_call_hooks + __NR_mkdirat;

    s32 ret = (s32) hook->prototype_func(regs);
    s32 dfd = (s32) regs->regs[0];
    char __user *pathname = (char *) regs->regs[1];
    umode_t mode = (umode_t) regs->regs[2];

    char* filename = kzalloc(PATH_MAX, GFP_KERNEL);
    if (copy_from_user(filename, pathname, PATH_MAX)) {
        kfree(filename);
        return -1;
    }

    fnla_t msg = fnla_alloc();
    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    size_t filename_len = strlen(filename);
    fnla_put_u32(msg, filename_len);
    fnla_put_bytes(msg, filename, filename_len);
    fnla_put_u32(msg, mode);
    fnla_put_s32(msg, ret);
    on_sys_call_end("mkdirat", msg);
    fnla_free(msg);

    kfree(filename);
    return ret;
}

// int unlinkat(int dirfd, const char *pathname, int flags);
asmlinkage long custom_unlinkat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_unlinkat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    char __user *pathname = (char *) regs->regs[1];
    int flag = (int) regs->regs[2];

    char* filename = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename == NULL) {
        pr_err_with_location("Failed to allocate filename\n");
        goto ret;
    }
    if (copy_from_user(filename, pathname, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if(!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename));
    fnla_put_bytes(msg, filename, strlen(filename));
    fnla_put_s32(msg, flag);
    fnla_put_s32(msg, ret);

    on_sys_call_end("unlinkat", msg);

    fnla_free(msg);

    ret:
    if (filename)
        kfree(filename);
    return ret;
}

// int symlinkat(const char *target, int newdirfd, const char *linkpath);
asmlinkage long custom_symlinkat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_symlinkat];

    int ret = (int) hook.prototype_func(regs);
    char __user *oldname = (char *) regs->regs[0];
    int newdfd = (int) regs->regs[1];
    char __user *newname = (char *) regs->regs[2];

    char* oldname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* newname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if(oldname_buf == NULL) {
        pr_err_with_location("Failed to allocate oldname_buf\n");
        goto ret;
    }
    if(newname_buf == NULL) {
        pr_err_with_location("Failed to allocate newname_buf\n");
        goto ret;
    }
    if (copy_from_user(oldname_buf, oldname, PATH_MAX)
        || copy_from_user(newname_buf, newname, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if(!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(oldname_buf));
    fnla_put_bytes(msg, oldname_buf, strlen(oldname_buf));
    fnla_put_s32(msg, newdfd);
    fnla_put_u32(msg, strlen(newname_buf));
    fnla_put_bytes(msg, newname_buf, strlen(newname_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("symlinkat", msg);

    fnla_free(msg);

    ret:
    if (oldname_buf)
        kfree(oldname_buf);
    if (newname_buf)
        kfree(newname_buf);
    return ret;
}

//   int linkat(int olddirfd, const char *oldpath,
//                  int newdirfd, const char *newpath, int flags);
asmlinkage long custom_linkat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_linkat];

    int ret = (int) hook.prototype_func(regs);
    int olddfd = (int) regs->regs[0];
    char __user *oldname = (char *) regs->regs[1];
    int newdfd = (int) regs->regs[2];
    char __user *newname = (char *) regs->regs[3];
    int flags = (int) regs->regs[4];

    char* oldname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* newname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if(oldname_buf == NULL) {
        pr_err_with_location("Failed to allocate oldname_buf\n");
        goto ret;
    }
    if(newname_buf == NULL) {
        pr_err_with_location("Failed to allocate newname_buf\n");
        goto ret;
    }
    if (copy_from_user(oldname_buf, oldname, PATH_MAX) || copy_from_user(newname_buf, newname, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if(!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, olddfd);
    fnla_put_u32(msg, strlen(oldname_buf));
    fnla_put_bytes(msg, oldname_buf, strlen(oldname_buf));
    fnla_put_s32(msg, newdfd);
    fnla_put_u32(msg, strlen(newname_buf));
    fnla_put_bytes(msg, newname_buf, strlen(newname_buf));
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("linkat", msg);

    fnla_free(msg);

    ret:
    if (oldname_buf)
        kfree(oldname_buf);
    if (newname_buf)
        kfree(newname_buf);
    return ret;
}

#ifdef __ARCH_WANT_RENAMEAT
asmlinkage long custom_renameat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_renameat];

    int ret = (int) hook.prototype_func(regs);
    int olddfd = (int) regs->regs[0];
    char __user *oldname = (char *) regs->regs[1];
    int newdfd = (int) regs->regs[2];
    char __user *newname = (char *) regs->regs[3];

    char* oldname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* newname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (oldname_buf == NULL) {
        pr_err_with_location("Failed to allocate oldname_buf\n");
        goto ret;
    }
    if (newname_buf == NULL) {
        pr_err_with_location("Failed to allocate newname_buf\n");
        goto ret;
    }
    if (copy_from_user(oldname_buf, oldname, PATH_MAX) || copy_from_user(newname_buf, newname, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, olddfd);
    fnla_put_u32(msg, strlen(oldname_buf));
    fnla_put_bytes(msg, oldname_buf, strlen(oldname_buf));
    fnla_put_s32(msg, newdfd);
    fnla_put_u32(msg, strlen(newname_buf));
    fnla_put_bytes(msg, newname_buf, strlen(newname_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("renameat", msg);

    fnla_free(msg);

    ret:
    if (oldname_buf) kfree(oldname_buf);
    if (newname_buf) kfree(newname_buf);
    return ret;
}
#endif

//  int umount(const char *target);
//  int umount2(const char *target, int flags);
asmlinkage long custom_umount2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_umount2];

    int ret = (int) hook.prototype_func(regs);
    char __user *target = (char *) regs->regs[0];
    int flags = (int) regs->regs[1];

    char* target_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (target_buf == NULL) {
        pr_err_with_location("Failed to allocate target_buf\n");
        goto ret;
    }
    if (copy_from_user(target_buf, target, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(target_buf));
    fnla_put_bytes(msg, target_buf, strlen(target_buf));
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("umount2", msg);

    fnla_free(msg);

    ret:
    if (target_buf)
        kfree(target_buf);
    return ret;
}

asmlinkage long custom_mount(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mount];

    int ret = (int) hook.prototype_func(regs);
    char __user *dev_name = (char *) regs->regs[0];
    char __user *dir_name = (char *) regs->regs[1];
    char __user *type = (char *) regs->regs[2];
    unsigned long flags = regs->regs[3];
    void __user *data = (void *) regs->regs[4];

    char* dev_name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* dir_name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* type_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (dev_name_buf == NULL || dir_name_buf == NULL || type_buf == NULL) {
        pr_err_with_location("Failed to allocate buffers\n");
        goto ret;
    }
    if (copy_from_user(dev_name_buf, dev_name, PATH_MAX) ||
        copy_from_user(dir_name_buf, dir_name, PATH_MAX) ||
        copy_from_user(type_buf, type, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(dev_name_buf));
    fnla_put_bytes(msg, dev_name_buf, strlen(dev_name_buf));
    fnla_put_u32(msg, strlen(dir_name_buf));
    fnla_put_bytes(msg, dir_name_buf, strlen(dir_name_buf));
    fnla_put_u32(msg, strlen(type_buf));
    fnla_put_bytes(msg, type_buf, strlen(type_buf));
    fnla_put_u64(msg, flags);
    fnla_put_u64(msg, (uintptr_t) data);

    fnla_put_s32(msg, ret);

    on_sys_call_end("mount", msg);

    fnla_free(msg);

    ret:
    if (dev_name_buf)
        kfree(dev_name_buf);
    if (dir_name_buf)
        kfree(dir_name_buf);
    if (type_buf)
        kfree(type_buf);
    return ret;
}

// int syscall(SYS_pivot_root, const char *new_root, const char *put_old);
asmlinkage long custom_pivot_root(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pivot_root];

    int ret = (int) hook.prototype_func(regs);
    const char __user *new_root = (const char __user *) regs->regs[0];
    const char __user *put_old = (const char __user *) regs->regs[1];

    char* new_root_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    char* put_old_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (new_root_buf == NULL || put_old_buf == NULL) {
        pr_err_with_location("Failed to allocate buffers\n");
        goto ret;
    }
    if (copy_from_user(new_root_buf, new_root, PATH_MAX) || copy_from_user(put_old_buf, put_old, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(new_root_buf));
    fnla_put_bytes(msg, new_root_buf, strlen(new_root_buf));
    fnla_put_u32(msg, strlen(put_old_buf));
    fnla_put_bytes(msg, put_old_buf, strlen(put_old_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("pivot_root", msg);

    fnla_free(msg);

    ret:
    if (new_root_buf)
        kfree(new_root_buf);
    if (put_old_buf)
        kfree(put_old_buf);
    return ret;
}

// long nfsservctl(int cmd, struct nfsctl_arg *argp,
//                       union nfsctl_res *resp);
asmlinkage long custom_nfsservctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_nfsservctl];

    long ret = (long) hook.prototype_func(regs);
    int cmd = (int) regs->regs[0];
    struct nfsctl_arg __user *arg = (struct nfsctl_arg __user *) regs->regs[1];
    struct nfsctl_res __user *res = (struct nfsctl_res __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, (uintptr_t) arg);
    fnla_put_u64(msg, (uintptr_t) res);
    fnla_put_s64(msg, ret);


    on_sys_call_end("nfsservctl", msg);

    fnla_free(msg);

    return ret;
}

//   int statfs(const char *path, struct statfs *buf);
//   int fstatfs(int fd, struct statfs *buf);
asmlinkage long custom_statfs(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_statfs];

    int ret = (int) hook.prototype_func(regs);
    const char __user *path = (const char __user *) regs->regs[0];
    struct statfs __user *buf = (struct statfs __user *) regs->regs[1];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL) {
        pr_err_with_location("Failed to allocate path_buf\n");
        goto ret;
    }
    if (copy_from_user(path_buf, path, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, ret);

    ret:
    if(path_buf)
        kfree(path_buf);
    return ret;
}

asmlinkage long custom_fstatfs(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_fstatfs];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    struct statfs __user *buf = (struct statfs __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fstatfs", msg);

    fnla_free(msg);

    return ret;
}

//int truncate(const char *path, off_t length);
//int ftruncate(int fd, off_t length);

asmlinkage long custom_truncate(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_truncate];

    int ret = (int) hook.prototype_func(regs);
    const char __user *path = (const char __user *) regs->regs[0];
    off_t length = (off_t) regs->regs[1];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL) {
        pr_err_with_location("Failed to allocate path_buf\n");
        goto ret;
    }
    if (copy_from_user(path_buf, path, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));
    fnla_put_u64(msg, length);
    fnla_put_s32(msg, ret);

    on_sys_call_end("truncate", msg);

    fnla_free(msg);

    ret:
    if(path_buf)
        kfree(path_buf);
    return ret;
}

asmlinkage long custom_ftruncate(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_ftruncate];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    off_t length = (off_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, length);
    fnla_put_s32(msg, ret);

    on_sys_call_end("ftruncate", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fallocate(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fallocate];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int mode = (int) regs->regs[1];
    loff_t offset = (loff_t) regs->regs[2];
    loff_t len = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, mode);
    fnla_put_u64(msg, offset);
    fnla_put_u64(msg, len);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fallocate", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_faccessat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_faccessat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    int mode = (int) regs->regs[2];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        goto ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_s32(msg, mode);
    fnla_put_s32(msg, ret);

    on_sys_call_end("faccessat", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_chdir(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_chdir];

    int ret = (int) hook.prototype_func(regs);
    const char __user *filename = (const char __user *) regs->regs[0];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("chdir", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_fchdir(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fchdir];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fchdir", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_chroot(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_chroot];

    int ret = (int) hook.prototype_func(regs);
    const char __user *filename = (const char __user *) regs->regs[0];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("chroot", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_fchmod(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fchmod];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    umode_t mode = (umode_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, mode);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fchmod", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fchmodat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fchmodat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    umode_t mode = (umode_t) regs->regs[2];
    int flag = (int) regs->regs[3];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_u32(msg, mode);
    fnla_put_s32(msg, flag);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fchmodat", msg);

    fnla_free(msg);

    ret:
    if(filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_fchown(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fchown];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    uid_t user = (uid_t) regs->regs[1];
    gid_t group = (gid_t) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, user);
    fnla_put_u32(msg, group);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fchown", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fchownat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fchownat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    uid_t user = (uid_t) regs->regs[2];
    gid_t group = (gid_t) regs->regs[3];
    int flag = (int) regs->regs[4];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_u32(msg, user);
    fnla_put_u32(msg, group);
    fnla_put_s32(msg, flag);

    fnla_put_s32(msg, ret);

    on_sys_call_end("fchownat", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_openat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_openat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    int flags = (int) regs->regs[2];
    umode_t mode = (umode_t) regs->regs[3];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_s32(msg, flags);
    fnla_put_u32(msg, mode);
    fnla_put_s32(msg, ret);

    on_sys_call_end("openat", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

asmlinkage long custom_close(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_close];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("close", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_vhangup(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_vhangup];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("vhangup", msg);

    fnla_free(msg);

    return ret;
}

// int pipe2(int pipefd[2], int flags);
asmlinkage long custom_pipe2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pipe2];

    int ret = (int) hook.prototype_func(regs);
    int __user *fildes = (int __user *) regs->regs[0];
    int flags = (int) regs->regs[1];

    int fildes_buf[2];
    if (copy_from_user(fildes_buf, fildes, sizeof(fildes_buf))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fildes_buf[0]);
    fnla_put_s32(msg, fildes_buf[1]);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("pipe2", msg);

    fnla_free(msg);

    return ret;
}

// int quotactl(int op, const char *_Nullable special, int id,
//                    caddr_t addr);
asmlinkage long custom_quotactl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_quotactl];

    int ret = (int) hook.prototype_func(regs);
    unsigned int cmd = (unsigned int) regs->regs[0];
    const char __user *special = (const char __user *) regs->regs[1];
    int id = (int) regs->regs[2];
    void __user *addr = (void __user *) regs->regs[3];

    char* special_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (special_buf == NULL) {
        pr_err_with_location("Failed to allocate special_buf\n");
        return ret;
    }
    if (copy_from_user(special_buf, special, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, cmd);
    fnla_put_u32(msg, strlen(special_buf));
    fnla_put_bytes(msg, special_buf, strlen(special_buf));
    fnla_put_s32(msg, id);
    fnla_put_u64(msg, (uintptr_t) addr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("quotactl", msg);

    fnla_free(msg);

    ret:
    if(special_buf)
        kfree(special_buf);
    return ret;
}

asmlinkage long custom_getdents64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getdents64];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *) regs->regs[1];
    unsigned int count = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }


    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) dirent);
    fnla_put_u32(msg, count);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getdents64", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_lseek(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_lseek];

    loff_t ret = (loff_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    loff_t offset = (loff_t) regs->regs[1];
    unsigned int whence = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, offset);
    fnla_put_u32(msg, whence);
    fnla_put_u64(msg, ret);

    on_sys_call_end("lseek", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_read(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_read];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    char __user *buf = (char *) regs->regs[1];
    size_t count = (size_t) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, count);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s64(msg, ret);

    on_sys_call_end("read", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_write(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_write];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    char __user *buf = (char *) regs->regs[1];
    size_t count = (size_t) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, count);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s64(msg, ret);

    on_sys_call_end("write", msg);

    fnla_free(msg);

    return ret;
}

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
//       ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
//
asmlinkage long custom_readv(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_readv];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    unsigned long iovcnt = (unsigned long) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) iov);
    fnla_put_u32(msg, iovcnt);
    fnla_put_s64(msg, ret);

    on_sys_call_end("readv", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_writev(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_writev];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *vec = (const struct iovec __user *) regs->regs[1];
    unsigned long vlen = (unsigned long) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) vec);
    fnla_put_u32(msg, vlen);
    fnla_put_s64(msg, ret);

    on_sys_call_end("writev", msg);

    fnla_free(msg);

    return ret;
}

//   ssize_t pread(int fd, void buf[.count], size_t count,
//                     off_t offset);
//       ssize_t pwrite(int fd, const void buf[.count], size_t count,
//                     off_t offset);
asmlinkage long custom_pread64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pread64];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    char __user *buf = (char *) regs->regs[1];
    size_t count = (size_t) regs->regs[2];
    loff_t pos = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, count);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_u64(msg, pos);
    fnla_put_s64(msg, ret);

    on_sys_call_end("pread64", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_pwrite64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pwrite64];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    char __user *buf = (char *) regs->regs[1];
    size_t count = (size_t) regs->regs[2];
    loff_t pos = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, count);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_u64(msg, pos);
    fnla_put_s64(msg, ret);

    on_sys_call_end("pwrite64", msg);

    fnla_free(msg);

    return ret;
}

////       ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
////                       off_t offset);
////       ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
////                       off_t offset);
////
////       ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
////                       off_t offset, int flags);
////       ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
////                       off_t offset, int flags);
asmlinkage long custom_preadv(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_preadv];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    int iovcnt = (int) regs->regs[2];
    loff_t offset = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) iov);
    fnla_put_u32(msg, iovcnt);
    fnla_put_u64(msg, offset);
    fnla_put_s64(msg, ret);

    on_sys_call_end("preadv", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_pwritev(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pwritev];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    int iovcnt = (int) regs->regs[2];
    loff_t offset = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) iov);
    fnla_put_u32(msg, iovcnt);
    fnla_put_u64(msg, offset);
    fnla_put_s64(msg, ret);

    on_sys_call_end("pwritev", msg);

    fnla_free(msg);

    return ret;
}

// ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset,
//                        size_t count);
asmlinkage long custom_sendfile(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_sendfile];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int out_fd = (int) regs->regs[0];
    int in_fd = (int) regs->regs[1];
    off_t __user *offset = (off_t __user *) regs->regs[2];
    size_t count = (size_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, out_fd);
    fnla_put_s32(msg, in_fd);
    fnla_put_u64(msg, (uintptr_t) offset);
    fnla_put_u32(msg, count);
    fnla_put_s64(msg, ret);

    on_sys_call_end("sendfile", msg);

    fnla_free(msg);

    return ret;
}

// int pselect(int nfds, fd_set *readfds, fd_set *writefds,
//            fd_set *exceptfds, const struct timespec *timeout,
//            const sigset_t *sigmask);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_pselect6(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pselect6];

    int ret = (int) hook.prototype_func(regs);
    int nfds = (int) regs->regs[0];
    fd_set __user *readfds = (fd_set __user *) regs->regs[1];
    fd_set __user *writefds = (fd_set __user *) regs->regs[2];
    fd_set __user *exceptfds = (fd_set __user *) regs->regs[3];
    const struct timespec __user *timeout = (const struct timespec __user *) regs->regs[4];
    const sigset_t __user *sigmask = (const sigset_t __user *) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, nfds);
    fnla_put_u64(msg, (uintptr_t) readfds);
    fnla_put_u64(msg, (uintptr_t) writefds);
    fnla_put_u64(msg, (uintptr_t) exceptfds);
    fnla_put_u64(msg, (uintptr_t) timeout);
    fnla_put_u64(msg, (uintptr_t) sigmask);
    fnla_put_s32(msg, ret);

    on_sys_call_end("pselect6", msg);

    fnla_free(msg);

    return ret;
}

// int ppoll(struct pollfd *fds, nfds_t nfds,
//        const struct timespec *timeout_ts, const sigset_t *sigmask);
asmlinkage long custom_ppoll(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ppoll];

    int ret = (int) hook.prototype_func(regs);
    struct pollfd __user *fds = (struct pollfd __user *) regs->regs[0];
    u32 nfds = (u32) regs->regs[1];
    const struct timespec __user *timeout_ts = (const struct timespec __user *) regs->regs[2];
    const sigset_t __user *sigmask = (const sigset_t __user *) regs->regs[3];
    size_t sigsetsize = (size_t) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) fds);
    fnla_put_u32(msg, nfds);
    fnla_put_u64(msg, (uintptr_t) timeout_ts);
    fnla_put_u64(msg, (uintptr_t) sigmask);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("ppoll", msg);

    fnla_free(msg);

    return ret;
}
#endif

//int signalfd(int fd, const sigset_t *mask, int flags);
asmlinkage long custom_signalfd4(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_signalfd4];

    int ret = (int) hook.prototype_func(regs);
    int ufd = (int) regs->regs[0];
    const sigset_t __user *user_mask = (const sigset_t __user *) regs->regs[1];
    size_t sizemask = (size_t) regs->regs[2];
    int flags = (int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ufd);
    fnla_put_u64(msg, (uintptr_t) user_mask);
    fnla_put_u32(msg, sizemask);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("signalfd4", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_vmsplice(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_vmsplice];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    unsigned long nr_segs = (unsigned long) regs->regs[2];
    unsigned int flags = (unsigned int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) iov);
    fnla_put_u32(msg, nr_segs);
    fnla_put_u32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("vmsplice", msg);

    fnla_free(msg);

    return ret;
}

// ssize_t splice(int fd_in, off_t *_Nullable off_in,
//                      int fd_out, off_t *_Nullable off_out,
//                      size_t len, unsigned int flags);
asmlinkage long custom_splice(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_splice];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd_in = (int) regs->regs[0];
    loff_t __user *off_in = (loff_t __user *) regs->regs[1];
    int fd_out = (int) regs->regs[2];
    loff_t __user *off_out = (loff_t __user *) regs->regs[3];
    size_t len = (size_t) regs->regs[4];
    unsigned int flags = (unsigned int) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd_in);
    fnla_put_u64(msg, (uintptr_t) off_in);
    fnla_put_s32(msg, fd_out);
    fnla_put_u64(msg, (uintptr_t) off_out);
    fnla_put_u32(msg, len);
    fnla_put_u32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("splice", msg);

    fnla_free(msg);

    return ret;
}

// ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
asmlinkage long custom_tee(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_tee];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fdin = (int) regs->regs[0];
    int fdout = (int) regs->regs[1];
    size_t len = (size_t) regs->regs[2];
    unsigned int flags = (unsigned int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fdin);
    fnla_put_s32(msg, fdout);
    fnla_put_u32(msg, len);
    fnla_put_u32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("tee", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_readlinkat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_readlinkat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *path = (const char __user *) regs->regs[1];
    char __user *buf = (char __user *) regs->regs[2];
    int bufsiz = (int) regs->regs[3];

    char* path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL) {
        pr_err_with_location("Failed to allocate path_buf\n");
        return ret;
    }
    if (copy_from_user(path_buf, path, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(path_buf));
    fnla_put_bytes(msg, path_buf, strlen(path_buf));
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, bufsiz);
    fnla_put_s32(msg, ret);

    on_sys_call_end("readlinkat", msg);

    fnla_free(msg);

    ret:
    if (path_buf)
        kfree(path_buf);
    return ret;
}

// int fstatat(int dirfd, const char *pathname, struct stat *buf,
//            int flags);
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
asmlinkage long custom_fstatat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_fstatat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    struct kstat __user *statbuf = (struct kstat __user *) regs->regs[2];
    int flag = (int) regs->regs[3];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_u64(msg, (uintptr_t) statbuf);
    fnla_put_s32(msg, flag);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fstatat", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}

//int fstat(int fd, struct stat *buf);
asmlinkage long custom_fstat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_fstat];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    struct kstat __user *statbuf = (struct kstat __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) statbuf);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fstat", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_sync(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sync];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sync", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fsync(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fsync];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fsync", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fdatasync(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fdatasync];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fdatasync", msg);

    fnla_free(msg);

    return ret;
}


#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
asmlinkage long custom_sync_file_range2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sync_file_range2];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];
    loff_t offset = (loff_t) regs->regs[2];
    loff_t nbytes = (loff_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, flags);
    fnla_put_u64(msg, offset);
    fnla_put_u64(msg, nbytes);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sync_file_range2", msg);

    fnla_free(msg);

    return ret;
}
#else
// int sync_file_range(int fd, off_t offset, off_t nbytes,
//                           unsigned int flags);
asmlinkage long custom_sync_file_range(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sync_file_range];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    loff_t offset = (loff_t) regs->regs[1];
    loff_t nbytes = (loff_t) regs->regs[2];
    unsigned int flags = (unsigned int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, offset);
    fnla_put_u64(msg, nbytes);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sync_file_range", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_timerfd_create(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timerfd_create];

    int ret = (int) hook.prototype_func(regs);
    int clockid = (int) regs->regs[0];
    int flags = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, clockid);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timerfd_create", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_timerfd_settime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timerfd_settime];

    int ret = (int) hook.prototype_func(regs);
    int ufd = (int) regs->regs[0];
    int flags = (int) regs->regs[1];
    const struct __kernel_itimerspec __user *new_value = (const struct __kernel_itimerspec __user *) regs->regs[2];
    const struct __kernel_itimerspec __user *old_value = (const struct __kernel_itimerspec __user *) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ufd);
    fnla_put_s32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) new_value);
    fnla_put_u64(msg, (uintptr_t) old_value);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timerfd_settime", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_timerfd_gettime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timerfd_gettime];

    int ret = (int) hook.prototype_func(regs);
    int ufd = (int) regs->regs[0];
    struct __kernel_itimerspec __user *otmr = (struct __kernel_itimerspec __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ufd);
    fnla_put_u64(msg, (uintptr_t) otmr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timerfd_gettime", msg);

    fnla_free(msg);

    return ret;
}
#endif

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_utimensat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_utimensat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    struct __kernel_timespec __user *utimes = (struct __kernel_timespec __user *) regs->regs[2];
    int flags = (int) regs->regs[3];

    char* filename_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (filename_buf == NULL) {
        pr_err_with_location("Failed to allocate filename_buf\n");
        return ret;
    }
    if (copy_from_user(filename_buf, filename, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u32(msg, strlen(filename_buf));
    fnla_put_bytes(msg, filename_buf, strlen(filename_buf));
    fnla_put_u64(msg, (uintptr_t) utimes);
    fnla_put_s32(msg, flags);

    on_sys_call_end("utimensat", msg);

    fnla_free(msg);

    ret:
    if (filename_buf)
        kfree(filename_buf);
    return ret;
}
#endif

asmlinkage long custom_acct(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_acct];

    int ret = (int) hook.prototype_func(regs);
    const char __user *name = (const char __user *) regs->regs[0];

    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (name_buf == NULL) {
        pr_err_with_location("Failed to allocate name_buf\n");
        return ret;
    }
    if (copy_from_user(name_buf, name, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("acct", msg);

    fnla_free(msg);

    ret:
    if (name_buf)
        kfree(name_buf);
    return ret;
}

asmlinkage long custom_capget(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_capget];

    int ret = (int) hook.prototype_func(regs);
    cap_user_header_t header = (cap_user_header_t) regs->regs[0];
    cap_user_data_t data = (cap_user_data_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) header);
    fnla_put_u64(msg, (uintptr_t) data);
    fnla_put_s32(msg, ret);

    on_sys_call_end("capget", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_capset(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_capset];

    int ret = (int) hook.prototype_func(regs);
    cap_user_header_t header = (cap_user_header_t) regs->regs[0];
    cap_user_data_t data = (cap_user_data_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) header);
    fnla_put_u64(msg, (uintptr_t) data);
    fnla_put_s32(msg, ret);

    on_sys_call_end("capset", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_personality(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_personality];

    int ret = (int) hook.prototype_func(regs);
    unsigned long persona = (unsigned long ) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, persona);
    fnla_put_s32(msg, ret);

    on_sys_call_end("personality", msg);

    fnla_free(msg);

    return ret;
}


asmlinkage long custom_exit(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_exit];

    int ret = (int) hook.prototype_func(regs);
    int status = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, status);
    fnla_put_s32(msg, ret);

    on_sys_call_end("exit", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_exit_group(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_exit_group];

    int ret = (int) hook.prototype_func(regs);
    int status = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, status);
    fnla_put_s32(msg, ret);

    on_sys_call_end("exit_group", msg);

    fnla_free(msg);

    return ret;
}

// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
asmlinkage long custom_waitid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_waitid];

    int ret = (int) hook.prototype_func(regs);
    int idtype = (int) regs->regs[0];
    uint32_t id = (uint32_t) regs->regs[1];
    siginfo_t __user *infop = (siginfo_t __user *) regs->regs[2];
    int options = (int) regs->regs[3];
    struct rusage __user *ru = (struct rusage __user *) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, idtype);
    fnla_put_u32(msg, id);
    fnla_put_u64(msg, (uintptr_t) infop);
    fnla_put_s32(msg, options);
    fnla_put_u64(msg, (uintptr_t) ru);
    fnla_put_s32(msg, ret);

    on_sys_call_end("waitid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_set_tid_address(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_set_tid_address];

    int ret = (int) hook.prototype_func(regs);
    int __user *tidptr = (int __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) tidptr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("set_tid_address", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_unshare(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_unshare];

    int ret = (int) hook.prototype_func(regs);
    unsigned long unshare_flags = (unsigned long) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, unshare_flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("unshare", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_futex(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_futex];

//    int __user *uaddr = (int __user *) regs->regs[0];
//    int op = (int) regs->regs[1];
//    int val = (int) regs->regs[2];
//    const struct timespec __user *timeout = (const struct timespec __user *) regs->regs[3];
//    int __user *uaddr2 = (int __user *) regs->regs[4];
//    int val3 = (int) regs->regs[5];

// skip futex
    return hook.prototype_func(regs);
}
#endif

asmlinkage long custom_set_robust_list(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_set_robust_list];

    int ret = (int) hook.prototype_func(regs);
    struct robust_list_head __user *head = (struct robust_list_head __user *) regs->regs[0];
    size_t len = (size_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) head);
    fnla_put_u32(msg, len);
    fnla_put_s32(msg, ret);

    on_sys_call_end("set_robust_list", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_get_robust_list(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_get_robust_list];

    int ret = (int) hook.prototype_func(regs);
    int pid = (int) regs->regs[0];
    struct robust_list_head __user *head_ptr = (struct robust_list_head __user *) regs->regs[1];
    size_t __user *len_ptr = (size_t __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) head_ptr);
    fnla_put_u64(msg, (uintptr_t) len_ptr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("get_robust_list", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_nanosleep(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_nanosleep];

    int ret = (int) hook.prototype_func(regs);
    const struct __kernel_timespec __user *rqtp = (const struct __kernel_timespec __user *) regs->regs[0];
    struct __kernel_timespec rqtp_val;

    if (copy_from_user(&rqtp_val, rqtp, sizeof(struct __kernel_timespec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) rqtp);
    fnla_put_u64(msg, rqtp_val.tv_sec);
    fnla_put_u64(msg, rqtp_val.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("nanosleep", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_getitimer(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getitimer];

    int ret = (int) hook.prototype_func(regs);
    int which = (int) regs->regs[0];
    char __user *value = (char __user *) regs->regs[1];

    struct timeval {
        __kernel_old_time_t	tv_sec;		/* seconds */
        __kernel_suseconds_t	tv_usec;	/* microseconds */
    };

    struct itimerval {
        struct timeval it_interval;/* timer interval */
        struct timeval it_value;	/* current value */
    };

    struct itimerval val;
    if (copy_from_user(&val, value, sizeof(struct itimerval))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u64(msg, val.it_interval.tv_sec);
    fnla_put_u64(msg, val.it_interval.tv_usec);
    fnla_put_u64(msg, val.it_value.tv_sec);
    fnla_put_u64(msg, val.it_value.tv_usec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getitimer", msg);

    fnla_free(msg);

    return ret;
}

//int setitimer(int which, const struct itimerval *restrict new_value,
//                     struct itimerval *_Nullable restrict old_value);
asmlinkage long custom_setitimer(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setitimer];

    int ret = (int) hook.prototype_func(regs);

    struct timeval {
        __kernel_old_time_t	tv_sec;		/* seconds */
        __kernel_suseconds_t	tv_usec;	/* microseconds */
    };

    struct itimerval {
        struct timeval it_interval;/* timer interval */
        struct timeval it_value;	/* current value */
    };

    int which = (int) regs->regs[0];
    const struct itimerval __user *new_value = (const struct itimerval __user *) regs->regs[1];
    struct itimerval __user *old_value = (struct itimerval __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_u64(msg, (uintptr_t) new_value);
    fnla_put_u64(msg, (uintptr_t) old_value);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setitimer", msg);

    fnla_free(msg);

    return ret;
}

//long syscall(SYS_kexec_load, unsigned long entry,
//                    unsigned long nr_segments, struct kexec_segment *segments,
//                    unsigned long flags);
//       long syscall(SYS_kexec_file_load, int kernel_fd, int initrd_fd,
//                    unsigned long cmdline_len, const char *cmdline,
//                    unsigned long flags);
asmlinkage long custom_kexec_load(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_kexec_load];

    long ret = (long) hook.prototype_func(regs);
    unsigned long entry = (unsigned long) regs->regs[0];
    unsigned long nr_segments = (unsigned long) regs->regs[1];
    struct kexec_segment __user *segments = (struct kexec_segment __user *) regs->regs[2];
    unsigned long flags = (unsigned long) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, entry);
    fnla_put_u64(msg, nr_segments);
    fnla_put_u64(msg, (uintptr_t) segments);
    fnla_put_u64(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("kexec_load", msg);

    fnla_free(msg);

    return ret;
}

//  int syscall(SYS_init_module, void module_image[.len], unsigned long len,
//                   const char *param_values);
//       int syscall(SYS_finit_module, int fd,
//                   const char *param_values, int flags);
asmlinkage long custom_init_module(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_init_module];

    int ret = (int) hook.prototype_func(regs);
    void __user *umod = (void __user *) regs->regs[0];
    unsigned long len = (unsigned long) regs->regs[1];
    const char __user *uargs = (const char __user *) regs->regs[2];

    char* umod_buf = kzalloc(len, GFP_KERNEL);
    if (umod_buf == NULL) {
        pr_err_with_location("Failed to allocate umod_buf\n");
        return ret;
    }
    char* uargs_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (uargs_buf == NULL) {
        pr_err_with_location("Failed to allocate uargs_buf\n");
        goto ret;
    }
    if (copy_from_user(umod_buf, umod, len) || copy_from_user(uargs_buf, uargs, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, len);
    fnla_put_bytes(msg, umod_buf, len);
    fnla_put_u32(msg, strlen(uargs_buf));
    fnla_put_bytes(msg, uargs_buf, strlen(uargs_buf));
    fnla_put_s32(msg, ret);

    on_sys_call_end("init_module", msg);

    fnla_free(msg);

    ret:
    if (umod_buf)
        kfree(umod_buf);
    if (uargs_buf)
        kfree(uargs_buf);
    return ret;
}

asmlinkage long custom_delete_module(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_delete_module];

    int ret = (int) hook.prototype_func(regs);
    const char __user *name = (const char __user *) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];

    char* name_buf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (name_buf == NULL) {
        pr_err_with_location("Failed to allocate name_buf\n");
        return ret;
    }
    if (copy_from_user(name_buf, name, PATH_MAX)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, strlen(name_buf));
    fnla_put_bytes(msg, name_buf, strlen(name_buf));
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("delete_module", msg);

    fnla_free(msg);

    ret:
    if (name_buf)
        kfree(name_buf);
    return ret;
}

asmlinkage long custom_timer_create(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_create];

    int ret = (int) hook.prototype_func(regs);
    clockid_t clockid = (clockid_t) regs->regs[0];
    struct sigevent __user *sevp = (struct sigevent __user *) regs->regs[1];
    timer_t __user *timerid = (timer_t __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, clockid);
    fnla_put_u64(msg, (uintptr_t) sevp);
    fnla_put_u64(msg, (uintptr_t) timerid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timer_create", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_timer_gettime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_gettime];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];
    struct __kernel_itimerspec __user *value = (struct __kernel_itimerspec __user *) regs->regs[1];
    struct __kernel_itimerspec val;

    if (copy_from_user(&val, value, sizeof(struct __kernel_itimerspec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, timerid);
    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u64(msg, val.it_interval.tv_sec);
    fnla_put_u64(msg, val.it_interval.tv_nsec);
    fnla_put_u64(msg, val.it_value.tv_sec);
    fnla_put_u64(msg, val.it_value.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timer_gettime", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_timer_getoverrun(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_getoverrun];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, timerid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timer_getoverrun", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_timer_settime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_settime];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];
    int flags = (int) regs->regs[1];
    const struct __kernel_itimerspec __user *new_value = (const struct __kernel_itimerspec __user *) regs->regs[2];
    struct __kernel_itimerspec val;

    if (copy_from_user(&val, new_value, sizeof(struct __kernel_itimerspec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, timerid);
    fnla_put_s32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) new_value);
    fnla_put_u64(msg, val.it_interval.tv_sec);
    fnla_put_u64(msg, val.it_interval.tv_nsec);
    fnla_put_u64(msg, val.it_value.tv_sec);
    fnla_put_u64(msg, val.it_value.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timer_settime", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_timer_delete(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_delete];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, timerid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("timer_delete", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_clock_settime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_settime];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    const struct __kernel_timespec __user *tp = (const struct __kernel_timespec __user *) regs->regs[1];

    struct __kernel_timespec val;
    if (copy_from_user(&val, tp, sizeof(struct __kernel_timespec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which_clock);
    fnla_put_u64(msg, (uintptr_t) tp);
    fnla_put_u64(msg, val.tv_sec);
    fnla_put_u64(msg, val.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("clock_settime", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_clock_gettime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_gettime];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timespec __user *tp = (struct __kernel_timespec __user *) regs->regs[1];
    struct __kernel_timespec val;

    if (copy_from_user(&val, tp, sizeof(struct __kernel_timespec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which_clock);
    fnla_put_u64(msg, (uintptr_t) tp);
    fnla_put_u64(msg, val.tv_sec);
    fnla_put_u64(msg, val.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("clock_gettime", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_clock_getres(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_getres];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timespec __user *tp = (struct __kernel_timespec __user *) regs->regs[1];
    struct __kernel_timespec val;

    if (copy_from_user(&val, tp, sizeof(struct __kernel_timespec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which_clock);
    fnla_put_u64(msg, (uintptr_t) tp);
    fnla_put_u64(msg, val.tv_sec);
    fnla_put_u64(msg, val.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("clock_getres", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_clock_nanosleep(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_nanosleep];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    int flags = (int) regs->regs[1];
    const struct __kernel_timespec __user *rqtp = (const struct __kernel_timespec __user *) regs->regs[2];
    const struct __kernel_timespec __user *rmtp = (const struct __kernel_timespec __user *) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which_clock);
    fnla_put_s32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) rqtp);
    fnla_put_u64(msg, (uintptr_t) rmtp);
    fnla_put_s32(msg, ret);

    on_sys_call_end("clock_nanosleep", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_syslog(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_syslog];

    int ret = (int) hook.prototype_func(regs);
    int type = (int) regs->regs[0];
    char __user *buf = (char __user *) regs->regs[1];
    int len = (int) regs->regs[2];

    char* buf_buf = kzalloc(len, GFP_KERNEL);
    if (buf_buf == NULL) {
        pr_err_with_location("Failed to allocate buf_buf\n");
        return ret;
    }

    if (copy_from_user(buf_buf, buf, len)) {
        pr_err_with_location("Failed to copy_from_user\n");
        goto ret;
    }

    fnla_t msg = fnla_alloc();

    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, type);
    fnla_put_u32(msg, len);
    fnla_put_bytes(msg, buf_buf, len);
    fnla_put_s32(msg, ret);

    on_sys_call_end("syslog", msg);

    fnla_free(msg);

    ret:
    if (buf_buf)
        kfree(buf_buf);
    return ret;
}

asmlinkage long custom_ptrace(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ptrace];

    long ret = (long) hook.prototype_func(regs);
    long request = (long) regs->regs[0];
    long pid = (long) regs->regs[1];
    unsigned long addr = (unsigned long) regs->regs[2];
    unsigned long data = (unsigned long) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, request);
    fnla_put_s64(msg, pid);
    fnla_put_u64(msg, addr);
    fnla_put_u64(msg, data);
    fnla_put_s64(msg, ret);

    on_sys_call_end("ptrace", msg);

    fnla_free(msg);
    return ret;
}

// int sched_setparam(pid_t pid, const struct sched_param *param);
//       int sched_getparam(pid_t pid, struct sched_param *param);
asmlinkage long custom_sched_setparam(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_setparam];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct sched_param __user *param = (struct sched_param __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) param);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_setparam", msg);

    fnla_free(msg);

    return ret;
}

// int sched_setscheduler(pid_t pid, int policy,
//                              const struct sched_param *param);
//       int sched_getscheduler(pid_t pid);
asmlinkage long custom_sched_setscheduler(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_setscheduler];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    int policy = (int) regs->regs[1];
    struct sched_param __user *param = (struct sched_param __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, policy);
    fnla_put_u64(msg, (uintptr_t) param);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_setscheduler", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sched_getscheduler(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_getscheduler];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_getscheduler", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sched_getparam(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_getparam];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct sched_param __user *param = (struct sched_param __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) param);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_getparam", msg);

    fnla_free(msg);

    return ret;
}

//pid: pid_t[K] - The pid of the process or thread whose affinity mask should be set.
//cpusetsize: size_t[K] - The size in bytes of the data pointed to by mask.
//mask: unsigned long*[K] - A pointer to an array of unsigned longs that comprises the CPU affinity mask.
asmlinkage long custom_sched_setaffinity(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_setaffinity];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    size_t cpusetsize = (size_t) regs->regs[1];
    unsigned long __user *mask = (unsigned long __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u32(msg, cpusetsize);
    fnla_put_u64(msg, (uintptr_t) mask);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_setaffinity", msg);

    fnla_free(msg);

    return ret;
}

//pid:pid_t[U] - process ID of the thread whose affinity is to be retrieved.
//cpusetsize:size_t[U] - number of bytes in the bitmask pointed to by mask.
//mask:unsigned long*[U] - pointer to a bit mask for the CPUs on which the thread may run.
asmlinkage long custom_sched_getaffinity(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_getaffinity];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    size_t cpusetsize = (size_t) regs->regs[1];
    unsigned long __user *mask = (unsigned long __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u32(msg, cpusetsize);
    fnla_put_u64(msg, (uintptr_t) mask);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_getaffinity", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sched_yield(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_yield];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_yield", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sched_get_priority_max(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_get_priority_max];

    int ret = (int) hook.prototype_func(regs);
    int policy = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, policy);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_get_priority_max", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sched_get_priority_min(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_get_priority_min];

    int ret = (int) hook.prototype_func(regs);
    int policy = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, policy);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_get_priority_min", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_sched_rr_get_interval(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_rr_get_interval];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct __kernel_timespec __user *interval = (struct __kernel_timespec __user *) regs->regs[1];
    struct __kernel_timespec val;

    if (copy_from_user(&val, interval, sizeof(struct __kernel_timespec))) {
        pr_err_with_location("Failed to copy_from_user\n");
        return ret;
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) interval);
    fnla_put_u64(msg, val.tv_sec);
    fnla_put_u64(msg, val.tv_nsec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_rr_get_interval", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_restart_syscall(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_restart_syscall];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("restart_syscall", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_kill(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_kill];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    int sig = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, sig);
    fnla_put_s32(msg, ret);

    on_sys_call_end("kill", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_tkill(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_tkill];

    int ret = (int) hook.prototype_func(regs);
    int tid = (int) regs->regs[0];
    int sig = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, tid);
    fnla_put_s32(msg, sig);
    fnla_put_s32(msg, ret);

    on_sys_call_end("tkill", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_tgkill(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_tgkill];

    int ret = (int) hook.prototype_func(regs);
    int tgid = (int) regs->regs[0];
    int tid = (int) regs->regs[1];
    int sig = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, tgid);
    fnla_put_s32(msg, tid);
    fnla_put_s32(msg, sig);
    fnla_put_s32(msg, ret);

    on_sys_call_end("tgkill", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sigaltstack(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sigaltstack];

    int ret = (int) hook.prototype_func(regs);
    void* uss = (void*) regs->regs[0];
    void* uoss = (void*) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) uss);
    fnla_put_u64(msg, (uintptr_t) uoss);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sigaltstack", msg);

    fnla_free(msg);

    return ret;
}

//mask:sigset_t*[K, U] - pointer to user space memory which holds the signal mask to be replaced.
//sigsetsize:size_t[K] - size of the mask in bytes.
asmlinkage long custom_rt_sigsuspend(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigsuspend];

    int ret = (int) hook.prototype_func(regs);
    sigset_t __user *mask = (sigset_t __user *) regs->regs[0];
    size_t sigsetsize = (size_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) mask);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigsuspend", msg);

    fnla_free(msg);

    return ret;
}

//signum:int[K] - Signal to be handled, which can either be a POSIX signal or real-time signal.
//act:const struct sigaction*[K] - New signal action, or NULL to restore default action.
//oldact:struct sigaction*[K] - Output parameter which will return the previous signal action, or NULL if not required.
//sigsetsize:size_t[K] - Size of the sigset specified by act in bytes.
asmlinkage long custom_rt_sigaction(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigaction];

    int ret = (int) hook.prototype_func(regs);
    int signum = (int) regs->regs[0];
    struct sigaction __user *act = (struct sigaction __user *) regs->regs[1];
    struct sigaction __user *oldact = (struct sigaction __user *) regs->regs[2];
    size_t sigsetsize = (size_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, signum);
    fnla_put_u64(msg, (uintptr_t) act);
    fnla_put_u64(msg, (uintptr_t) oldact);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigaction", msg);

    fnla_free(msg);

    return ret;
}

//int syscall(SYS_rt_sigprocmask, int how,
//                                  const kernel_sigset_t *_Nullable set,
//                                  kernel_sigset_t *_Nullable oldset,
//                                  size_t sigsetsize);
//
//       /* Prototype for the legacy system call */
// [[deprecated]] int syscall(SYS_sigprocmask, int how,
//                                  const old_kernel_sigset_t *_Nullable set,
//                                  old_kernel_sigset_t *_Nullable oldset);
#if defined(__NR_sigprocmask)
asmlinkage long custom_sigprocmask(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sigprocmask];

    int ret = (int) hook.prototype_func(regs);
    int how = (int) regs->regs[0];
    void __user *set = (void __user *) regs->regs[1];
    void __user *oldset = (void __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, how);
    fnla_put_u64(msg, (uintptr_t) set);
    fnla_put_u64(msg, (uintptr_t) oldset);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sigprocmask", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_rt_sigprocmask(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigprocmask];

    int ret = (int) hook.prototype_func(regs);
    int how = (int) regs->regs[0];
    void __user *set = (void __user *) regs->regs[1];
    void __user *oldset = (void __user *) regs->regs[2];
    size_t sigsetsize = (size_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, how);
    fnla_put_u64(msg, (uintptr_t) set);
    fnla_put_u64(msg, (uintptr_t) oldset);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigprocmask", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_rt_sigpending(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigpending];

    int ret = (int) hook.prototype_func(regs);
    sigset_t __user *set = (sigset_t __user *) regs->regs[0];
    size_t sigsetsize = (size_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) set);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigpending", msg);

    fnla_free(msg);

    return ret;
}

//set:const sigset_t*[K] - a pointer to a structure to examine a set of signals that the process may be waiting for.
//info:siginfo_t*[U] - a pointer to a structure where information about the signal caught is stored.
//timeout:const struct timespec*[K] - a pointer to a structure that specifies an upper limit on the amount of time that the call should block.
//sigsetsize:size_t[K] - the size of the signal set in bytes.
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_rt_sigtimedwait(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigtimedwait];

    int ret = (int) hook.prototype_func(regs);
    const sigset_t __user *set = (const sigset_t __user *) regs->regs[0];
    siginfo_t __user *info = (siginfo_t __user *) regs->regs[1];
    const struct __kernel_timespec __user *timeout = (const struct __kernel_timespec __user *) regs->regs[2];
    size_t sigsetsize = (size_t) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) set);
    fnla_put_u64(msg, (uintptr_t) info);
    fnla_put_u64(msg, (uintptr_t) timeout);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigtimedwait", msg);

    fnla_free(msg);

    return ret;
}
#endif

//tgid:pid_t[K] - thread group identifier for which signal is to be sent.
//sig:int[U] - signal to be sent.
//info:siginfo_t*[U] - signal info.
asmlinkage long custom_rt_sigqueueinfo(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigqueueinfo];

    int ret = (int) hook.prototype_func(regs);
    pid_t tgid = (pid_t) regs->regs[0];
    int sig = (int) regs->regs[1];
    siginfo_t __user *info = (siginfo_t __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, tgid);
    fnla_put_s32(msg, sig);
    fnla_put_u64(msg, (uintptr_t) info);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigqueueinfo", msg);

    fnla_free(msg);

    return ret;
}

//ustack:pointer[KU] - Pointer to the user-space signal stack context. The signal stack context is defined by each architecture.
asmlinkage long custom_rt_sigreturn(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigreturn];

    int ret = (int) hook.prototype_func(regs);
    void __user *ustack = (void __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) ustack);
    fnla_put_s32(msg, ret);

    on_sys_call_end("rt_sigreturn", msg);

    fnla_free(msg);

    return ret;
}

//int getpriority(int which, id_t who);
//int setpriority(int which, id_t who, int prio);
asmlinkage long custom_setpriority(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setpriority];

    int ret = (int) hook.prototype_func(regs);
    int which = (int) regs->regs[0];
    int who = (int) regs->regs[1];
    int niceval = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_s32(msg, who);
    fnla_put_s32(msg, niceval);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setpriority", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getpriority(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getpriority];

    int ret = (int) hook.prototype_func(regs);
    int which = (int) regs->regs[0];
    int who = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, which);
    fnla_put_s32(msg, who);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getpriority", msg);

    fnla_free(msg);

    return ret;
}

// int syscall(SYS_reboot, int magic, int magic2, int op, void *arg);
asmlinkage long custom_reboot(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_reboot];

    int ret = (int) hook.prototype_func(regs);
    int magic = (int) regs->regs[0];
    int magic2 = (int) regs->regs[1];
    unsigned int op = (unsigned int) regs->regs[2];
    void __user *arg = (void __user *) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, magic);
    fnla_put_s32(msg, magic2);
    fnla_put_u32(msg, op);
    fnla_put_u64(msg, (uintptr_t) arg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("reboot", msg);

    fnla_free(msg);

    return ret;
}

// int setregid(gid_t rgid, gid_t egid);
asmlinkage long custom_setregid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setregid];

    int ret = (int) hook.prototype_func(regs);
    int rgid = (int) regs->regs[0];
    int egid = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, rgid);
    fnla_put_s32(msg, egid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setregid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setgid];

    int ret = (int) hook.prototype_func(regs);
    int gid = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, gid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setreuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setreuid];

    int ret = (int) hook.prototype_func(regs);
    int ruid = (int) regs->regs[0];
    int euid = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ruid);
    fnla_put_s32(msg, euid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setreuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setuid];

    int ret = (int) hook.prototype_func(regs);
    int uid = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, uid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setresuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setresuid];

    int ret = (int) hook.prototype_func(regs);
    int ruid = (int) regs->regs[0];
    int euid = (int) regs->regs[1];
    int suid = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ruid);
    fnla_put_s32(msg, euid);
    fnla_put_s32(msg, suid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setresuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getresuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getresuid];

    int ret = (int) hook.prototype_func(regs);
    int __user *ruid = (int __user *) regs->regs[0];
    int __user *euid = (int __user *) regs->regs[1];
    int __user *suid = (int __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }
    int ruid_val = 0;
    int euid_val = 0;
    int suid_val = 0;

    if (ruid) {
        if (copy_from_user(&ruid_val, ruid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    if (euid) {
        if (copy_from_user(&euid_val, euid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    if (suid) {
        if (copy_from_user(&suid_val, suid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) ruid);
    if (ruid) {
        fnla_put_s32(msg, ruid_val);
    } else {
        fnla_put_s32(msg, -1);
    }
    fnla_put_u64(msg, (uintptr_t) euid);
    if (euid) {
        fnla_put_s32(msg, euid_val);
    } else {
        fnla_put_s32(msg, -1);
    }
    fnla_put_u64(msg, (uintptr_t) suid);
    if (suid) {
        fnla_put_s32(msg, suid_val);
    } else {
        fnla_put_s32(msg, -1);
    }

    fnla_put_s32(msg, ret);

    on_sys_call_end("getresuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setresgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setresgid];

    int ret = (int) hook.prototype_func(regs);
    int rgid = (int) regs->regs[0];
    int egid = (int) regs->regs[1];
    int sgid = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, rgid);
    fnla_put_s32(msg, egid);
    fnla_put_s32(msg, sgid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setresgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getresgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getresgid];

    int ret = (int) hook.prototype_func(regs);
    int __user *rgid = (int __user *) regs->regs[0];
    int __user *egid = (int __user *) regs->regs[1];
    int __user *sgid = (int __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    int rgid_val = 0;
    int egid_val = 0;
    int sgid_val = 0;

    if (rgid) {
        if (copy_from_user(&rgid_val, rgid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    if (egid) {
        if (copy_from_user(&egid_val, egid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    if (sgid) {
        if (copy_from_user(&sgid_val, sgid, sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) rgid);
    if (rgid) {
        fnla_put_s32(msg, rgid_val);
    } else {
        fnla_put_s32(msg, -1);
    }
    fnla_put_u64(msg, (uintptr_t) egid);
    if (egid) {
        fnla_put_s32(msg, egid_val);
    } else {
        fnla_put_s32(msg, -1);
    }
    fnla_put_u64(msg, (uintptr_t) sgid);
    if (sgid) {
        fnla_put_s32(msg, sgid_val);
    } else {
        fnla_put_s32(msg, -1);
    }

    fnla_put_s32(msg, ret);

    on_sys_call_end("getresgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setfsuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setfsuid];

    int ret = (int) hook.prototype_func(regs);
    int uid = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, uid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setfsuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setfsgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setfsgid];

    int ret = (int) hook.prototype_func(regs);
    int gid = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, gid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setfsgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_times(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_times];

    clock_t ret = (clock_t) hook.prototype_func(regs);
    struct tms __user *tbuf = (struct tms __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) tbuf);
    fnla_put_s64(msg, ret);

    on_sys_call_end("times", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setpgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setpgid];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    pid_t pgid = (pid_t) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, pgid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setpgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getpgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getpgid];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getpgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getsid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getsid];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getsid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setsid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setsid];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setsid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getgroups(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getgroups];

    int ret = (int) hook.prototype_func(regs);
    int gidsetsize = (int) regs->regs[0];
    gid_t __user *grouplist = (gid_t __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    int *grouplist_val = NULL;
    if (grouplist) {
        grouplist_val = vmalloc(gidsetsize * sizeof(int));
        if (!grouplist_val) {
            pr_err_with_location("Failed to allocate grouplist_val\n");
            fnla_free(msg);
            return ret;
        }

        if (copy_from_user(grouplist_val, grouplist, gidsetsize * sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            vfree(grouplist_val);
            fnla_free(msg);
            return ret;
        }
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, gidsetsize);
    if (grouplist) {
        for (int i = 0; i < gidsetsize; ++i) {
            fnla_put_s32(msg, grouplist_val[i]);
        }
    }
    fnla_put_s32(msg, ret);

    on_sys_call_end("getgroups", msg);

    fnla_free(msg);

    if(grouplist_val) {
        vfree(grouplist_val);
    }
    return ret;
}

asmlinkage long custom_setgroups(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setgroups];

    int ret = (int) hook.prototype_func(regs);
    int gidsetsize = (int) regs->regs[0];
    gid_t __user *grouplist = (gid_t __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    int *grouplist_val = NULL;
    if (grouplist) {
        grouplist_val = vmalloc(gidsetsize * sizeof(int));
        if (!grouplist_val) {
            pr_err_with_location("Failed to allocate grouplist_val\n");
            fnla_free(msg);
            return ret;
        }

        if (copy_from_user(grouplist_val, grouplist, gidsetsize * sizeof(int))) {
            pr_err_with_location("Failed to copy_from_user\n");
            vfree(grouplist_val);
            fnla_free(msg);
            return ret;
        }
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, gidsetsize);
    if (grouplist) {
        for (int i = 0; i < gidsetsize; ++i) {
            fnla_put_s32(msg, grouplist_val[i]);
        }
    }
    fnla_put_s32(msg, ret);

    on_sys_call_end("setgroups", msg);

    fnla_free(msg);

    if(grouplist_val) {
        vfree(grouplist_val);
    }
    return ret;
}

asmlinkage long custom_uname(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_uname];

    int ret = (int) hook.prototype_func(regs);
    struct old_utsname __user *name = (struct old_utsname __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_s32(msg, ret);

    on_sys_call_end("uname", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sethostname(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sethostname];

    int ret = (int) hook.prototype_func(regs);
    char __user *name = (char __user *) regs->regs[0];
    int len = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_s32(msg, len);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sethostname", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setdomainname(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setdomainname];

    int ret = (int) hook.prototype_func(regs);
    char __user *name = (char __user *) regs->regs[0];
    int len = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) name);
    fnla_put_s32(msg, len);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setdomainname", msg);

    fnla_free(msg);

    return ret;
}

#ifdef __ARCH_WANT_SET_GET_RLIMIT
asmlinkage long custom_getrlimit(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getrlimit];

    int ret = (int) hook.prototype_func(regs);
    unsigned int resource = (unsigned int) regs->regs[0];
    struct rlimit __user *rlim = (struct rlimit __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, resource);
    fnla_put_u64(msg, (uintptr_t) rlim);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getrlimit", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_setrlimit(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setrlimit];

    int ret = (int) hook.prototype_func(regs);
    unsigned int resource = (unsigned int) regs->regs[0];
    struct rlimit __user *rlim = (struct rlimit __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, resource);
    fnla_put_u64(msg, (uintptr_t) rlim);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setrlimit", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_getrusage(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getrusage];

    int ret = (int) hook.prototype_func(regs);
    int who = (int) regs->regs[0];
    struct rusage __user *ru = (struct rusage __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, who);
    fnla_put_u64(msg, (uintptr_t) ru);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getrusage", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_umask(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_umask];

    mode_t ret = (mode_t) hook.prototype_func(regs);
    mode_t mask = (mode_t) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, mask);
    fnla_put_s64(msg, ret);

    on_sys_call_end("umask", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_prctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_prctl];

    int ret = (int) hook.prototype_func(regs);
    int option = (int) regs->regs[0];
    unsigned long arg2 = (unsigned long) regs->regs[1];
    unsigned long arg3 = (unsigned long) regs->regs[2];
    unsigned long arg4 = (unsigned long) regs->regs[3];
    unsigned long arg5 = (unsigned long) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, option);
    fnla_put_u64(msg, arg2);
    fnla_put_u64(msg, arg3);
    fnla_put_u64(msg, arg4);
    fnla_put_u64(msg, arg5);
    fnla_put_s32(msg, ret);

    on_sys_call_end("prctl", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getcpu(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getcpu];

    int ret = (int) hook.prototype_func(regs);
    unsigned __user *cpup = (unsigned __user *) regs->regs[0];
    unsigned __user *nodep = (unsigned __user *) regs->regs[1];
    struct getcpu_cache __user *tcache = (struct getcpu_cache __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) cpup);
    fnla_put_u64(msg, (uintptr_t) nodep);
    fnla_put_u64(msg, (uintptr_t) tcache);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getcpu", msg);

    fnla_free(msg);

    return ret;
}

// int gettimeofday(struct timeval *restrict tv,
//                        struct timezone *_Nullable restrict tz);
// int settimeofday(const struct timeval *tv,
//                        const struct timezone *_Nullable tz);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_gettimeofday(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_gettimeofday];

    int ret = (int) hook.prototype_func(regs);
    struct timeval __user *tv = (struct timeval __user *) regs->regs[0];
    struct timezone __user *tz = (struct timezone __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) tv);
    fnla_put_u64(msg, (uintptr_t) tz);
    fnla_put_s32(msg, ret);

    on_sys_call_end("gettimeofday", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_settimeofday(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_settimeofday];

    int ret = (int) hook.prototype_func(regs);
    struct timeval __user *tv = (struct timeval __user *) regs->regs[0];
    struct timezone __user *tz = (struct timezone __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) tv);
    fnla_put_u64(msg, (uintptr_t) tz);
    fnla_put_s32(msg, ret);

    on_sys_call_end("settimeofday", msg);

    fnla_free(msg);

    return ret;
}

//       int adjtimex(struct timex *buf);
//
//       int clock_adjtime(clockid_t clk_id, struct timex *buf);
//
//       int ntp_adjtime(struct timex *buf);
asmlinkage long custom_adjtimex(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_adjtimex];

    int ret = (int) hook.prototype_func(regs);
    struct timex __user *buf = (struct timex __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, ret);

    on_sys_call_end("adjtimex", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_getpid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getpid];

    pid_t ret = (pid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getpid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getppid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getppid];

    pid_t ret = (pid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getppid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getuid];

    uid_t ret = (uid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, ret);

    on_sys_call_end("getuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_geteuid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_geteuid];

    uid_t ret = (uid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, ret);

    on_sys_call_end("geteuid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getgid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getgid];

    gid_t ret = (gid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, ret);

    on_sys_call_end("getgid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getegid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getegid];

    gid_t ret = (gid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s64(msg, ret);

    on_sys_call_end("getegid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_gettid(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_gettid];

    pid_t ret = (pid_t) hook.prototype_func(regs);

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("gettid", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sysinfo(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sysinfo];

    int ret = (int) hook.prototype_func(regs);
    struct sysinfo __user *info = (struct sysinfo __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) info);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sysinfo", msg);

    fnla_free(msg);

    return ret;
}

//mqd_t mq_open(const char *name, int oflag);
//mqd_t mq_open(const char *name, int oflag, mode_t mode,
//                     struct mq_attr *attr);
asmlinkage long custom_mq_open(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_open];

    mqd_t ret = (mqd_t) hook.prototype_func(regs);
    const char __user *name = (const char __user *) regs->regs[0];
    int oflag = (int) regs->regs[1];
    mode_t mode = (mode_t) regs->regs[2];
    struct mq_attr __user *attr = (struct mq_attr __user *) regs->regs[3];

    char* name_buf = NULL;
    if (name) {
        name_buf = vmalloc(PATH_MAX);
        if (!name_buf) {
            pr_err_with_location("Failed to allocate name_buf\n");
            return ret;
        }

        if (copy_from_user(name_buf, name, PATH_MAX)) {
            pr_err_with_location("Failed to copy_from_user\n");
            goto ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) name);
    if (name) {
        fnla_put_u32(msg, strlen(name_buf));
        fnla_put_bytes(msg, name_buf, strlen(name_buf));
    }
    fnla_put_s32(msg, oflag);
    fnla_put_u32(msg, mode);
    fnla_put_u64(msg, (uintptr_t) attr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("mq_open", msg);

    fnla_free(msg);

    ret:
    if (name_buf) {
        vfree(name_buf);
    }
    return ret;
}

asmlinkage long custom_mq_unlink(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_unlink];

    int ret = (int) hook.prototype_func(regs);
    const char __user *name = (const char __user *) regs->regs[0];

    char* name_buf = NULL;
    if (name) {
        name_buf = vmalloc(PATH_MAX);
        if (!name_buf) {
            pr_err_with_location("Failed to allocate name_buf\n");
            return ret;
        }

        if (copy_from_user(name_buf, name, PATH_MAX)) {
            pr_err_with_location("Failed to copy_from_user\n");
            goto ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) name);
    if (name) {
        fnla_put_u32(msg, strlen(name_buf));
        fnla_put_bytes(msg, name_buf, strlen(name_buf));
    }
    fnla_put_s32(msg, ret);

    on_sys_call_end("mq_unlink", msg);

    fnla_free(msg);

    ret:
    if (name_buf) {
        vfree(name_buf);
    }
    return ret;
}

// int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
//           unsigned msg_prio, const struct timespec *abstime);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_mq_timedsend(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_timedsend];

    int ret = (int) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    const char __user *msg_ptr = (const char __user *) regs->regs[1];
    size_t msg_len = (size_t) regs->regs[2];
    unsigned int msg_prio = (unsigned int) regs->regs[3];
    const struct __kernel_timespec __user *abs_timeout = (const struct __kernel_timespec __user *) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, mqdes);
    fnla_put_u64(msg, (uintptr_t) msg_ptr);
    fnla_put_u32(msg, msg_len);
    fnla_put_u32(msg, msg_prio);
    fnla_put_u64(msg, (uintptr_t) abs_timeout);
    fnla_put_s32(msg, ret);

    on_sys_call_end("mq_timedsend", msg);

    fnla_free(msg);

    return ret;
}

//ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr,
//           size_t msg_len, unsigned *restrict msg_prio,
//           const struct timespec *restrict abstime);
asmlinkage long custom_mq_timedreceive(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_timedreceive];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    char __user *msg_ptr = (char __user *) regs->regs[1];
    size_t msg_len = (size_t) regs->regs[2];
    unsigned int __user *msg_prio = (unsigned int __user *) regs->regs[3];
    const struct __kernel_timespec __user *abs_timeout = (const struct __kernel_timespec __user *) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, mqdes);
    fnla_put_u64(msg, (uintptr_t) msg_ptr);
    fnla_put_u32(msg, msg_len);
    fnla_put_u64(msg, (uintptr_t) msg_prio);
    fnla_put_u64(msg, (uintptr_t) abs_timeout);
    fnla_put_s64(msg, ret);

    on_sys_call_end("mq_timedreceive", msg);

    fnla_free(msg);
    return ret;
}
#endif

asmlinkage long custom_mq_notify(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_notify];

    int ret = (int) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    const struct sigevent __user *notification = (const struct sigevent __user *) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, mqdes);
    fnla_put_u64(msg, (uintptr_t) notification);
    fnla_put_s32(msg, ret);

    on_sys_call_end("mq_notify", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_mq_getsetattr(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_getsetattr];

    int ret = (int) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    struct mq_attr __user *mqstat = (struct mq_attr __user *) regs->regs[1];
    struct mq_attr __user *omqstat = (struct mq_attr __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, mqdes);
    fnla_put_u64(msg, (uintptr_t) mqstat);
    fnla_put_u64(msg, (uintptr_t) omqstat);
    fnla_put_s32(msg, ret);

    on_sys_call_end("mq_getsetattr", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_msgget(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_msgget];

    int ret = (int) hook.prototype_func(regs);
    key_t key = (key_t) regs->regs[0];
    int msgflg = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, key);
    fnla_put_s32(msg, msgflg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("msgget", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_msgctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_msgctl];

    int ret = (int) hook.prototype_func(regs);
    int msqid = (int) regs->regs[0];
    int cmd = (int) regs->regs[1];
    struct msqid_ds __user *buf = (struct msqid_ds __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, msqid);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, ret);

    on_sys_call_end("msgctl", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_msgsnd(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_msgsnd];

    int ret = (int) hook.prototype_func(regs);
    int msqid = (int) regs->regs[0];
    const void __user *msgp = (const void __user *) regs->regs[1];
    size_t msgsz = (size_t) regs->regs[2];
    int msgflg = (int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, msqid);
    fnla_put_u64(msg, (uintptr_t) msgp);
    fnla_put_u32(msg, msgsz);
    fnla_put_s32(msg, msgflg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("msgsnd", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_msgrcv(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_msgrcv];

    int ret = (int) hook.prototype_func(regs);
    int msqid = (int) regs->regs[0];
    void __user *msgp = (void __user *) regs->regs[1];
    size_t msgsz = (size_t) regs->regs[2];
    long msgtyp = (long) regs->regs[3];
    int msgflg = (int) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, msqid);
    fnla_put_u64(msg, (uintptr_t) msgp);
    fnla_put_u32(msg, msgsz);
    fnla_put_s64(msg, msgtyp);
    fnla_put_s32(msg, msgflg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("msgrcv", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_semget(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_semget];

    int ret = (int) hook.prototype_func(regs);
    key_t key = (key_t) regs->regs[0];
    int nsems = (int) regs->regs[1];
    int semflg = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, key);
    fnla_put_s32(msg, nsems);
    fnla_put_s32(msg, semflg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("semget", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_semctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_semctl];

    int ret = (int) hook.prototype_func(regs);
    int semid = (int) regs->regs[0];
    int semnum = (int) regs->regs[1];
    int cmd = (int) regs->regs[2];
    unsigned long arg = (unsigned long) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, semid);
    fnla_put_s32(msg, semnum);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, arg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("semctl", msg);

    fnla_free(msg);

    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_semtimedop(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_semtimedop];

    int ret = (int) hook.prototype_func(regs);
    int semid = (int) regs->regs[0];
    struct sembuf __user *sops = (struct sembuf __user *) regs->regs[1];
    unsigned nsops = (unsigned) regs->regs[2];
    const struct __kernel_timespec __user *timeout = (const struct __kernel_timespec __user *) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, semid);
    fnla_put_u64(msg, (uintptr_t) sops);
    fnla_put_u32(msg, nsops);
    fnla_put_u64(msg, (uintptr_t) timeout);
    fnla_put_s32(msg, ret);

    on_sys_call_end("semtimedop", msg);

    fnla_free(msg);

    return ret;
}
#endif

asmlinkage long custom_semop(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_semop];

    int ret = (int) hook.prototype_func(regs);
    int semid = (int) regs->regs[0];
    struct sembuf __user *sops = (struct sembuf __user *) regs->regs[1];
    unsigned nsops = (unsigned) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, semid);
    fnla_put_u64(msg, (uintptr_t) sops);
    fnla_put_u32(msg, nsops);
    fnla_put_s32(msg, ret);

    on_sys_call_end("semop", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_shmget(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_shmget];

    int ret = (int) hook.prototype_func(regs);
    key_t key = (key_t) regs->regs[0];
    size_t size = (size_t) regs->regs[1];
    int shmflg = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, key);
    fnla_put_u32(msg, size);
    fnla_put_s32(msg, shmflg);
    fnla_put_s32(msg, ret);

    on_sys_call_end("shmget", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_shmctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_shmctl];

    int ret = (int) hook.prototype_func(regs);
    int shmid = (int) regs->regs[0];
    int cmd = (int) regs->regs[1];
    struct shmid_ds __user *buf = (struct shmid_ds __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, shmid);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_s32(msg, ret);

    on_sys_call_end("shmctl", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_shmat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_shmat];

    void *ret = (void *) hook.prototype_func(regs);
    int shmid = (int) regs->regs[0];
    char __user *shmaddr = (char __user *) regs->regs[1];
    int shmflg = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, shmid);
    fnla_put_u64(msg, (uintptr_t) shmaddr);
    fnla_put_s32(msg, shmflg);
    fnla_put_u64(msg, (uintptr_t) ret);

    on_sys_call_end("shmat", msg);

    fnla_free(msg);

    return (long) ret;
}

asmlinkage long custom_shmdt(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_shmdt];

    int ret = (int) hook.prototype_func(regs);
    char __user *shmaddr = (char __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) shmaddr);
    fnla_put_s32(msg, ret);

    on_sys_call_end("shmdt", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_socket(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_socket];

    int ret = (int) hook.prototype_func(regs);
    int family = (int) regs->regs[0];
    int type = (int) regs->regs[1];
    int protocol = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, family);
    fnla_put_s32(msg, type);
    fnla_put_s32(msg, protocol);
    fnla_put_s32(msg, ret);

    on_sys_call_end("socket", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_socketpair(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_socketpair];

    int ret = (int) hook.prototype_func(regs);
    int family = (int) regs->regs[0];
    int type = (int) regs->regs[1];
    int protocol = (int) regs->regs[2];
    int __user *usockvec = (int __user *) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, family);
    fnla_put_s32(msg, type);
    fnla_put_s32(msg, protocol);
    fnla_put_u64(msg, (uintptr_t) usockvec);
    fnla_put_s32(msg, ret);

    on_sys_call_end("socketpair", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_bind(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_bind];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int addrlen = (int) regs->regs[2];

    struct sockaddr addr_buf;
    if (addr) {
        if (copy_from_user(&addr_buf, addr, sizeof(struct sockaddr))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) addr);
    if (addr) {
        fnla_put_u32(msg, sizeof(struct sockaddr));
        fnla_put_bytes(msg, (char*) &addr_buf, sizeof(struct sockaddr));
    }
    fnla_put_s32(msg, addrlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("bind", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_listen(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_listen];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    int backlog = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_s32(msg, backlog);
    fnla_put_s32(msg, ret);

    on_sys_call_end("listen", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_accept(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_accept];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int __user *addrlen = (int __user *) regs->regs[2];

    struct sockaddr addr_buf;
    if (addr) {
        if (copy_from_user(&addr_buf, addr, sizeof(struct sockaddr))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) addr);
    if (addr) {
        fnla_put_u32(msg, sizeof(struct sockaddr));
        fnla_put_bytes(msg, (char*) &addr_buf, sizeof(struct sockaddr));
    }
    fnla_put_u64(msg, (uintptr_t) addrlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("accept", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_connect(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_connect];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int addrlen = (int) regs->regs[2];

    struct sockaddr addr_buf;
    if (addr) {
        if (copy_from_user(&addr_buf, addr, sizeof(struct sockaddr))) {
            pr_err_with_location("Failed to copy_from_user\n");
            return ret;
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) addr);
    if (addr) {
        fnla_put_u32(msg, sizeof(struct sockaddr));
        fnla_put_bytes(msg, (char*) &addr_buf, sizeof(struct sockaddr));
    }
    fnla_put_s32(msg, addrlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("connect", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getsockname(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getsockname];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int __user *addrlen = (int __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) addr);
    fnla_put_u64(msg, (uintptr_t) addrlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getsockname", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getpeername(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getpeername];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int __user *addrlen = (int __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) addr);
    fnla_put_u64(msg, (uintptr_t) addrlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getpeername", msg);

    fnla_free(msg);

    return ret;
}

//ssize_t sendto(int socket, const void *message, size_t length,
//           int flags, const struct sockaddr *dest_addr,
//           socklen_t dest_len);
asmlinkage long custom_sendto(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sendto];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    void __user *buff = (void __user *) regs->regs[1];
    size_t len = (size_t) regs->regs[2];
    int flags = (int) regs->regs[3];
    struct sockaddr __user *dest_addr = (struct sockaddr __user *) regs->regs[4];
    int dest_addr_len = (int) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) buff);
    fnla_put_u32(msg, len);
    fnla_put_s32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) dest_addr);
    fnla_put_s32(msg, dest_addr_len);
    fnla_put_s64(msg, ret);

    on_sys_call_end("sendto", msg);

    fnla_free(msg);

    return ret;
}

//ssize_t recvfrom(int socket, void *restrict buffer, size_t length,
//           int flags, struct sockaddr *restrict address,
//           socklen_t *restrict address_len);
asmlinkage long custom_recvfrom(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_recvfrom];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    void __user *buff = (void __user *) regs->regs[1];
    size_t len = (size_t) regs->regs[2];
    unsigned flags = (unsigned) regs->regs[3];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[4];
    int __user *addr_len = (int __user *) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) buff);
    fnla_put_u32(msg, len);
    fnla_put_u32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) addr);
    fnla_put_u64(msg, (uintptr_t) addr_len);
    fnla_put_s64(msg, ret);

    on_sys_call_end("recvfrom", msg);

    fnla_free(msg);

    return ret;
}

//  int setsockopt(int socket, int level, int option_name,
//           const void *option_value, socklen_t option_len);
asmlinkage long custom_setsockopt(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setsockopt];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    int level = (int) regs->regs[1];
    int optname = (int) regs->regs[2];
    void __user *optval = (void __user *) regs->regs[3];
    u32 optlen = (u32) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_s32(msg, level);
    fnla_put_s32(msg, optname);
    fnla_put_u64(msg, (uintptr_t) optval);
    fnla_put_u32(msg, optlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setsockopt", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_getsockopt(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getsockopt];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    int level = (int) regs->regs[1];
    int optname = (int) regs->regs[2];
    char __user *optval = (char __user *) regs->regs[3];
    int __user *optlen = (int __user *) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_s32(msg, level);
    fnla_put_s32(msg, optname);
    fnla_put_u64(msg, (uintptr_t) optval);
    fnla_put_u64(msg, (uintptr_t) optlen);
    fnla_put_s32(msg, ret);

    on_sys_call_end("getsockopt", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_shutdown(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_shutdown];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    int how = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_s32(msg, how);
    fnla_put_s32(msg, ret);

    on_sys_call_end("shutdown", msg);

    fnla_free(msg);

    return ret;
}

// ssize_t sendmsg(int socket, const struct msghdr *message, int flags);
asmlinkage long custom_sendmsg(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sendmsg];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct msghdr __user *msg = (struct msghdr __user *) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, sockfd);
    fnla_put_u64(msg_fnla, (uintptr_t) msg);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("sendmsg", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_recvmsg(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_recvmsg];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct msghdr __user *msg = (struct msghdr __user *) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, sockfd);
    fnla_put_u64(msg_fnla, (uintptr_t) msg);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("recvmsg", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//ssize_t readahead(int fd, off_t offset, size_t count);
asmlinkage long custom_readahead(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_readahead];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    loff_t offset = (loff_t) regs->regs[1];
    size_t count = (size_t) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fd);
    fnla_put_s64(msg_fnla, offset);
    fnla_put_u32(msg_fnla, count);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("readahead", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int brk(void *addr);
//       void *sbrk(intptr_t increment);
asmlinkage long custom_brk(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_brk];

    int ret = (int) hook.prototype_func(regs);
    void *addr = (void *) regs->regs[0];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) addr);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("brk", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int munmap(void addr[.length], size_t length);
asmlinkage long custom_munmap(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_munmap];

    int ret = (int) hook.prototype_func(regs);
    uintptr_t addr = (uintptr_t) regs->regs[0];
    size_t len = (size_t) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, addr);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("munmap", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// void *mremap(void old_address[.old_size], size_t old_size,
//                    size_t new_size, int flags, ... /* void *new_address */);
asmlinkage long custom_mremap(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mremap];

    uintptr_t ret = (uintptr_t) hook.prototype_func(regs);
    uintptr_t old_addr = (uintptr_t) regs->regs[0];
    size_t old_len = (size_t) regs->regs[1];
    size_t new_len = (size_t) regs->regs[2];
    int flags = (int) regs->regs[3];
    uintptr_t new_addr = (uintptr_t) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return (long) ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, old_addr);
    fnla_put_u32(msg_fnla, old_len);
    fnla_put_u32(msg_fnla, new_len);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_u64(msg_fnla, new_addr);
    fnla_put_u64(msg_fnla, ret);

    on_sys_call_end("mremap", msg_fnla);

    fnla_free(msg_fnla);

    return (long) ret;
}

//key_serial_t add_key(const char *type, const char *description,
//                     const void payload[.plen], size_t plen,
//        key_serial_t keyring);
asmlinkage long custom_add_key(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_add_key];

    long ret = (long) hook.prototype_func(regs);
    const char __user *type = (const char __user *) regs->regs[0];
    const char __user *description = (const char __user *) regs->regs[1];
    const void __user *payload = (const void __user *) regs->regs[2];
    size_t plen = (size_t) regs->regs[3];
    u64 keyring = (u64) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) type);
    fnla_put_u64(msg_fnla, (uintptr_t) description);
    fnla_put_u64(msg_fnla, (uintptr_t) payload);
    fnla_put_u32(msg_fnla, plen);
    fnla_put_u64(msg_fnla, keyring);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("add_key", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//key_serial_t request_key(const char *type, const char *description,
//                                const char *_Nullable callout_info,
//                                key_serial_t dest_keyring);
asmlinkage long custom_request_key(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_request_key];

    long ret = hook.prototype_func(regs);
    const char __user *type = (const char __user *) regs->regs[0];
    const char __user *description = (const char __user *) regs->regs[1];
    const char __user *callout_info = (const char __user *) regs->regs[2];
    u64 dest_keyring = (u64) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) type);
    fnla_put_u64(msg_fnla, (uintptr_t) description);
    fnla_put_u64(msg_fnla, (uintptr_t) callout_info);
    fnla_put_u64(msg_fnla, dest_keyring);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("request_key", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//long syscall(SYS_keyctl, int operation, unsigned long arg2,
//                    unsigned long arg3, unsigned long arg4,
//                    unsigned long arg5);
asmlinkage long custom_keyctl(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_keyctl];

    long ret = hook.prototype_func(regs);
    int operation = (int) regs->regs[0];
    unsigned long arg2 = (unsigned long) regs->regs[1];
    unsigned long arg3 = (unsigned long) regs->regs[2];
    unsigned long arg4 = (unsigned long) regs->regs[3];
    unsigned long arg5 = (unsigned long) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, operation);
    fnla_put_u64(msg_fnla, arg2);
    fnla_put_u64(msg_fnla, arg3);
    fnla_put_u64(msg_fnla, arg4);
    fnla_put_u64(msg_fnla, arg5);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("keyctl", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//long syscall(SYS_clone3, struct clone_args *cl_args, size_t size);
// int clone(int (*fn)(void *_Nullable), void *stack, int flags,
//                 void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid,
//                                              void *_Nullable tls,
//                                              pid_t *_Nullable child_tid */ );
asmlinkage long custom_clone(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clone];

    long ret = (long) hook.prototype_func(regs);
    void* fn = (void*) regs->regs[0];
    void* stack = (void*) regs->regs[1];
    //void* child_stack, int flags, void* arg
    int flags = (int) regs->regs[2];
    void* arg = (void*) regs->regs[3];
    //pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid
    pid_t* parent_tid = (pid_t*) regs->regs[4];
    void* tls = (void*) regs->regs[5];
    pid_t* child_tid = (pid_t*) regs->regs[6];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) fn);
    fnla_put_u64(msg_fnla, (uintptr_t) stack);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_u64(msg_fnla, (uintptr_t) arg);
    fnla_put_u64(msg_fnla, (uintptr_t) parent_tid);
    fnla_put_u64(msg_fnla, (uintptr_t) tls);
    fnla_put_u64(msg_fnla, (uintptr_t) child_tid);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("clone", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

static int count(struct user_arg_ptr argv, int max)
{
    int i = 0;

    if (argv.ptr.native != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv, i);

            if (!p)
                break;

            if (IS_ERR(p))
                return -EFAULT;

            if (i >= max)
                return -E2BIG;
            ++i;

            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
            cond_resched();
        }
    }
    return i;
}

static inline bool valid_arg_len(long len)
{
    return len <= MAX_ARG_STRLEN;
}

static int (*my_strnlen_user)(const char __user *str, long len) = NULL;

//int execve(const char *pathname, char *const _Nullable argv[],
//                  char *const _Nullable envp[]);
asmlinkage long custom_execve(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_execve];

    int ret = (int) hook.prototype_func(regs);
    const char __user *filename = (const char __user *) regs->regs[0];
    const char __user *const __user *__argv = (const char __user *const __user *) regs->regs[1];
    const char __user *const __user *__envp = (const char __user *const __user *) regs->regs[2];

    char *path = NULL;
    if (filename) {
        path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path) {
            if (strncpy_from_user(path, filename, PATH_MAX) < 0) {
                pr_err_with_location("Failed to copy_from_user\n");
                kfree(path);
                path = NULL;
            }
        }
    }

    struct user_arg_ptr argv = { .ptr.native = __argv };
    struct user_arg_ptr envp = { .ptr.native = __envp };
    int argc = count(argv, MAX_ARG_STRINGS);
    int envc = count(envp, MAX_ARG_STRINGS);

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) filename);
    fnla_put_u64(msg_fnla, (uintptr_t) __argv);
    fnla_put_u64(msg_fnla, (uintptr_t) __envp);
    fnla_put_s32(msg_fnla, ret);

    if (filename) {
        fnla_put_u32(msg_fnla, strlen(path));
        fnla_put_bytes(msg_fnla, path, strlen(path));
    }

    fnla_put_s32(msg_fnla, argc);
    for (int i = 0; i < argc; ++i) {
        const char __user *str = get_user_arg_ptr(argv, i);
        if (IS_ERR(str)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 0);
            continue;
        }
        if (my_strnlen_user == NULL) {
            my_strnlen_user = (int (*)(const char __user *, long)) my_kallsyms_lookup_name("strnlen_user");
            if(my_strnlen_user == NULL) {
                pr_err_with_location("Failed to find strnlen_user\n");
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 0);
                continue;
            }
        }
        ssize_t len = my_strnlen_user(str, MAX_ARG_STRLEN);
        if (!len || !valid_arg_len(len)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 1);
            continue;
        }

        char* str_buf = vmalloc(len + 1);
        if(!str_buf) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 2);
            continue;
        }
        if (str_buf) {
            if (copy_from_user(str_buf, str, len)) {
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 3);
                continue;
            }
            str_buf[len] = '\0';
        }

        fnla_put_u64(msg_fnla, (uintptr_t) str);
        fnla_put_u32(msg_fnla, len);
        fnla_put_bytes(msg_fnla, str_buf, len);

        vfree(str_buf);
    }
    fnla_put_s32(msg_fnla, envc);
    for (int i = 0; i < envc; ++i) {
        const char __user *str = get_user_arg_ptr(envp, i);
        if (IS_ERR(str)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 0);
            continue;
        }
        if (my_strnlen_user == NULL) {
            my_strnlen_user = (int (*)(const char __user *, long)) my_kallsyms_lookup_name("strnlen_user");
            if(my_strnlen_user == NULL) {
                pr_err_with_location("Failed to find strnlen_user\n");
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 0);
                continue;
            }
        }
        ssize_t len = my_strnlen_user(str, MAX_ARG_STRLEN);
        if (!len || !valid_arg_len(len)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 1);
            continue;
        }

        char* str_buf = vmalloc(len + 1);
        if(!str_buf) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 2);
            continue;
        }
        if (str_buf) {
            if (copy_from_user(str_buf, str, len)) {
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 3);
                continue;
            }
            str_buf[len] = '\0';
        }

        fnla_put_u64(msg_fnla, (uintptr_t) str);
        fnla_put_u32(msg_fnla, len);
        fnla_put_bytes(msg_fnla, str_buf, len);

        vfree(str_buf);
    }

    on_sys_call_end("execve", msg_fnla);

    ret:
    if (msg_fnla)
        fnla_free(msg_fnla);
    if (path) {
        kfree(path);
    }
    return ret;
}

//void *mmap(void addr[.length], size_t length, int prot, int flags,
//                  int fd, off_t offset);
asmlinkage long custom_mmap(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_mmap];

    long ret = (long) hook.prototype_func(regs);
    unsigned long addr = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    int prot = (int) regs->regs[2];
    int flags = (int) regs->regs[3];
    int fd = (int) regs->regs[4];
    loff_t offset = (loff_t) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, addr);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, prot);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, fd);
    fnla_put_s64(msg_fnla, offset);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("mmap", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_fadvise64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR3264_fadvise64];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    loff_t offset = (loff_t) regs->regs[1];
    size_t len = (size_t) regs->regs[2];
    int advice = (int) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fd);
    fnla_put_s64(msg_fnla, offset);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, advice);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("fadvise64", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int swapon(const char *path, int swapflags);
// int swapoff(const char *path);
#ifndef __ARCH_NOMMU
asmlinkage long custom_swapon(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_swapon];

    int ret = (int) hook.prototype_func(regs);
    const char __user *specialfile = (const char __user *) regs->regs[0];
    int swap_flags = (int) regs->regs[1];

    char* path_buf = NULL;
    if (specialfile) {
        path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_buf) {
            if (strncpy_from_user(path_buf, specialfile, PATH_MAX) < 0) {
                pr_err_with_location("Failed to copy_from_user\n");
                kfree(path_buf);
                path_buf = NULL;
            }
        }
    }

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) specialfile);
    fnla_put_s32(msg_fnla, swap_flags);
    fnla_put_s32(msg_fnla, ret);

    if (specialfile) {
        fnla_put_u32(msg_fnla, strlen(path_buf));
        fnla_put_bytes(msg_fnla, path_buf, strlen(path_buf));
    }

    on_sys_call_end("swapon", msg_fnla);

    ret:
    if (msg_fnla)
        fnla_free(msg_fnla);
    if (path_buf) {
        kfree(path_buf);
    }
    return ret;
}

asmlinkage long custom_swapoff(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_swapoff];

    int ret = (int) hook.prototype_func(regs);
    const char __user *specialfile = (const char __user *) regs->regs[0];

    char* path_buf = NULL;
    if (specialfile) {
        path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_buf) {
            if (strncpy_from_user(path_buf, specialfile, PATH_MAX) < 0) {
                pr_err_with_location("Failed to copy_from_user\n");
                kfree(path_buf);
                path_buf = NULL;
            }
        }
    }

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) specialfile);
    fnla_put_s32(msg_fnla, ret);

    if (specialfile) {
        fnla_put_u32(msg_fnla, strlen(path_buf));
        fnla_put_bytes(msg_fnla, path_buf, strlen(path_buf));
    }

    on_sys_call_end("swapoff", msg_fnla);

    ret:
    if (msg_fnla)
        fnla_free(msg_fnla);
    if (path_buf) {
        kfree(path_buf);
    }
    return ret;
}

asmlinkage long custom_mprotect(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mprotect];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    unsigned long prot = (unsigned long) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_u64(msg_fnla, prot);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mprotect", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_msync(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_msync];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("msync", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_mlock(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mlock];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mlock", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_munlock(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_munlock];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("munlock", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_mlockall(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mlockall];

    int ret = (int) hook.prototype_func(regs);
    int flags = (int) regs->regs[0];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mlockall", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_munlockall(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_munlockall];

    int ret = (int) hook.prototype_func(regs);

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("munlockall", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_mincore(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mincore];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    unsigned char __user *vec = (unsigned char __user *) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_u64(msg_fnla, (uintptr_t) vec);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mincore", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_madvise(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_madvise];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    int behavior = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u32(msg_fnla, len);
    fnla_put_s32(msg_fnla, behavior);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("madvise", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_remap_file_pages(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_remap_file_pages];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    unsigned long size = (unsigned long) regs->regs[1];
    unsigned long prot = (unsigned long) regs->regs[2];
    unsigned long pgoff = (unsigned long) regs->regs[3];
    unsigned long flags = (unsigned long) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u64(msg_fnla, size);
    fnla_put_u64(msg_fnla, prot);
    fnla_put_u64(msg_fnla, pgoff);
    fnla_put_u64(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("remap_file_pages", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_mbind(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mbind];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    unsigned long len = (unsigned long) regs->regs[1];
    unsigned long mode = (unsigned long) regs->regs[2];
    unsigned long __user *nmask = (unsigned long __user *) regs->regs[3];
    unsigned long maxnode = (unsigned long) regs->regs[4];
    unsigned flags = (unsigned) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u64(msg_fnla, len);
    fnla_put_u64(msg_fnla, mode);
    fnla_put_u64(msg_fnla, (uintptr_t) nmask);
    fnla_put_u64(msg_fnla, maxnode);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mbind", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_set_mempolicy(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_set_mempolicy];

    int ret = (int) hook.prototype_func(regs);
    int mode = (int) regs->regs[0];
    unsigned long __user *nmask = (unsigned long __user *) regs->regs[1];
    unsigned long maxnode = (unsigned long) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, mode);
    fnla_put_u64(msg_fnla, (uintptr_t) nmask);
    fnla_put_u64(msg_fnla, maxnode);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("set_mempolicy", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_get_mempolicy(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_get_mempolicy];

    int ret = (int) hook.prototype_func(regs);
    int __user *policy = (int __user *) regs->regs[0];
    unsigned long __user *nmask = (unsigned long __user *) regs->regs[1];
    unsigned long maxnode = (unsigned long) regs->regs[2];
    unsigned long addr = (unsigned long) regs->regs[3];
    unsigned long flags = (unsigned long) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) policy);
    fnla_put_u64(msg_fnla, (uintptr_t) nmask);
    fnla_put_u64(msg_fnla, maxnode);
    fnla_put_u64(msg_fnla, addr);
    fnla_put_u64(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("get_mempolicy", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//long migrate_pages(int pid, unsigned long maxnode,
//                          const unsigned long *old_nodes,
//                          const unsigned long *new_nodes);
asmlinkage long custom_migrate_pages(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_migrate_pages];

    long ret = hook.prototype_func(regs);
    int pid = (int) regs->regs[0];
    unsigned long maxnode = (unsigned long) regs->regs[1];
    unsigned long __user *old_nodes = (unsigned long __user *) regs->regs[2];
    unsigned long __user *new_nodes = (unsigned long __user *) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pid);
    fnla_put_u64(msg_fnla, maxnode);
    fnla_put_u64(msg_fnla, (uintptr_t) old_nodes);
    fnla_put_u64(msg_fnla, (uintptr_t) new_nodes);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("migrate_pages", msg_fnla);

    fnla_free(msg_fnla);


    return ret;
}

// long move_pages(int pid, unsigned long count, void *pages[.count],
//                       const int nodes[.count], int status[.count], int flags);
asmlinkage long custom_move_pages(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_move_pages];

    long ret = hook.prototype_func(regs);
    int pid = (int) regs->regs[0];
    unsigned long count = (unsigned long) regs->regs[1];
    void __user * __user *pages = (void __user * __user *) regs->regs[2];
    int __user *nodes = (int __user *) regs->regs[3];
    int __user *status = (int __user *) regs->regs[4];
    int flags = (int) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pid);
    fnla_put_u64(msg_fnla, count);
    fnla_put_u64(msg_fnla, (uintptr_t) pages);
    fnla_put_u64(msg_fnla, (uintptr_t) nodes);
    fnla_put_u64(msg_fnla, (uintptr_t) status);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("move_pages", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}
#endif

//  int syscall(SYS_rt_tgsigqueueinfo, pid_t tgid, pid_t tid,
//                   int sig, siginfo_t *info);
asmlinkage long custom_rt_tgsigqueueinfo(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_tgsigqueueinfo];

    int ret = (int) hook.prototype_func(regs);
    pid_t tgid = (pid_t) regs->regs[0];
    pid_t tid = (pid_t) regs->regs[1];
    int sig = (int) regs->regs[2];
    siginfo_t __user *uinfo = (siginfo_t __user *) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, tgid);
    fnla_put_s32(msg_fnla, tid);
    fnla_put_s32(msg_fnla, sig);
    fnla_put_u64(msg_fnla, (uintptr_t) uinfo);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("rt_tgsigqueueinfo", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int syscall(SYS_perf_event_open, struct perf_event_attr *attr,
//                   pid_t pid, int cpu, int group_fd, unsigned long flags);
asmlinkage long custom_perf_event_open(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_perf_event_open];

    int ret = (int) hook.prototype_func(regs);
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *) regs->regs[0];
    pid_t pid = (pid_t) regs->regs[1];
    int cpu = (int) regs->regs[2];
    int group_fd = (int) regs->regs[3];
    unsigned long flags = (unsigned long) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) attr_uptr);
    fnla_put_s32(msg_fnla, pid);
    fnla_put_s32(msg_fnla, cpu);
    fnla_put_s32(msg_fnla, group_fd);
    fnla_put_u64(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("perf_event_open", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int accept4(int
//sockfd, struct sockaddr *addr,            socklen_t *addrlen, int flags);
asmlinkage long custom_accept4(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_accept4];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct sockaddr __user *addr = (struct sockaddr __user *) regs->regs[1];
    int __user *addrlen = (int __user *) regs->regs[2];
    int flags = (int) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, sockfd);
    fnla_put_u64(msg_fnla, (uintptr_t) addr);
    fnla_put_u64(msg_fnla, (uintptr_t) addrlen);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("accept4", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
//                    int flags, struct timespec *timeout);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_recvmmsg(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_recvmmsg];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct mmsghdr __user *msgvec = (struct mmsghdr __user *) regs->regs[1];
    unsigned vlen = (unsigned) regs->regs[2];
    unsigned flags = (unsigned) regs->regs[3];
    struct timespec __user *timeout = (struct timespec __user *) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, sockfd);
    fnla_put_u64(msg_fnla, (uintptr_t) msgvec);
    fnla_put_u32(msg_fnla, vlen);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u64(msg_fnla, (uintptr_t) timeout);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("recvmmsg", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}
#endif

asmlinkage long custom_arch_specific_syscall(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_arch_specific_syscall];

    long ret = hook.prototype_func(regs);
    unsigned long arg1 = (unsigned long) regs->regs[0];
    unsigned long arg2 = (unsigned long) regs->regs[1];
    unsigned long arg3 = (unsigned long) regs->regs[2];
    unsigned long arg4 = (unsigned long) regs->regs[3];
    unsigned long arg5 = (unsigned long) regs->regs[4];
    unsigned long arg6 = (unsigned long) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, arg1);
    fnla_put_u64(msg_fnla, arg2);
    fnla_put_u64(msg_fnla, arg3);
    fnla_put_u64(msg_fnla, arg4);
    fnla_put_u64(msg_fnla, arg5);
    fnla_put_u64(msg_fnla, arg6);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("arch_specific_syscall", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//pid_t wait4(pid_t pid, int *_Nullable wstatus, int options,
//                   struct rusage *_Nullable rusage);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_wait4(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_wait4];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    int __user *wstatus = (int __user *) regs->regs[1];
    int options = (int) regs->regs[2];
    struct rusage __user *ru = (struct rusage __user *) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pid);
    fnla_put_u64(msg_fnla, (uintptr_t) wstatus);
    fnla_put_s32(msg_fnla, options);
    fnla_put_u64(msg_fnla, (uintptr_t) ru);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("wait4", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}
#endif

//int prlimit(pid_t pid, int resource,
//            const struct rlimit *_Nullable new_limit,
//            struct rlimit *_Nullable old_limit);
asmlinkage long custom_prlimit64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_prlimit64];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    unsigned int resource = (unsigned int) regs->regs[1];
    struct rlimit64 __user *new_rlim = (struct rlimit64 __user *) regs->regs[2];
    struct rlimit64 __user *old_rlim = (struct rlimit64 __user *) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pid);
    fnla_put_u32(msg_fnla, resource);
    fnla_put_u64(msg_fnla, (uintptr_t) new_rlim);
    fnla_put_u64(msg_fnla, (uintptr_t) old_rlim);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("prlimit64", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int fanotify_init(unsigned int flags, unsigned int event_f_flags);
asmlinkage long custom_fanotify_init(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fanotify_init];

    int ret = (int) hook.prototype_func(regs);
    unsigned int flags = (unsigned int) regs->regs[0];
    unsigned int event_f_flags = (unsigned int) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u32(msg_fnla, event_f_flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("fanotify_init", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int fanotify_mark(int fanotify_fd, unsigned int flags,
//                         uint64_t mask, int dirfd,
//                         const char *_Nullable pathname);
asmlinkage long custom_fanotify_mark(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fanotify_mark];

    int ret = (int) hook.prototype_func(regs);
    int fanotify_fd = (int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];
    uint64_t mask = (uint64_t) regs->regs[2];
    int dirfd = (int) regs->regs[3];
    const char __user *pathname = (const char __user *) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fanotify_fd);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u64(msg_fnla, mask);
    fnla_put_s32(msg_fnla, dirfd);
    fnla_put_u64(msg_fnla, (uintptr_t) pathname);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("fanotify_mark", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int name_to_handle_at(int dirfd, const char *pathname,
//                             struct file_handle *handle,
//                             int *mount_id, int flags);
// int open_by_handle_at(int mount_fd, struct file_handle *handle,
//                             int flags);
asmlinkage long custom_name_to_handle_at(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_name_to_handle_at];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *name = (const char __user *) regs->regs[1];
    struct file_handle __user *handle = (struct file_handle __user *) regs->regs[2];
    int __user *mnt_id = (int __user *) regs->regs[3];
    int flags = (int) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, dfd);
    fnla_put_u64(msg_fnla, (uintptr_t) name);
    fnla_put_u64(msg_fnla, (uintptr_t) handle);
    fnla_put_u64(msg_fnla, (uintptr_t) mnt_id);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("name_to_handle_at", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_open_by_handle_at(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_open_by_handle_at];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    struct file_handle __user *handle = (struct file_handle __user *) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, dfd);
    fnla_put_u64(msg_fnla, (uintptr_t) handle);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("open_by_handle_at", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

//int clock_adjtime(clockid_t clk_id, struct timex *buf);
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_clock_adjtime(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_adjtime];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct timex __user *tx = (struct timex __user *) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, which_clock);
    fnla_put_u64(msg_fnla, (uintptr_t) tx);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("clock_adjtime", msg_fnla);

    return ret;
}
#endif

asmlinkage long custom_syncfs(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_syncfs];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, ret);

    on_sys_call_end("syncfs", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_setns(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_setns];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int nstype = (int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_s32(msg, nstype);
    fnla_put_s32(msg, ret);

    on_sys_call_end("setns", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_sendmmsg(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sendmmsg];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct mmsghdr __user *msgvec = (struct mmsghdr __user *) regs->regs[1];
    unsigned vlen = (unsigned) regs->regs[2];
    unsigned flags = (unsigned) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, sockfd);
    fnla_put_u64(msg, (uintptr_t) msgvec);
    fnla_put_u32(msg, vlen);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sendmmsg", msg);

    fnla_free(msg);

    return ret;
}

//ssize_t process_vm_readv(pid_t pid,
//                              const struct iovec *local_iov,
//                              unsigned long liovcnt,
//                              const struct iovec *remote_iov,
//                              unsigned long riovcnt,
//                              unsigned long flags);
//ssize_t process_vm_writev(pid_t pid,
//                              const struct iovec *local_iov,
//                              unsigned long liovcnt,
//                              const struct iovec *remote_iov,
//                              unsigned long riovcnt,
//                              unsigned long flags);
asmlinkage long custom_process_vm_readv(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_process_vm_readv];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    const struct iovec __user *lvec = (const struct iovec __user *) regs->regs[1];
    unsigned long liovcnt = (unsigned long) regs->regs[2];
    const struct iovec __user *rvec = (const struct iovec __user *) regs->regs[3];
    unsigned long riovcnt = (unsigned long) regs->regs[4];
    unsigned long flags = (unsigned long) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) lvec);
    fnla_put_u64(msg, liovcnt);
    fnla_put_u64(msg, (uintptr_t) rvec);
    fnla_put_u64(msg, riovcnt);
    fnla_put_u64(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("process_vm_readv", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_process_vm_writev(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_process_vm_writev];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    const struct iovec __user *lvec = (const struct iovec __user *) regs->regs[1];
    unsigned long liovcnt = (unsigned long) regs->regs[2];
    const struct iovec __user *rvec = (const struct iovec __user *) regs->regs[3];
    unsigned long riovcnt = (unsigned long) regs->regs[4];
    unsigned long flags = (unsigned long) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) lvec);
    fnla_put_u64(msg, liovcnt);
    fnla_put_u64(msg, (uintptr_t) rvec);
    fnla_put_u64(msg, riovcnt);
    fnla_put_u64(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("process_vm_writev", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_kcmp(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_kcmp];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid1 = (pid_t) regs->regs[0];
    pid_t pid2 = (pid_t) regs->regs[1];
    int type = (int) regs->regs[2];
    unsigned long idx1 = (unsigned long) regs->regs[3];
    unsigned long idx2 = (unsigned long) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid1);
    fnla_put_s32(msg, pid2);
    fnla_put_s32(msg, type);
    fnla_put_u64(msg, idx1);
    fnla_put_u64(msg, idx2);
    fnla_put_s32(msg, ret);

    on_sys_call_end("kcmp", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_finit_module(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_finit_module];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const char __user *uargs = (const char __user *) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fd);
    fnla_put_u64(msg, (uintptr_t) uargs);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("finit_module", msg);

    fnla_free(msg);

    return ret;
}

//int syscall(SYS_sched_setattr, pid_t pid, struct sched_attr *attr,
//                   unsigned int flags);
asmlinkage long custom_sched_setattr(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_setattr];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct sched_attr __user *attr = (struct sched_attr __user *) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) attr);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_setattr", msg);

    fnla_free(msg);

    return ret;
}

//int syscall(SYS_sched_getattr, pid_t pid, struct sched_attr *attr,
//                   unsigned int size, unsigned int flags);
asmlinkage long custom_sched_getattr(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_getattr];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct sched_attr __user *attr = (struct sched_attr __user *) regs->regs[1];
    unsigned int size = (unsigned int) regs->regs[2];
    unsigned int flags = (unsigned int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u64(msg, (uintptr_t) attr);
    fnla_put_u32(msg, size);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("sched_getattr", msg);

    fnla_free(msg);

    return ret;
}

// int renameat2(int olddirfd, const char *oldpath,
//                    int newdirfd, const char *newpath, unsigned int flags);
asmlinkage long custom_renameat2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_renameat2];

    int ret = (int) hook.prototype_func(regs);
    int olddfd = (int) regs->regs[0];
    const char __user *oldname = (const char __user *) regs->regs[1];
    int newdfd = (int) regs->regs[2];
    const char __user *newname = (const char __user *) regs->regs[3];
    unsigned int flags = (unsigned int) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    char* oldname_str = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!oldname_str) {
        pr_err_with_location("Failed to allocate memory for oldname\n");
        return ret;
    }

    char* newname_str = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!newname_str) {
        pr_err_with_location("Failed to allocate memory for newname\n");
        kfree(oldname_str);
        return ret;
    }

    if (copy_from_user(oldname_str, oldname, PATH_MAX)
        || copy_from_user(newname_str, newname, PATH_MAX)) {
        pr_err_with_location("Failed to copy oldname from user space\n");
        kfree(oldname_str);
        kfree(newname_str);
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, olddfd);
    fnla_put_u64(msg, (uintptr_t) oldname);
    fnla_put_s32(msg, newdfd);
    fnla_put_u64(msg, (uintptr_t) newname);
    fnla_put_u32(msg, flags);

    fnla_put_s32(msg, ret);

    if (oldname) {
        fnla_put_u32(msg, strlen(oldname_str));
        fnla_put_bytes(msg, oldname_str, strlen(oldname_str));
    }

    if (newname) {
        fnla_put_u32(msg, strlen(newname_str));
        fnla_put_bytes(msg, newname_str, strlen(newname_str));
    }

    on_sys_call_end("renameat2", msg);

    return ret;
}

// int syscall(SYS_seccomp, unsigned int operation, unsigned int flags,
//                   void *args);
asmlinkage long custom_seccomp(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_seccomp];

    int ret = (int) hook.prototype_func(regs);
    unsigned int op = (unsigned int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];
    void __user *uargs = (void __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, op);
    fnla_put_u32(msg, flags);
    fnla_put_u64(msg, (uintptr_t) uargs);
    fnla_put_s32(msg, ret);

    on_sys_call_end("seccomp", msg);

    fnla_free(msg);

    return ret;
}

//ssize_t getrandom(void buf[.buflen], size_t buflen, unsigned int flags);
asmlinkage long custom_getrandom(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_getrandom];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    void __user *buf = (void __user *) regs->regs[0];
    size_t buflen = (size_t) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) buf);
    fnla_put_u64(msg, buflen);
    fnla_put_u32(msg, flags);
    fnla_put_s64(msg, ret);

    on_sys_call_end("getrandom", msg);

    fnla_free(msg);

    return ret;
}

// int memfd_create(const char *name, unsigned int flags);
asmlinkage long custom_memfd_create(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_memfd_create];

    int ret = (int) hook.prototype_func(regs);
    const char __user *uname = (const char __user *) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];

    int len = 0;
    char* name = NULL;

    if (uname) {
        if (my_strnlen_user == NULL) {
            my_strnlen_user = (int (*)(const char __user *, long)) my_kallsyms_lookup_name("strnlen_user");
            if(my_strnlen_user == NULL) {
                pr_err_with_location("Failed to find strnlen_user\n");
                return ret;
            }
        }
        len = my_strnlen_user(uname, PATH_MAX);
        if (len > 0) {
            name = kmalloc(len + 1, GFP_KERNEL);
            if (!name) {
                pr_err_with_location("Failed to allocate memory for name\n");
                return ret;
            }

            if (copy_from_user(name, uname, len)) {
                pr_err_with_location("Failed to copy name from user space\n");
                kfree(name);
                return ret;
            }

            name[len] = '\0';
        }
    }

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        kfree(name);
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) uname);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    if (name) {
        fnla_put_u32(msg, len);
        fnla_put_bytes(msg, name, len);
    }

    on_sys_call_end("memfd_create", msg);

    kfree(name);

    fnla_free(msg);
    return ret;
}

//int bpf(int cmd, union bpf_attr *attr, unsigned int size);
asmlinkage long custom_bpf(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_bpf];

    int ret = (int) hook.prototype_func(regs);
    int cmd = (int) regs->regs[0];
    union bpf_attr __user *attr = (union bpf_attr __user *) regs->regs[1];
    unsigned int size = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, cmd);
    fnla_put_u64(msg, (uintptr_t) attr);
    fnla_put_u32(msg, size);
    fnla_put_s32(msg, ret);

    on_sys_call_end("bpf", msg);

    fnla_free(msg);

    return ret;
}

// int execveat(int dirfd, const char *pathname,
//                    char *const _Nullable argv[],
//                    char *const _Nullable envp[],
//                    int flags);
asmlinkage long custom_execveat(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_execveat];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    const char __user *const __user *__argv = (const char __user *const __user *) regs->regs[2];
    const char __user *const __user *__envp = (const char __user *const __user *) regs->regs[3];
    int flags = (int) regs->regs[4];

    char *path = NULL;
    if (filename) {
        path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path) {
            if (strncpy_from_user(path, filename, PATH_MAX) < 0) {
                pr_err_with_location("Failed to copy_from_user\n");
                kfree(path);
                path = NULL;
            }
        }
    }

    struct user_arg_ptr argv = { .ptr.native = __argv };
    struct user_arg_ptr envp = { .ptr.native = __envp };
    int argc = count(argv, MAX_ARG_STRINGS);
    int envc = count(envp, MAX_ARG_STRINGS);

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        goto ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, dfd);
    fnla_put_u64(msg_fnla, (uintptr_t) filename);
    fnla_put_u64(msg_fnla, (uintptr_t) __argv);
    fnla_put_u64(msg_fnla, (uintptr_t) __envp);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    if (filename) {
        fnla_put_u32(msg_fnla, strlen(path));
        fnla_put_bytes(msg_fnla, path, strlen(path));
    }

    fnla_put_s32(msg_fnla, argc);
    for (int i = 0; i < argc; ++i) {
        const char __user *str = get_user_arg_ptr(argv, i);
        if (IS_ERR(str)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 0);
            continue;
        }
        if (my_strnlen_user == NULL) {
            my_strnlen_user = (int (*)(const char __user *, long)) my_kallsyms_lookup_name("strnlen_user");
            if(my_strnlen_user == NULL) {
                pr_err_with_location("Failed to find strnlen_user\n");
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 0);
                continue;
            }
        }
        ssize_t len = my_strnlen_user(str, MAX_ARG_STRLEN);
        if (!len || !valid_arg_len(len)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 1);
            continue;
        }

        char* str_buf = vmalloc(len + 1);
        if(!str_buf) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 2);
            continue;
        }
        if (str_buf) {
            if (copy_from_user(str_buf, str, len)) {
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 3);
                continue;
            }
            str_buf[len] = '\0';
        }

        fnla_put_u64(msg_fnla, (uintptr_t) str);
        fnla_put_u32(msg_fnla, len);
        fnla_put_bytes(msg_fnla, str_buf, len);

        vfree(str_buf);
    }
    fnla_put_s32(msg_fnla, envc);
    for (int i = 0; i < envc; ++i) {
        const char __user *str = get_user_arg_ptr(envp, i);
        if (IS_ERR(str)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 0);
            continue;
        }
        if (my_strnlen_user == NULL) {
            my_strnlen_user = (int (*)(const char __user *, long)) my_kallsyms_lookup_name("strnlen_user");
            if(my_strnlen_user == NULL) {
                pr_err_with_location("Failed to find strnlen_user\n");
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 0);
                continue;
            }
        }
        ssize_t len = my_strnlen_user(str, MAX_ARG_STRLEN);
        if (!len || !valid_arg_len(len)) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 1);
            continue;
        }

        char* str_buf = vmalloc(len + 1);
        if(!str_buf) {
            fnla_put_u64(msg_fnla, 0);
            fnla_put_u32(msg_fnla, 2);
            continue;
        }
        if (str_buf) {
            if (copy_from_user(str_buf, str, len)) {
                fnla_put_u64(msg_fnla, 0);
                fnla_put_u32(msg_fnla, 3);
                continue;
            }
            str_buf[len] = '\0';
        }

        fnla_put_u64(msg_fnla, (uintptr_t) str);
        fnla_put_u32(msg_fnla, len);
        fnla_put_bytes(msg_fnla, str_buf, len);

        vfree(str_buf);
    }

    on_sys_call_end("execveat", msg_fnla);

    ret:
    if (msg_fnla)
        fnla_free(msg_fnla);
    if (path) {
        kfree(path);
    }
    return ret;
}

asmlinkage long custom_userfaultfd(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_userfaultfd];

    int ret = (int) hook.prototype_func(regs);
    int flags = (int) regs->regs[0];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("userfaultfd", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int syscall(SYS_membarrier, int cmd, unsigned int flags, int cpu_id);
asmlinkage long custom_membarrier(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_membarrier];

    int ret = (int) hook.prototype_func(regs);
    int cmd = (int) regs->regs[0];
    int flags = (int) regs->regs[1];
    int cpu_id = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, cmd);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, cpu_id);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("membarrier", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int mlock2(const void addr[.len], size_t len, unsigned int flags);
asmlinkage long custom_mlock2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mlock2];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    int flags = (int) regs->regs[2];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u64(msg_fnla, len);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("mlock2", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// ssize_t copy_file_range(int fd_in, off_t *_Nullable off_in,
//                               int fd_out, off_t *_Nullable off_out,
//                               size_t len, unsigned int flags);
asmlinkage long custom_copy_file_range(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_copy_file_range];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd_in = (int) regs->regs[0];
    loff_t __user *off_in = (loff_t __user *) regs->regs[1];
    int fd_out = (int) regs->regs[2];
    loff_t __user *off_out = (loff_t __user *) regs->regs[3];
    size_t len = (size_t) regs->regs[4];
    unsigned int flags = (unsigned int) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fd_in);
    fnla_put_u64(msg_fnla, (uintptr_t) off_in);
    fnla_put_s32(msg_fnla, fd_out);
    fnla_put_u64(msg_fnla, (uintptr_t) off_out);
    fnla_put_u64(msg_fnla, len);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("copy_file_range", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
//                       off_t offset, int flags);
//       ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
//                       off_t offset, int flags);
asmlinkage long custom_preadv2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_preadv2];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    int iovcnt = (int) regs->regs[2];
    off_t offset = (off_t) regs->regs[3];
    int flags = (int) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fd);
    fnla_put_u64(msg_fnla, (uintptr_t) iov);
    fnla_put_s32(msg_fnla, iovcnt);
    fnla_put_s64(msg_fnla, offset);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("preadv2", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

asmlinkage long custom_pwritev2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pwritev2];

    ssize_t ret = (ssize_t) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    const struct iovec __user *iov = (const struct iovec __user *) regs->regs[1];
    int iovcnt = (int) regs->regs[2];
    off_t offset = (off_t) regs->regs[3];
    int flags = (int) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, fd);
    fnla_put_u64(msg_fnla, (uintptr_t) iov);
    fnla_put_s32(msg_fnla, iovcnt);
    fnla_put_s64(msg_fnla, offset);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s64(msg_fnla, ret);

    on_sys_call_end("pwritev2", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);
asmlinkage long custom_pkey_mprotect(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pkey_mprotect];

    int ret = (int) hook.prototype_func(regs);
    unsigned long start = (unsigned long) regs->regs[0];
    size_t len = (size_t) regs->regs[1];
    unsigned long prot = (unsigned long) regs->regs[2];
    int pkey = (int) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, start);
    fnla_put_u64(msg_fnla, len);
    fnla_put_u64(msg_fnla, prot);
    fnla_put_s32(msg_fnla, pkey);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("pkey_mprotect", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

// int pkey_alloc(unsigned int flags, unsigned int access_rights);
asmlinkage long custom_pkey_alloc(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pkey_alloc];

    int ret = (int) hook.prototype_func(regs);
    unsigned int flags = (unsigned int) regs->regs[0];
    unsigned int access_rights = (unsigned int) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u32(msg_fnla, access_rights);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("pkey_alloc", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_pkey_free(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pkey_free];

    int ret = (int) hook.prototype_func(regs);
    int pkey = (int) regs->regs[0];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pkey);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("pkey_free", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

//int statx(int dirfd, const char *restrict pathname, int flags,
//                 unsigned int mask, struct statx *restrict statxbuf);
asmlinkage long custom_statx(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_statx];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *path = (const char __user *) regs->regs[1];
    unsigned flags = (unsigned) regs->regs[2];
    unsigned mask = (unsigned) regs->regs[3];
    struct statx __user *buffer = (struct statx __user *) regs->regs[4];

    char* path_str = NULL;
    if (path) {
        path_str = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_str) {
            if (copy_from_user(path_str, path, PATH_MAX) < 0) {
                pr_err_with_location("Failed to copy_from_user\n");
                kfree(path_str);
                return ret;
            }
        }
    }

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        kfree(path_str);
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, dfd);
    fnla_put_u64(msg_fnla, (uintptr_t) path);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u32(msg_fnla, mask);
    fnla_put_u64(msg_fnla, (uintptr_t) buffer);
    fnla_put_s32(msg_fnla, ret);

    if (path) {
        fnla_put_u32(msg_fnla, strlen(path_str));
        fnla_put_bytes(msg_fnla, path_str, strlen(path_str));
    }

    on_sys_call_end("statx", msg_fnla);

    kfree(path_str);

    fnla_free(msg_fnla);
    return ret;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
asmlinkage long custom_io_pgetevents(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_io_pgetevents];

    int ret = (int) hook.prototype_func(regs);
    aio_context_t ctx_id = (aio_context_t) regs->regs[0];
    long min_nr = (long) regs->regs[1];
    long nr = (long) regs->regs[2];
    struct io_event __user *events = (struct io_event __user *) regs->regs[3];
    struct timespec __user *timeout = (struct timespec __user *) regs->regs[4];
    const struct __kernel_timespec __user *timespec = (const struct __kernel_timespec __user *) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, ctx_id);
    fnla_put_s64(msg_fnla, min_nr);
    fnla_put_s64(msg_fnla, nr);
    fnla_put_u64(msg_fnla, (uintptr_t) events);
    fnla_put_u64(msg_fnla, (uintptr_t) timeout);
    fnla_put_u64(msg_fnla, (uintptr_t) timespec);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("io_pgetevents", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}
#endif

asmlinkage long custom_rseq(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rseq];

    int ret = (int) hook.prototype_func(regs);
    void __user *rseq = (void __user *) regs->regs[0];
    unsigned int rseq_len = (unsigned int) regs->regs[1];
    int flags = (int) regs->regs[2];
    int sig = (int) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u64(msg_fnla, (uintptr_t) rseq);
    fnla_put_u32(msg_fnla, rseq_len);
    fnla_put_s32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, sig);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("rseq", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

asmlinkage long custom_kexec_file_load(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_kexec_file_load];

    int ret = (int) hook.prototype_func(regs);
    int kernel_fd = (int) regs->regs[0];
    int initrd_fd = (int) regs->regs[1];
    unsigned long cmdline_len = (unsigned long) regs->regs[2];
    const char __user *cmdline = (const char __user *) regs->regs[3];
    unsigned long flags = (unsigned long) regs->regs[4];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, kernel_fd);
    fnla_put_s32(msg_fnla, initrd_fd);
    fnla_put_u64(msg_fnla, cmdline_len);
    fnla_put_u64(msg_fnla, (uintptr_t) cmdline);
    fnla_put_u64(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("kexec_file_load", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}
/*

#if defined(__SYSCALL_COMPAT) || __BITS_PER_LONG == 32
asmlinkage long custom_clock_gettime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_gettime64];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timespec __user *tp = (struct __kernel_timespec __user *) regs->regs[1];

    //on_sys_call_end("clock_gettime64,%d,%llu,%d,%d", which_clock, (unsigned long long) tp, ret, current->pid,
     //               current_uid());

    return ret;
}

asmlinkage long custom_clock_settime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_settime64];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timespec __user *tp = (struct __kernel_timespec __user *) regs->regs[1];

    //on_sys_call_end("clock_settime64,%d,%llu,%d,%d", which_clock, (unsigned long long) tp, ret, current->pid,
     //               current_uid());

    return ret;
}

asmlinkage long custom_clock_adjtime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_adjtime64];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timex __user *tx = (struct __kernel_timex __user *) regs->regs[1];

    //on_sys_call_end("clock_adjtime64,%d,%llu,%d,%d", which_clock, (unsigned long long) tx, ret, current->pid,
      //              current_uid());

    return ret;
}

asmlinkage long custom_clock_getres_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_getres_time64];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    struct __kernel_timespec __user *tp = (struct __kernel_timespec __user *) regs->regs[1];

    //on_sys_call_end("clock_getres_time64,%d,%llu,%d,%d", which_clock, (unsigned long long) tp, ret, current->pid,
          //          current_uid());

    return ret;
}

asmlinkage long custom_clock_nanosleep_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clock_nanosleep_time64];

    int ret = (int) hook.prototype_func(regs);
    clockid_t which_clock = (clockid_t) regs->regs[0];
    int flags = (int) regs->regs[1];
    struct __kernel_timespec __user *rqtp = (struct __kernel_timespec __user *) regs->regs[2];
    struct __kernel_timespec __user *rmtp = (struct __kernel_timespec __user *) regs->regs[3];

    //on_sys_call_end("clock_nanosleep_time64,%d,%d,%llu,%llu,%d,%d", which_clock, flags, (unsigned long long) rqtp,
       //             (unsigned long long) rmtp, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_timer_gettime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_gettime64];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];
    struct __kernel_itimerspec __user *value = (struct __kernel_itimerspec __user *) regs->regs[1];

    //on_sys_call_end("timer_gettime64,%llu,%llu,%d,%d", timerid, (unsigned long long) value, ret, current->pid,
      //              current_uid());

    return ret;
}

asmlinkage long custom_timer_settime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timer_settime64];

    int ret = (int) hook.prototype_func(regs);
    timer_t timerid = (timer_t) regs->regs[0];
    int flags = (int) regs->regs[1];
    const struct __kernel_itimerspec __user *new_value = (const struct __kernel_itimerspec __user *) regs->regs[2];
    struct __kernel_itimerspec __user *old_value = (struct __kernel_itimerspec __user *) regs->regs[3];

    //on_sys_call_end("timer_settime64,%llu,%d,%llu,%llu,%d,%d", timerid, flags, (unsigned long long) new_value,
    //                (unsigned long long) old_value, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_timerfd_gettime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timerfd_gettime64];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    struct __kernel_itimerspec __user *otmr = (struct __kernel_itimerspec __user *) regs->regs[1];

    //on_sys_call_end("timerfd_gettime64,%d,%llu,%d,%d", fd, (unsigned long long) otmr, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_timerfd_settime64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_timerfd_settime64];

    int ret = (int) hook.prototype_func(regs);
    int fd = (int) regs->regs[0];
    int flags = (int) regs->regs[1];
    const struct __kernel_itimerspec __user *new_value = (const struct __kernel_itimerspec __user *) regs->regs[2];
    struct __kernel_itimerspec __user *old_value = (struct __kernel_itimerspec __user *) regs->regs[3];

    //on_sys_call_end("timerfd_settime64,%d,%d,%llu,%llu,%d,%d", fd, flags, (unsigned long long) new_value,
    //                (unsigned long long) old_value, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_utimensat_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_utimensat_time64];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    struct __kernel_timespec __user *utimes = (struct __kernel_timespec __user *) regs->regs[2];
    int flags = (int) regs->regs[3];

    //on_sys_call_end("utimensat_time64,%d,%llu,%llu,%d,%d,%d", dfd, (unsigned long long) filename,
     //               (unsigned long long) utimes, flags, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_pselect6_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pselect6_time64];

    int ret = (int) hook.prototype_func(regs);
    int n = (int) regs->regs[0];
    fd_set __user *inp = (fd_set __user *) regs->regs[1];
    fd_set __user *outp = (fd_set __user *) regs->regs[2];
    fd_set __user *exp = (fd_set __user *) regs->regs[3];
    struct __kernel_timespec __user *tsp = (struct __kernel_timespec __user *) regs->regs[4];
    void __user *sig = (void __user *) regs->regs[5];

    //on_sys_call_end("pselect6_time64,%d,%llu,%llu,%llu,%llu,%llu,%d,%d", n, (unsigned long long) inp,
       //             (unsigned long long) outp, (unsigned long long) exp, (unsigned long long) tsp,
       //             (unsigned long long) sig, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_ppoll_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_ppoll_time64];

    int ret = (int) hook.prototype_func(regs);
    struct pollfd __user *ufds = (struct pollfd __user *) regs->regs[0];
    unsigned int nfds = (unsigned int) regs->regs[1];
    struct __kernel_timespec __user *tsp = (struct __kernel_timespec __user *) regs->regs[2];
    const sigset_t __user *sigmask = (const sigset_t __user *) regs->regs[3];
    size_t sigsetsize = (size_t) regs->regs[4];

    //on_sys_call_end("ppoll_time64,%llu,%u,%llu,%llu,%llu,%d,%d", (unsigned long long) ufds, nfds,
   //                 (unsigned long long) tsp, (unsigned long long) sigmask, sigsetsize, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_io_pgetevents_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_io_pgetevents_time64];

    int ret = (int) hook.prototype_func(regs);
    aio_context_t ctx_id = (aio_context_t) regs->regs[0];
    long min_nr = (long) regs->regs[1];
    long nr = (long) regs->regs[2];
    struct io_event __user *events = (struct io_event __user *) regs->regs[3];
    struct __kernel_timespec __user *timeout = (struct __kernel_timespec __user *) regs->regs[4;

    //on_sys_call_end("io_pgetevents_time64,%llu,%ld,%ld,%llu,%llu,%d,%d", ctx_id, min_nr, nr, (unsigned long long) events,
     //               (unsigned long long) timeout, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_recvmmsg_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_recvmmsg_time64];

    int ret = (int) hook.prototype_func(regs);
    int sockfd = (int) regs->regs[0];
    struct mmsghdr __user *msgvec = (struct mmsghdr __user *) regs->regs[1];
    unsigned vlen = (unsigned) regs->regs[2];
    unsigned flags = (unsigned) regs->regs[3];
    struct __kernel_timespec __user *timeout = (struct __kernel_timespec __user *) regs->regs[4];

    //on_sys_call_end("recvmmsg_time64,%d,%llu,%u,%u,%llu,%d,%d", sockfd, (unsigned long long) msgvec, vlen, flags,
    //                (unsigned long long) timeout, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_mq_timedsend_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_timedsend_time64];

    int ret = (int) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    const char __user *msg_ptr = (const char __user *) regs->regs[1];
    size_t msg_len = (size_t) regs->regs[2];
    unsigned int msg_prio = (unsigned int) regs->regs[3];
    const struct __kernel_timespec __user *abs_timeout = (const struct __kernel_timespec __user *) regs->regs[4;

    //on_sys_call_end("mq_timedsend_time64,%d,%llu,%llu,%u,%u,%llu,%d,%d", mqdes, (unsigned long long) msg_ptr, msg_len,
     //               msg_prio, (unsigned long long) abs_timeout, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_mq_timedreceive_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mq_timedreceive_time64];

    int ret = (int) hook.prototype_func(regs);
    mqd_t mqdes = (mqd_t) regs->regs[0];
    char __user *msg_ptr = (char __user *) regs->regs[1];
    size_t msg_len = (size_t) regs->regs[2];
    unsigned int __user *msg_prio = (unsigned int __user *) regs->regs[3];
    const struct __kernel_timespec __user *abs_timeout = (const struct __kernel_timespec __user *) regs->regs[4;

    //on_sys_call_end("mq_timedreceive_time64,%d,%llu,%llu,%llu,%llu,%d,%d", mqdes, (unsigned long long) msg_ptr, msg_len,
      //              (unsigned long long) msg_prio, (unsigned long long) abs_timeout, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_semtimedop_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_semtimedop_time64];

    int ret = (int) hook.prototype_func(regs);
    int semid = (int) regs->regs[0];
    struct sembuf __user *sops = (struct sembuf __user *) regs->regs[1];
    unsigned nsops = (unsigned) regs->regs[2];
    const struct __kernel_timespec __user *timeout = (const struct __kernel_timespec __user *) regs->regs[3;

    //on_sys_call_end("semtimedop_time64,%d,%llu,%u,%llu,%d,%d", semid, (unsigned long long) sops, nsops,
     //               (unsigned long long) timeout, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_rt_sigtimedwait_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_rt_sigtimedwait_time64];

    int ret = (int) hook.prototype_func(regs);
    const sigset_t __user *uthese = (const sigset_t __user *) regs->regs[0];
    siginfo_t __user *uinfo = (siginfo_t __user *) regs->regs[1];
    const struct __kernel_timespec __user *uts = (const struct __kernel_timespec __user *) regs->regs[2;
    size_t sigsetsize = (size_t) regs->regs[3];

    //on_sys_call_end("rt_sigtimedwait_time64,%llu,%llu,%llu,%u,%d,%d", (unsigned long long) uthese,
    //                (unsigned long long) uinfo, (unsigned long long) uts, sigsetsize, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_futex_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_futex_time64];

    int ret = (int) hook.prototype_func(regs);
    u32 __user *uaddr = (u32 __user *) regs->regs[0];
    int op = (int) regs->regs[1];
    u32 val = (u32) regs->regs[2];
    const struct __kernel_timespec __user *utime = (const struct __kernel_timespec __user *) regs->regs[3;
    u32 __user *uaddr2 = (u32 __user *) regs->regs[4];
    u32 val3 = (u32) regs->regs[5];

    //on_sys_call_end("futex_time64,%llu,%d,%u,%llu,%llu,%u,%d,%d", (unsigned long long) uaddr, op, val,
    //                (unsigned long long) utime, (unsigned long long) uaddr2, val3, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_sched_rr_get_interval_time64(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_sched_rr_get_interval_time64];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    struct __kernel_timespec __user *interval = (struct __kernel_timespec __user *) regs->regs[1;

    //on_sys_call_end("sched_rr_get_interval_time64,%d,%llu,%d,%d", pid, (unsigned long long) interval, ret, current->pid,
    //                current_uid());

    return ret;
}
#endif*/

asmlinkage long custom_pidfd_send_signal(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pidfd_send_signal];

    int ret = (int) hook.prototype_func(regs);
    int pidfd = (int) regs->regs[0];
    int sig = (int) regs->regs[1];
    siginfo_t __user *info = (siginfo_t __user *) regs->regs[2];
    unsigned int flags = (unsigned int) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_s32(msg_fnla, pidfd);
    fnla_put_s32(msg_fnla, sig);
    fnla_put_u64(msg_fnla, (uintptr_t) info);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("pidfd_send_signal", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

asmlinkage long custom_io_uring_setup(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_io_uring_setup];

    int ret = (int) hook.prototype_func(regs);
    unsigned entries = (unsigned) regs->regs[0];
    struct io_uring_params __user *p = (struct io_uring_params __user *) regs->regs[1];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u32(msg_fnla, entries);
    fnla_put_u64(msg_fnla, (uintptr_t) p);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("io_uring_setup", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

asmlinkage long custom_io_uring_enter(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_io_uring_enter];

    int ret = (int) hook.prototype_func(regs);
    unsigned fd = (unsigned) regs->regs[0];
    unsigned to_submit = (unsigned) regs->regs[1];
    unsigned min_complete = (unsigned) regs->regs[2];
    unsigned flags = (unsigned) regs->regs[3];
    sigset_t __user *sig = (sigset_t __user *) regs->regs[4];
    size_t sigsetsize = (size_t) regs->regs[5];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u32(msg_fnla, fd);
    fnla_put_u32(msg_fnla, to_submit);
    fnla_put_u32(msg_fnla, min_complete);
    fnla_put_u32(msg_fnla, flags);
    fnla_put_u64(msg_fnla, (uintptr_t) sig);
    fnla_put_u32(msg_fnla, sigsetsize);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("io_uring_enter", msg_fnla);

    fnla_free(msg_fnla);
    return ret;
}

asmlinkage long custom_io_uring_register(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_io_uring_register];

    int ret = (int) hook.prototype_func(regs);
    unsigned fd = (unsigned) regs->regs[0];
    unsigned opcode = (unsigned) regs->regs[1];
    void __user *arg = (void __user *) regs->regs[2];
    unsigned nr_args = (unsigned) regs->regs[3];

    fnla_t msg_fnla = fnla_alloc();
    if (!msg_fnla) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg_fnla);
    fnla_put_u32(msg_fnla, fd);
    fnla_put_u32(msg_fnla, opcode);
    fnla_put_u64(msg_fnla, (uintptr_t) arg);
    fnla_put_u32(msg_fnla, nr_args);
    fnla_put_s32(msg_fnla, ret);

    on_sys_call_end("io_uring_register", msg_fnla);

    fnla_free(msg_fnla);

    return ret;
}

asmlinkage long custom_open_tree(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_open_tree];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    unsigned flags = (unsigned) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u64(msg, (uintptr_t) filename);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("open_tree", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_move_mount(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_move_mount];

    int ret = (int) hook.prototype_func(regs);
    int from_dfd = (int) regs->regs[0];
    const char __user *from_pathname = (const char __user *) regs->regs[1];
    int to_dfd = (int) regs->regs[2];
    const char __user *to_pathname = (const char __user *) regs->regs[3];
    unsigned int flags = (unsigned int) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, from_dfd);
    fnla_put_u64(msg, (uintptr_t) from_pathname);
    fnla_put_s32(msg, to_dfd);
    fnla_put_u64(msg, (uintptr_t) to_pathname);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("move_mount", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fsopen(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fsopen];

    int ret = (int) hook.prototype_func(regs);
    const char __user *fs_name = (const char __user *) regs->regs[0];
    unsigned flags = (unsigned) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) fs_name);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fsopen", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_fsconfig(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fsconfig];

    int ret = (int) hook.prototype_func(regs);
    int fs_fd = (int) regs->regs[0];
    unsigned cmd = (unsigned) regs->regs[1];
    const char __user *key = (const char __user *) regs->regs[2];
    const char __user *value = (const char __user *) regs->regs[3];
    unsigned aux = (unsigned) regs->regs[4];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fs_fd);
    fnla_put_u32(msg, cmd);
    fnla_put_u64(msg, (uintptr_t) key);
    fnla_put_u64(msg, (uintptr_t) value);
    fnla_put_u32(msg, aux);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fsconfig", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_fsmount(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fsmount];

    int ret = (int) hook.prototype_func(regs);
    int fs_fd = (int) regs->regs[0];
    unsigned flags = (unsigned) regs->regs[1];
    unsigned ms_flags = (unsigned) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, fs_fd);
    fnla_put_u32(msg, flags);
    fnla_put_u32(msg, ms_flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fsmount", msg);

    fnla_free(msg);

    return ret;
}

asmlinkage long custom_fspick(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_fspick];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *path = (const char __user *) regs->regs[1];
    unsigned flags = (unsigned) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u64(msg, (uintptr_t) path);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("fspick", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_pidfd_open(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pidfd_open];

    int ret = (int) hook.prototype_func(regs);
    pid_t pid = (pid_t) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pid);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("pidfd_open", msg);

    fnla_free(msg);

    return ret;
}

#ifdef __ARCH_WANT_SYS_CLONE3
asmlinkage long custom_clone3(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_clone3];

    int ret = (int) hook.prototype_func(regs);
    struct clone_args __user *uargs = (struct clone_args __user *) regs->regs[0];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u64(msg, (uintptr_t) uargs);
    fnla_put_s32(msg, ret);

    on_sys_call_end("clone3", msg);

    fnla_free(msg);
    return ret;
}
#endif

asmlinkage long custom_close_range(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_close_range];

    int ret = (int) hook.prototype_func(regs);
    unsigned int fd = (unsigned int) regs->regs[0];
    unsigned int max_fd = (unsigned int) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_u32(msg, fd);
    fnla_put_u32(msg, max_fd);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("close_range", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_openat2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_openat2];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    struct open_how __user *how = (struct open_how __user *) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u64(msg, (uintptr_t) filename);
    fnla_put_u64(msg, (uintptr_t) how);
    fnla_put_s32(msg, ret);

    on_sys_call_end("openat2", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_pidfd_getfd(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_pidfd_getfd];

    int ret = (int) hook.prototype_func(regs);
    int pidfd = (int) regs->regs[0];
    int fd = (int) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pidfd);
    fnla_put_s32(msg, fd);
    fnla_put_u32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("pidfd_getfd", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_faccessat2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_faccessat2];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *filename = (const char __user *) regs->regs[1];
    int mode = (int) regs->regs[2];
    int flags = (int) regs->regs[3];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, dfd);
    fnla_put_u64(msg, (uintptr_t) filename);
    fnla_put_s32(msg, mode);
    fnla_put_s32(msg, flags);
    fnla_put_s32(msg, ret);

    on_sys_call_end("faccessat2", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_process_madvise(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_process_madvise];

    int ret = (int) hook.prototype_func(regs);
    int pidfd = (int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];
    unsigned int advice = (unsigned int) regs->regs[2];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, pidfd);
    fnla_put_u32(msg, flags);
    fnla_put_u32(msg, advice);
    fnla_put_s32(msg, ret);

    on_sys_call_end("process_madvise", msg);

    fnla_free(msg);
    return ret;
}

asmlinkage long custom_epoll_pwait2(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_epoll_pwait2];

    int ret = (int) hook.prototype_func(regs);
    int epfd = (int) regs->regs[0];
    struct epoll_event __user *events = (struct epoll_event __user *) regs->regs[1];
    int maxevents = (int) regs->regs[2];
    int timeout = (int) regs->regs[3];
    const sigset_t __user *sigmask = (const sigset_t __user *) regs->regs[4];
    size_t sigsetsize = (size_t) regs->regs[5];

    fnla_t msg = fnla_alloc();
    if (!msg) {
        pr_err_with_location("Failed to allocate fnla\n");
        return ret;
    }

    fnla_put_referer(msg);
    fnla_put_s32(msg, epfd);
    fnla_put_u64(msg, (uintptr_t) events);
    fnla_put_s32(msg, maxevents);
    fnla_put_s32(msg, timeout);
    fnla_put_u64(msg, (uintptr_t) sigmask);
    fnla_put_u32(msg, sigsetsize);
    fnla_put_s32(msg, ret);

    on_sys_call_end("epoll_pwait2", msg);

    fnla_free(msg);
    return ret;
}


/*

asmlinkage long custom_mount_setattr(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_mount_setattr];

    int ret = (int) hook.prototype_func(regs);
    int dfd = (int) regs->regs[0];
    const char __user *path = (const char __user *) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];
    struct mount_attr __user *attr = (struct mount_attr __user *) regs->regs[3];

    //on_sys_call_end("mount_setattr,%d,%llu,%u,%llu,%d,%d", dfd, (unsigned long long) path, flags,
//(unsigned long long) attr, ret, current->pid, current_uid());

    return ret;
}


asmlinkage long custom_quotactl_fd(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_quotactl_fd];

    int ret = (int) hook.prototype_func(regs);
    int cmd = (int) regs->regs[0];
    int fd = (int) regs->regs[1];
    int id = (int) regs->regs[2];
    void __user *addr = (void __user *) regs->regs[3];

    //on_sys_call_end("quotactl_fd,%d,%d,%d,%llu,%d,%d", cmd, fd, id, (unsigned long long) addr, ret, current->pid,
       //             current_uid());

    return ret;
}

asmlinkage long custom_landlock_create_ruleset(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_landlock_create_ruleset];

    int ret = (int) hook.prototype_func(regs);
    const struct landlock_ruleset_attr __user *attr = (const struct landlock_ruleset_attr __user *) regs->regs[0];

    //on_sys_call_end("landlock_create_ruleset,%llu,%d,%d", (unsigned long long) attr, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_landlock_add_rule(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_landlock_add_rule];

    int ret = (int) hook.prototype_func(regs);
    int ruleset_fd = (int) regs->regs[0];
    const struct landlock_rule_info __user *rule_info = (const struct landlock_rule_info __user *) regs->regs[1];
    unsigned int flags = (unsigned int) regs->regs[2];

    //on_sys_call_end("landlock_add_rule,%d,%llu,%u,%d,%d", ruleset_fd, (unsigned long long) rule_info, flags, ret,
      //              current->pid, current_uid());

    return ret;
}

asmlinkage long custom_landlock_restrict_self(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_landlock_restrict_self];

    int ret = (int) hook.prototype_func(regs);
    int ruleset_fd = (int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];

    //on_sys_call_end("landlock_restrict_self,%d,%u,%d,%d", ruleset_fd, flags, ret, current->pid, current_uid());

    return ret;
}

#ifdef __ARCH_WANT_MEMFD_SECRET
asmlinkage long custom_memfd_secret(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_memfd_secret];

    int ret = (int) hook.prototype_func(regs);
    const char __user *name = (const char __user *) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];
    struct memfd_secret __user *secret = (struct memfd_secret __user *) regs->regs[2];
    unsigned int len = (unsigned int) regs->regs[3];

    //on_sys_call_end("memfd_secret,%llu,%u,%llu,%u,%d,%d", (unsigned long long) name, flags,
    //                (unsigned long long) secret, len, ret, current->pid, current_uid());

    return ret;
}
#endif

asmlinkage long custom_process_mrelease(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_process_mrelease];

    int ret = (int) hook.prototype_func(regs);
    int pidfd = (int) regs->regs[0];
    unsigned int flags = (unsigned int) regs->regs[1];

    //on_sys_call_end("process_mrelease,%d,%u,%d,%d", pidfd, flags, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_futex_waitv(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_futex_waitv];

    int ret = (int) hook.prototype_func(regs);
    struct futex_waitv __user *waiters = (struct futex_waitv __user *) regs->regs[0];
    unsigned int nwaiters = (unsigned int) regs->regs[1];
    struct futex_waitv_block __user *blocks = (struct futex_waitv_block __user *) regs->regs[2];
    unsigned int nblocks = (unsigned int) regs->regs[3];
    unsigned int flags = (unsigned int) regs->regs[4];

    //on_sys_call_end("futex_waitv,%llu,%u,%llu,%u,%llu,%u,%u,%d,%d", (unsigned long long) waiters, nwaiters,
      //              (unsigned long long) blocks, nblocks, flags, ret, current->pid, current_uid());

    return ret;
}

asmlinkage long custom_set_mempolicy_home_node(const struct pt_regs *regs) {
    struct sys_call_hook hook = sys_call_hooks[__NR_set_mempolicy_home_node];

    int ret = (int) hook.prototype_func(regs);
    unsigned int home_node = (unsigned int) regs->regs[0];

    //on_sys_call_end("set_mempolicy_home_node,%u,%d,%d", home_node, ret, current->pid, current_uid());

    return ret;
}*/

s32 init_daat(void) {
    if (init_memhack() != 0) {
        printk(KERN_ERR "[daat] init_memhack failed\n");
        return -1;
    }

    if (init_server() != 0) {
        printk(KERN_ERR "[daat] init_server failed\n");
        return -1;
    }

#if defined(TEST)
        MODIFY_SYSCALL(mkdirat)
        return 0;
#endif

    PUT_HOOK(io_setup)
    PUT_HOOK(io_destroy)
    PUT_HOOK(io_submit)
    PUT_HOOK(io_cancel)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(io_getevents)
#endif
    PUT_HOOK(setxattr)
    PUT_HOOK(lsetxattr)
    PUT_HOOK(fsetxattr)
    PUT_HOOK(getxattr)
    PUT_HOOK(lgetxattr)
    PUT_HOOK(fgetxattr)
    PUT_HOOK(listxattr)
    PUT_HOOK(llistxattr)
    PUT_HOOK(flistxattr)
    PUT_HOOK(removexattr)
    PUT_HOOK(lremovexattr)
    PUT_HOOK(fremovexattr)
    PUT_HOOK(getcwd)
    PUT_HOOK(lookup_dcookie)
#if defined(__NR_eventfd)
    PUT_HOOK(eventfd)
#endif
#if defined(__NR_eventfd2)
    PUT_HOOK(eventfd2)
#endif
#if defined(__NR_epoll_create)
    PUT_HOOK(epoll_create)
#endif
    PUT_HOOK(epoll_create1)
    PUT_HOOK(epoll_ctl)
#if defined(__NR_epoll_wait)
    PUT_HOOK(epoll_wait)
#endif
    PUT_HOOK(dup)
#if defined(__NR_dup2)
    PUT_HOOK(dup2)
#endif
    PUT_HOOK(dup3)
    sys_call_hooks[__NR3264_fcntl].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_fcntl];
    sys_call_hooks[__NR3264_fcntl].hook_func = (syscall_fn_t) custom_fnctl;
    PUT_HOOK(inotify_init1)
    PUT_HOOK(inotify_add_watch)
    PUT_HOOK(inotify_rm_watch)
    PUT_HOOK(ioctl)
    PUT_HOOK(ioprio_set)
    PUT_HOOK(ioprio_get)
    PUT_HOOK(flock)
    PUT_HOOK(mknodat)
    PUT_HOOK(mkdirat)
    PUT_HOOK(unlinkat)
    PUT_HOOK(symlinkat)
    PUT_HOOK(linkat)
#ifdef __ARCH_WANT_RENAMEAT
    PUT_HOOK(renameat)
#endif
    PUT_HOOK(umount2)
    PUT_HOOK(mount)
    PUT_HOOK(pivot_root)
    PUT_HOOK(nfsservctl)
    sys_call_hooks[__NR3264_statfs].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_statfs];
    sys_call_hooks[__NR3264_statfs].hook_func = (syscall_fn_t) custom_statfs;
    sys_call_hooks[__NR3264_fstatfs].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_fstatfs];
    sys_call_hooks[__NR3264_fstatfs].hook_func = (syscall_fn_t) custom_fstatfs;
    sys_call_hooks[__NR3264_truncate].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_truncate];
    sys_call_hooks[__NR3264_truncate].hook_func = (syscall_fn_t) custom_truncate;
    sys_call_hooks[__NR3264_ftruncate].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_ftruncate];
    sys_call_hooks[__NR3264_ftruncate].hook_func = (syscall_fn_t) custom_ftruncate;
    PUT_HOOK(fallocate)
    PUT_HOOK(faccessat)
    PUT_HOOK(chdir)
    PUT_HOOK(fchdir)
    PUT_HOOK(chroot)
    PUT_HOOK(fchmod)
    PUT_HOOK(fchmodat)
    PUT_HOOK(fchown)
    PUT_HOOK(fchownat)
    PUT_HOOK(openat)
    PUT_HOOK(close)
    PUT_HOOK(vhangup)
    PUT_HOOK(pipe2)
    PUT_HOOK(quotactl)
    PUT_HOOK(getdents64)
    sys_call_hooks[__NR3264_lseek].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_lseek];
    sys_call_hooks[__NR3264_lseek].hook_func = (syscall_fn_t) custom_lseek;
    PUT_HOOK(read)
    PUT_HOOK(write)
    PUT_HOOK(readv)
    PUT_HOOK(writev)
    PUT_HOOK(pread64)
    PUT_HOOK(pwrite64)
    PUT_HOOK(preadv)
    PUT_HOOK(pwritev)
    sys_call_hooks[__NR3264_sendfile].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_sendfile];
    sys_call_hooks[__NR3264_sendfile].hook_func = (syscall_fn_t) custom_sendfile;
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(pselect6)
    PUT_HOOK(ppoll)
#endif
    PUT_HOOK(signalfd4)
    PUT_HOOK(vmsplice)
    PUT_HOOK(splice)
    PUT_HOOK(tee)
    PUT_HOOK(readlinkat)
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
    sys_call_hooks[__NR3264_fstatat].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_fstatat];
    sys_call_hooks[__NR3264_fstatat].hook_func = (syscall_fn_t) custom_fstatat;
    sys_call_hooks[__NR3264_fstat].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_fstat];
    sys_call_hooks[__NR3264_fstat].hook_func = (syscall_fn_t) custom_fstat;
#endif
    PUT_HOOK(sync)
    PUT_HOOK(fsync)
    PUT_HOOK(fdatasync)
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
    PUT_HOOK(sync_file_range2)
#else
    PUT_HOOK(sync_file_range)
#endif
    PUT_HOOK(timerfd_create)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(timerfd_settime)
    PUT_HOOK(timerfd_gettime)
#endif
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(utimensat)
#endif
    PUT_HOOK(acct)
    PUT_HOOK(capget)
    PUT_HOOK(capset)
    PUT_HOOK(personality)
    PUT_HOOK(exit)
    PUT_HOOK(exit_group)
    PUT_HOOK(waitid)
    PUT_HOOK(set_tid_address)
    PUT_HOOK(unshare)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(futex)
#endif
    PUT_HOOK(set_robust_list)
    PUT_HOOK(get_robust_list)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(nanosleep)
#endif
    PUT_HOOK(getitimer)
    PUT_HOOK(setitimer)
    PUT_HOOK(kexec_load)
    PUT_HOOK(init_module)
    PUT_HOOK(delete_module)
    PUT_HOOK(timer_create)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(timer_gettime)
#endif
    PUT_HOOK(timer_getoverrun)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(timer_settime)
#endif
    PUT_HOOK(timer_delete)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(clock_settime)
    PUT_HOOK(clock_gettime)
    PUT_HOOK(clock_getres)
    PUT_HOOK(clock_nanosleep)
#endif
    PUT_HOOK(syslog)
    PUT_HOOK(ptrace)
    PUT_HOOK(sched_setparam)
    PUT_HOOK(sched_setscheduler)
    PUT_HOOK(sched_getscheduler)
    PUT_HOOK(sched_getparam)
    PUT_HOOK(sched_setaffinity)
    PUT_HOOK(sched_getaffinity)
    PUT_HOOK(sched_yield)
    PUT_HOOK(sched_get_priority_max)
    PUT_HOOK(sched_get_priority_min)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(sched_rr_get_interval)
#endif
    PUT_HOOK(restart_syscall)
    PUT_HOOK(kill)
    PUT_HOOK(tkill)
    PUT_HOOK(tgkill)
    PUT_HOOK(sigaltstack)
    PUT_HOOK(rt_sigsuspend)
    PUT_HOOK(rt_sigaction)
#if defined(__NR_sigprocmask)
    PUT_HOOK(sigprocmask
#endif
    PUT_HOOK(rt_sigprocmask)
    PUT_HOOK(rt_sigpending)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(rt_sigtimedwait)
#endif
    PUT_HOOK(rt_sigqueueinfo)
    PUT_HOOK(rt_sigreturn)
    PUT_HOOK(setpriority)
    PUT_HOOK(getpriority)
    PUT_HOOK(reboot)
    PUT_HOOK(setregid)
    PUT_HOOK(setgid)
    PUT_HOOK(setreuid)
    PUT_HOOK(setuid)
    PUT_HOOK(setresuid)
    PUT_HOOK(getresuid)
    PUT_HOOK(setresgid)
    PUT_HOOK(getresgid)
    PUT_HOOK(setfsuid)
    PUT_HOOK(setfsgid)
    PUT_HOOK(times)
    PUT_HOOK(setpgid)
    PUT_HOOK(getpgid)
    PUT_HOOK(getsid)
    PUT_HOOK(setsid)
    PUT_HOOK(getgroups)
    PUT_HOOK(setgroups)
    PUT_HOOK(uname)
    PUT_HOOK(sethostname)
    PUT_HOOK(setdomainname)
#ifdef __ARCH_WANT_SET_GET_RLIMIT
    PUT_HOOK(getrlimit)
    PUT_HOOK(setrlimit)
#endif
    PUT_HOOK(getrusage)
    PUT_HOOK(umask)
    PUT_HOOK(prctl)
    PUT_HOOK(getcpu)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(gettimeofday)
    PUT_HOOK(settimeofday)
    PUT_HOOK(adjtimex)
#endif
    PUT_HOOK(getpid)
    PUT_HOOK(getppid)
    PUT_HOOK(getuid)
    PUT_HOOK(geteuid)
    PUT_HOOK(getgid)
    PUT_HOOK(getegid)
    PUT_HOOK(gettid)
    PUT_HOOK(sysinfo)
    PUT_HOOK(mq_open)
    PUT_HOOK(mq_unlink)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(mq_timedsend)
    PUT_HOOK(mq_timedreceive)
#endif
    PUT_HOOK(mq_notify)
    PUT_HOOK(mq_getsetattr)
    PUT_HOOK(msgget)
    PUT_HOOK(msgctl)
    PUT_HOOK(msgsnd)
    PUT_HOOK(msgrcv)
    PUT_HOOK(semget)
    PUT_HOOK(semctl)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(semtimedop)
#endif
    PUT_HOOK(semop)
    PUT_HOOK(shmget)
    PUT_HOOK(shmctl)
    PUT_HOOK(shmat)
    PUT_HOOK(shmdt)
    PUT_HOOK(socket)
    PUT_HOOK(socketpair)
    PUT_HOOK(bind)
    PUT_HOOK(listen)
    PUT_HOOK(accept)
    PUT_HOOK(connect)
    PUT_HOOK(getsockname)
    PUT_HOOK(getpeername)
    PUT_HOOK(sendto)
    PUT_HOOK(recvfrom)
    PUT_HOOK(setsockopt)
    PUT_HOOK(getsockopt)
    PUT_HOOK(shutdown)
    PUT_HOOK(sendmsg)
    PUT_HOOK(recvmsg)
    PUT_HOOK(readahead)
    PUT_HOOK(brk)
    PUT_HOOK(munmap)
    PUT_HOOK(mremap)
    PUT_HOOK(add_key)
    PUT_HOOK(request_key)
    PUT_HOOK(keyctl)
    PUT_HOOK(clone)
    PUT_HOOK(execve)
    sys_call_hooks[__NR3264_mmap].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_mmap];
    sys_call_hooks[__NR3264_mmap].hook_func = (syscall_fn_t) custom_mmap;
    sys_call_hooks[__NR3264_fadvise64].prototype_func = (syscall_fn_t) find_syscall_table()[__NR3264_fadvise64];
    sys_call_hooks[__NR3264_fadvise64].hook_func = (syscall_fn_t) custom_fadvise64;
#ifndef __ARCH_NOMMU
    PUT_HOOK(swapoff)
    PUT_HOOK(swapon)
    PUT_HOOK(mprotect)
    PUT_HOOK(msync)
    PUT_HOOK(mlock)
    PUT_HOOK(munlock)
    PUT_HOOK(mlockall)
    PUT_HOOK(munlockall)
    PUT_HOOK(mincore)
    PUT_HOOK(madvise)
    PUT_HOOK(remap_file_pages)
    PUT_HOOK(mbind)
    PUT_HOOK(get_mempolicy)
    PUT_HOOK(set_mempolicy)
    PUT_HOOK(migrate_pages)
    PUT_HOOK(move_pages)
#endif
    PUT_HOOK(rt_tgsigqueueinfo)
    PUT_HOOK(perf_event_open)
    PUT_HOOK(accept4)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(recvmmsg)
#endif
    PUT_HOOK(arch_specific_syscall)
#if  defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(wait4)
#endif
    PUT_HOOK(prlimit64)
    PUT_HOOK(fanotify_init)
    PUT_HOOK(fanotify_mark)
    PUT_HOOK(name_to_handle_at)
    PUT_HOOK(open_by_handle_at)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(clock_adjtime)
#endif
    PUT_HOOK(syncfs)
    PUT_HOOK(setns)
    PUT_HOOK(sendmmsg)
    PUT_HOOK(process_vm_readv)
    PUT_HOOK(process_vm_writev)
    PUT_HOOK(kcmp)
    PUT_HOOK(finit_module)
    PUT_HOOK(sched_setattr)
    PUT_HOOK(sched_getattr)
    PUT_HOOK(renameat2)
    PUT_HOOK(seccomp)
    PUT_HOOK(getrandom)
    PUT_HOOK(memfd_create)
    PUT_HOOK(bpf)
    PUT_HOOK(execveat)
    PUT_HOOK(userfaultfd)
    PUT_HOOK(membarrier)
    PUT_HOOK(mlock2)
    PUT_HOOK(copy_file_range)
    PUT_HOOK(preadv2)
    PUT_HOOK(pwritev2)
    PUT_HOOK(pkey_mprotect)
    PUT_HOOK(pkey_alloc)
    PUT_HOOK(pkey_free)
    PUT_HOOK(statx)
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
    PUT_HOOK(io_pgetevents)
#endif
    PUT_HOOK(rseq)
    PUT_HOOK(kexec_file_load)
/*
#if defined(__SYSCALL_COMPAT) || __BITS_PER_LONG == 32
    PUT_HOOK(clock_gettime64)
    PUT_HOOK(clock_settime64)
    PUT_HOOK(clock_adjtime64)
    PUT_HOOK(clock_getres_time64)
    PUT_HOOK(clock_nanosleep_time64)
    PUT_HOOK(timer_gettime64)
    PUT_HOOK(timer_settime64)
    PUT_HOOK(timerfd_gettime64)
    PUT_HOOK(timerfd_settime64)
    PUT_HOOK(utimensat_time64)
    PUT_HOOK(pselect6_time64)
    PUT_HOOK(ppoll_time64)
    PUT_HOOK(io_pgetevents_time64)
    PUT_HOOK(recvmmsg_time64)
    PUT_HOOK(mq_timedsend_time64)
    PUT_HOOK(mq_timedreceive_time64)
    PUT_HOOK(semtimedop_time64)
    PUT_HOOK(rt_sigtimedwait_time64)
    PUT_HOOK(futex_time64)
    PUT_HOOK(sched_rr_get_interval_time64)
#endif
 */
    PUT_HOOK(pidfd_send_signal)
    PUT_HOOK(io_uring_setup)
    PUT_HOOK(io_uring_enter)
    PUT_HOOK(io_uring_register)
    PUT_HOOK(open_tree)
    PUT_HOOK(move_mount)
    PUT_HOOK(fsopen)
    PUT_HOOK(fsconfig)
    PUT_HOOK(fsmount)
    PUT_HOOK(fspick)
    PUT_HOOK(pidfd_open)
#ifdef __ARCH_WANT_SYS_CLONE3
    PUT_HOOK(clone3)
#endif
    PUT_HOOK(close_range)
    PUT_HOOK(openat2)
    PUT_HOOK(pidfd_getfd)
    PUT_HOOK(faccessat2)
    PUT_HOOK(process_madvise)
    PUT_HOOK(epoll_pwait2)
    /*PUT_HOOK(mount_setattr)
    PUT_HOOK(quotactl_fd)
    PUT_HOOK(landlock_create_ruleset)
    PUT_HOOK(landlock_add_rule)
    PUT_HOOK(landlock_restrict_self)
#ifdef __ARCH_WANT_MEMFD_SECRET
    PUT_HOOK(memfd_secret)
#endif
    PUT_HOOK(process_mrelease)
    PUT_HOOK(futex_waitv)
    PUT_HOOK(set_mempolicy_home_node)*/

    return 0;
}

s32 exit_daat(void) {
    exit_server();

#if defined(TEST)
    RESTORE_SYSCALL(mkdirat)
    return 0;
#endif

    restore_syscall_table();

    return 0;
}

s32 restore_syscall_table(void) {
    for (int nr = 0; nr < __NR_syscalls; ++nr) {
        struct sys_call_hook *hook = sys_call_hooks + nr;
        if (hook->hooked) {
            int ret = unprotect_rodata_memory(BREAK_KERNEL_MODE, nr);
            if (ret != 0) {
                printk(KERN_ERR "[daat] unprotect_rodata_memory failed, nr = %d\n", nr);
                continue;
            }
            find_syscall_table()[nr] = (unsigned long) hook->prototype_func;
            hook->hooked = 0;
            ret = protect_rodata_memory(BREAK_KERNEL_MODE, nr);
            if (ret != 0) {
                printk(KERN_ERR "[daat] protect_rodata_memory failed, nr = %d\n", nr);
            }
        }
    }

    return 0;
}

s32 inject_sys_call(u32 nr) {
    struct sys_call_hook* hook = sys_call_hooks + nr;
    if (hook->hook_func && hook->prototype_func && !hook->hooked) {
        int ret = unprotect_rodata_memory(BREAK_KERNEL_MODE, nr);
        if (ret != 0) {
            printk(KERN_ERR "[daat] unprotect_rodata_memory failed, nr = %d\n", nr);
            return -1;
        }

        find_syscall_table()[nr] = (unsigned long) hook->hook_func;
        hook->hooked = 1;

        ret = protect_rodata_memory(BREAK_KERNEL_MODE, nr);
        if (ret != 0) {
            printk(KERN_ERR "[daat] protect_rodata_memory failed, nr = %d\n", nr);
            return -1;
        }
        return 0;
    }
    return -2;
}
