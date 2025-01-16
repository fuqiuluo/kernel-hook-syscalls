//
// Created by fuqiuluo on 24-12-20.
//

#ifndef DAAT_SERVER_H
#define DAAT_SERVER_H

#include <linux/completion.h>
#include "fnla.h"

#define DAAT_KEY "114514"
#define NETLINK_DAAT 31

#define NLMSG_HELLO 0x11
#define NLMSG_SYSCALL_END 0x12
#define NLMSG_CONNECTED 0x13
#define NLMSG_HOOK_SYSCALL 0x14

#define MAX_MSG_SIZE (1024)
#define HASH_TABLE_SIZE 1024

struct seq_waiter {
    u32 seq;                       // 要等待的 seq
    struct completion complete;    // 等待的同步机制
    void *response_data;           // 收到的返回数据
    struct hlist_node node;        // 哈希表中的节点
};

extern s32 init_server(void);

extern struct seq_waiter *register_waiter(u32 seq);

extern s32 wait_for_response(struct seq_waiter *waiter, u64 timeout);

extern void unregister_waiter(struct seq_waiter *waiter);

extern s32 on_sys_call_end(const char *syscall_name, fnla_t data);

extern void exit_server(void);

#endif //DAAT_SERVER_H
