//
// Created by fuqiuluo on 24-12-20.
//
#include "server.h"
#include "config.h"
#include "syscalls.h"
#include "hacktask.h"
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/inet.h>

static struct sock *nl_sock = NULL;
static pid_t nl_pid = 0;
static DEFINE_SPINLOCK(wait_table_lock);
static struct hlist_head seq_wait_table[HASH_TABLE_SIZE];

static inline u32 seq_hash(u32 seq) {
    return seq % HASH_TABLE_SIZE;
}

struct seq_waiter *register_waiter(u32 seq) {
    struct seq_waiter *waiter;
    u32 hash_key;

    waiter = kzalloc(sizeof(*waiter), GFP_KERNEL);
    if (!waiter)
        return NULL;

    init_completion(&waiter->complete);
    waiter->seq = seq;
    waiter->response_data = NULL;

    hash_key = seq_hash(seq);

    spin_lock(&wait_table_lock);
    hlist_add_head(&waiter->node, &seq_wait_table[hash_key]);
    spin_unlock(&wait_table_lock);

    return waiter;
}

s32 wait_for_response(struct seq_waiter *waiter, u64 timeout) {
    unsigned long ret;

    ret = wait_for_completion_timeout(&waiter->complete, timeout);
    if (!ret) {
        return -ETIMEDOUT;
    }

    return 0;
}

static s32 handle_incoming_response(u32 seq, void *response_data) {
    bool ready;
    struct seq_waiter *waiter;
    u32 hash_key;

    ready = false;
    hash_key = seq_hash(seq);

    spin_lock(&wait_table_lock);
    hlist_for_each_entry(waiter, &seq_wait_table[hash_key], node) {
        if (waiter->seq == seq) {
            waiter->response_data = response_data;
            complete(&waiter->complete);
            hlist_del(&waiter->node);
            kfree(waiter);
            ready = true;
            break;
        }
    }
    spin_unlock(&wait_table_lock);

    return ready;
}

void unregister_waiter(struct seq_waiter *waiter) {
    spin_lock(&wait_table_lock);
    hlist_del(&waiter->node);
    spin_unlock(&wait_table_lock);

    kfree(waiter);
}

static s32 send_to_userspace(s32 typ, const char *msg, size_t size, u32 seq) {
    if(nl_pid == 0 || nl_sock == NULL) {
        return -1;
    }

    size_t payload_size = size;
    struct sk_buff *skb = nlmsg_new(payload_size, GFP_KERNEL); // allocate new skb
    if (!skb) {
        printk(KERN_ERR "[daat] Failed to allocate new skb\n");
        return -2;
    }
    struct nlmsghdr *out_nlh = nlmsg_put(skb, 0, seq, typ, (s32) payload_size, 0);
    if (!out_nlh) {
        nlmsg_free(skb); // free the skb
        printk(KERN_ERR "[daat] Failed to put nlmsg\n");
        return -3;
    }
    char *payload = nlmsg_data(out_nlh);
    memcpy(payload, msg, size);
    s32 res = nlmsg_unicast(nl_sock, skb, nl_pid);

    if(res == 0) {
        return 0;
    } else if (res == -ESRCH || res == -111) {
        printk(KERN_ERR "[daat] Target process (pid=%d) is not reachable\n", nl_pid);
        nl_pid = 0;
        return -5;
    } else if (res == -ENOMEM) {
        printk(KERN_ERR "[daat] Netlink buffer is full, message not sent\n");
        return -4;
    } else {
        printk(KERN_ERR "[daat] Unknown error (code=%d) while sending Netlink message\n", res);
        return -4;
    }
}

void handle_hello(struct nlmsghdr *nlh, char* payload, s32 payload_len) {
    fnla_t data = fnla_init_with_data(payload, payload_len);
    u32 key_len = 0;
    if(fnla_get_u32(data, &key_len) == NULL) {
        printk(KERN_ERR "[daat] Invalid key length received!\n");
        return;
    }
    char* key = kzalloc(key_len, GFP_KERNEL);
    if(fnla_get_bytes(data, key, key_len) == NULL) {
        printk(KERN_ERR "[daat] Invalid key received!\n");
        kfree(key);
        return;
    }
    u32 auth_status = 0;
    if (key_len != strlen(DAAT_KEY) || strncmp(key, DAAT_KEY, key_len) != 0) {
        printk(KERN_ERR "[daat] Wrong key received!\n");
    } else {
        restore_syscall_table();
        nl_pid = (pid_t) nlh->nlmsg_pid;
        printk(KERN_INFO "[daat] Authenticated! Key = %s\n", key);
        auth_status = 1;
    }
    kfree(key);
    fnla_free(data);

    fnla_t msg = fnla_alloc();
    fnla_put_u32(msg, auth_status);
    if(auth_status == 1) {
        fnla_put_string(msg, DAAT_VERSION);
    } else {
        fnla_put_string(msg, "Fuck");
    }
    send_to_userspace(NLMSG_CONNECTED, NLA_DATA(msg), NLA_SIZE(msg), nlh->nlmsg_seq);
    fnla_free(msg);
}

void handle_hook_syscall(struct nlmsghdr *nlh, char* payload, s32 payload_len) {
    fnla_t data = fnla_init_with_data(payload, payload_len);
    u32 i;
    u32 nr_list_len = 0;
    if(fnla_get_u32(data, &nr_list_len) == NULL) {
        fnla_free(data);
        printk(KERN_ERR "[daat] Invalid nr_list_len received!\n");
        return;
    }
    u32 *nr_list = kzalloc(nr_list_len * sizeof(u32), GFP_KERNEL);
    for (i = 0; i < nr_list_len; i++) {
        if(fnla_get_u32(data, &nr_list[i]) == NULL) {
            printk(KERN_ERR "[daat] Invalid nr_list received!\n");
            fnla_free(data);
            kfree(nr_list);
            return;
        }
    }
    fnla_free(data);

    fnla_t msg = fnla_alloc();
    for (i = 0; i < nr_list_len; i++) {
        if(inject_sys_call(nr_list[i]) != 0) {
            fnla_put_u32(msg, nr_list[i]);
        } else {
            printk(KERN_INFO "[daat] Hooked syscall %d\n", nr_list[i]);
            fnla_put_u32(msg, 0);
        }
    }
    kfree(nr_list);
    send_to_userspace(NLMSG_HOOK_SYSCALL, NLA_DATA(msg), NLA_SIZE(msg), nlh->nlmsg_seq);
    fnla_free(msg);
}

static void nl_custom_data_ready(struct sk_buff *skb) {
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    char *payload = nlmsg_data(nlh);
    s32 payload_len = nlmsg_len(nlh);

    if (nlh->nlmsg_pid == nl_pid - 1) {
        handle_incoming_response(nlh->nlmsg_seq, payload);
    }

    if (DEBUG) {
        char* hex = kmalloc(payload_len * 2 + 1, GFP_KERNEL);
        for (s32 i = 0; i < payload_len; i++) {
            sprintf(hex + i * 2, "%02x", payload[i]);
        }
        printk(KERN_INFO "[daat] Received netlink message, type: %d, pid: %d, seq: %d, payload: %s\n",
               nlh->nlmsg_type, nlh->nlmsg_pid, nlh->nlmsg_seq, hex);
        kfree(hex);
    }

    switch(nlh->nlmsg_type) {
        case NLMSG_SYSCALL_END:
        case NLMSG_CONNECTED:
            break;
        case NLMSG_HELLO: {
            handle_hello(nlh, payload, payload_len);
            break;
        }
        case NLMSG_HOOK_SYSCALL: {
            handle_hook_syscall(nlh, payload, payload_len);
            break;
        }
        default:
            printk(KERN_ERR "[daat] Unknow msgtype recieved!\n");
    }
}

s32 init_server(void) {
    struct netlink_kernel_cfg cfg = {
            .input = nl_custom_data_ready,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_DAAT, &cfg);
    if (!nl_sock) {
        printk(KERN_ERR "[daat] Failed to create netlink socket\n");
        return -ENOMEM;
    }
//    nl_sock->sk_sndbuf = 1024 * 512;
//    nl_sock->sk_rcvbuf = 1024 * 512;

    printk(KERN_INFO "[daat] sndbuf: %d, rcvbuf: %d\n", nl_sock->sk_sndbuf, nl_sock->sk_rcvbuf);

    return 0;
}

s32 on_sys_call_end(const char *syscall_name, fnla_t data) {
    fnla_t new_data = fnla_alloc();
    fnla_put_u32(new_data, NLA_SIZE(data) + strlen(syscall_name) + 4 + 4);
    fnla_put_u32(new_data, strlen(syscall_name));
    fnla_put_string(new_data, syscall_name);
    fnla_put_u32(new_data, NLA_SIZE(data));
    fnla_put_nla(new_data, data);
    s32 ret = send_to_userspace(NLMSG_SYSCALL_END, NLA_DATA(new_data), NLA_SIZE(new_data), 0);
    fnla_free(new_data);
    return ret;
}

void exit_server(void) {
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
        nl_sock = NULL;
    }
}