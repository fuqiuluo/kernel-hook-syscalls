//
// Created by fuqiuluo on 24-12-20.
//
#include "log.h"
#include <linux/netlink.h>
#include <net/sock.h>

#define DAAT_KEY "114514"
#define NETLINK_DAAT 31
#define NLMSG_GETECHO 0x11
#define NLMSG_SETECHO 0x12

static struct sock *nl_sock = NULL;
static u32 pid = 0;

static void nl_custom_data_ready(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    void *payload;
    struct sk_buff *out_skb;
    void *out_payload;
    struct nlmsghdr *out_nlh;
    int payload_len;
    nlh = nlmsg_hdr(skb);
    switch(nlh->nlmsg_type) {
        case NLMSG_SETECHO:
            break;
        case NLMSG_GETECHO:
            payload = nlmsg_data(nlh);
            payload_len = nlmsg_len(nlh);
            if (strcmp(payload, DAAT_KEY) != 0) {
                printk(KERN_INFO "[daat] Invalid key received!\n");
                return;
            }
            out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
            if (!out_skb) goto failure;
            out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SETECHO, payload_len, 0);
            if (!out_nlh) goto failure;
            out_payload = nlmsg_data(out_nlh);
            strcpy(out_payload, "[daat] your connection is ok!\n");
            nlmsg_unicast(nl_sock, out_skb, nlh->nlmsg_pid);
            pid = nlh->nlmsg_pid;
            break;
        default:
            printk(KERN_INFO "[daat] Unknow msgtype recieved!\n");
    }
    return;
    failure:
    printk(KERN_INFO "[daat] failed in fun dataready!\n");
}

int init_log(void) {
    struct netlink_kernel_cfg cfg = {
            .input = nl_custom_data_ready,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_DAAT, &cfg);
    if (!nl_sock) {
        printk(KERN_ERR "[daat] Failed to create netlink socket\n");
        return -ENOMEM;
    }

    return 0;
}

static void send_to_userspace(const char *msg) {
    if(pid == 0) {
        return;
    }

    struct sk_buff *skb;
    struct nlmsghdr *out_nlh;
    size_t msg_size = strlen(msg);
    int res;

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "[daat] Failed to allocate new skb\n");
        return;
    }
    out_nlh = nlmsg_put(skb, 0, 0, NLMSG_SETECHO, msg_size, 0);
    if (!out_nlh) {
        printk(KERN_ERR "[daat] Failed to put nlmsg\n");
        return;
    }
    void *payload = nlmsg_data(out_nlh);
    strncpy(payload, msg, msg_size);
    res = nlmsg_unicast(nl_sock, skb, pid);

    if (res < 0)
        printk(KERN_ERR "[daat] Failed to send netlink message\n");
}

int trace_log(const char *fmt, ...) {
    char *buffer;
    buffer = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory for log buffer\n");
        return -ENOMEM;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, MAX_LOG_SIZE, fmt, args);
    va_end(args);

    send_to_userspace(buffer);

    kfree(buffer);

    return 0;
}

void release_log(void) {
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
        nl_sock = NULL;
    }
}