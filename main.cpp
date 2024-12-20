#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <sys/socket.h>
#include <strings.h>

#define NETLINK_DAAT 31
#define MAX_PAYLOAD 512

static struct nlmsghdr *nlh = nullptr;
static int sock_fd;
static FILE *log_file;

#define DAAT_KEY "114514"
#define NLMSG_GETECHO 0x11
#define NLMSG_SETECHO 0x12

int main(int argn, char* argv[]) {
    struct sockaddr_nl src_addr{}, dst_addr{};
    struct iovec iov{};
    struct msghdr msg{};

    sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_DAAT);
    bzero(&src_addr, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    int ret = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (ret < 0) {
        perror("bind");
        return -1;
    }
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0; // 表示内核
    dst_addr.nl_groups = 0; //未指定接收多播组
    nlh = static_cast<nlmsghdr *>(malloc(NLMSG_SPACE(MAX_PAYLOAD)));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD); //保证对齐
    nlh->nlmsg_pid = getpid();  /* self pid */
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = NLMSG_GETECHO;
    strcpy((char*) NLMSG_DATA(nlh), DAAT_KEY);
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0);
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));


    log_file = fopen("daat.log", "a");

    std::atexit([]() {
        if (nlh)
            free(nlh);
        if (sock_fd > 0)
            close(sock_fd);
        if (log_file)
            fclose(log_file);
    });

    while (true) {
        auto size = recvmsg(sock_fd, &msg, 0);
        printf("Received log size: %zd\n", size);
        if (log_file) {
            fprintf(log_file, "%s\n", (char *)NLMSG_DATA(nlh));
            fflush(log_file);
        }
    }
    return 0;
}