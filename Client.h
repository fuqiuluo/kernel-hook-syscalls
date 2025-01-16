//
// Created by 13723 on 24-12-22.
//

#ifndef TRS_CLIENT_H
#define TRS_CLIENT_H

#include <linux/netlink.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <initializer_list>
#include <vector>
#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <unordered_map>
#include <memory>
#include <iostream>
#include <chrono>
#include <functional>

#define DAAT_KEY "114514"
#define NETLINK_DAAT 31

#define NLMSG_HELLO 0x11
#define NLMSG_SYSCALL_END 0x12
#define NLMSG_CONNECTED 0x13
#define NLMSG_HOOK_SYSCALL 0x14

namespace trs::client {
    struct Packet {
        uint32_t seq{};
        int32_t typ{};
        std::vector<uint8_t> data;
    };

    struct WaitContext {
        uint32_t seq;                                // 等待的 seq
        std::condition_variable cv;                 // 条件变量，用于等待响应
        std::mutex mtx;                             // 锁，用于同步
        bool completed = false;                     // 是否已完成
        Packet response;                       // 收到的返回数据

        explicit WaitContext(uint32_t s) : seq(s) {}
    };

    class Client {
    public:
        ~Client();

        int32_t connect();
        size_t send(int32_t typ, const char *data, size_t len, uint32_t seq);
        Packet sendAndWaitResponse(int32_t typ, const char *data, size_t len, uint32_t seq, int timeout_ms);
        void addHandler(int32_t typ, std::function<void(const Packet&)> handler);
        void loop();

        int32_t hookSyscall(const std::vector<uint32_t>& nr);
    private:
        int32_t sock_fd = 0;
        std::atomic<int32_t> seq_factory = 0;
        struct sockaddr_nl src_addr{}, dst_addr{};

        std::unordered_map<uint32_t, std::shared_ptr<WaitContext>> seq_table_;
        std::unordered_map<uint32_t, std::function<void(const Packet&)>> handlers;
        std::mutex mtx_;

        void addWaiter(uint32_t seq, std::shared_ptr<WaitContext> context);
        std::shared_ptr<WaitContext> getWaiter(uint32_t seq);
        void removeWaiter(uint32_t seq);
        void handleResponse(uint32_t seq, const Packet& response);
        Packet recv();
    };

}

#endif //TRS_CLIENT_H
