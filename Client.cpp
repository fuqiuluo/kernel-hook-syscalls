//
// Created by 13723 on 24-12-22.
//

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
#include <iostream>
#include "Client.h"
#include "fnla.h"

using namespace trs::client;

void char_to_hex(const char *input, char *output, size_t length) {
    const char hex_digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        output[i * 2] = hex_digits[byte >> 4];
        output[i * 2 + 1] = hex_digits[byte & 0x0F];
    }
    output[length * 2] = '\0';
}

int Client::connect() {
    sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_DAAT);

//    int bufsize = 1024 * 512;
//    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
//        perror("setsockopt SO_SNDBUF failed");
//        close(sock_fd);
//        return -1;
//    }
//
//    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
//        perror("setsockopt SO_RCVBUF failed");
//        close(sock_fd);
//        return -1;
//    }

    bzero(&src_addr, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    int ret = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (ret < 0) {
        perror("bind error");
        return -1;
    }

    auto* fnla = fnla_init();
    fnla_put_u32(fnla, strlen(DAAT_KEY));
    fnla_put_string(fnla, DAAT_KEY);
    send(NLMSG_HELLO, NLA_DATA(fnla), NLA_SIZE(fnla), seq_factory.fetch_add(1));
    fnla_free(fnla);

    Packet packet;
    while (true) {
        packet = recv();

        if (packet.typ == NLMSG_CONNECTED) {
            break;
        } else {
            char* hex = (char*) malloc(packet.data.size() * 2 + 1);
            char_to_hex((char*) packet.data.data(), hex, packet.data.size());
            std::cerr << "Invalid response, seq = " << packet.seq << ", typ = " << packet.typ << ", data = " << hex << std::endl;
            free(hex);
        }
    }

    char reason[256];
    size_t len;
    uint32_t authStatus = 0;

    fnla = fnla_init_with_data((char*) packet.data.data(), packet.data.size());
    fnla_get_u32(fnla, &authStatus);
    fnla_get_string(fnla, reason, &len);
    fnla_free(fnla);

    if (authStatus == 1) {
        return 0;
    } else {
        std::cerr << "Connect failed: " << reason << std::endl;
    }

    return -2;
}

size_t Client::send(int32_t typ, const char *data, size_t len, uint32_t seq) {
    struct iovec iov{};
    struct msghdr msg{};

    size_t payload_len = len + 1;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;
    auto *nlh = static_cast<nlmsghdr *>(malloc(NLMSG_SPACE(payload_len)));
    nlh->nlmsg_len = NLMSG_SPACE(payload_len); // 算上msg和hdr的总长度
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = typ;
    nlh->nlmsg_seq = seq;
    memcpy((char*) NLMSG_DATA(nlh), data, len);
    ((char*) NLMSG_DATA(nlh))[len] = '\0';
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    auto rt = sendmsg(sock_fd, &msg, 0);

    free(nlh);
    return rt;
}

Packet Client::recv() {
    struct nlmsghdr *nlh;
    struct iovec iov{};
    struct msghdr msg{};
    size_t payload_len = NLMSG_SPACE(128 * 1024);
    nlh = static_cast<nlmsghdr *>(malloc(payload_len));
    memset(nlh, 0, payload_len);
    iov.iov_base = (void *)nlh;
    iov.iov_len = payload_len;
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    auto size = recvmsg(sock_fd, &msg, 0);
    if (size > 0) {
        std::vector<uint8_t> s;
        auto* data = (char*) NLMSG_DATA(nlh);
        for (int i = 0; i < nlh->nlmsg_len - sizeof(nlmsghdr); ++i) {
            s.push_back(data[i]);
        }
        Packet ret = {nlh->nlmsg_seq, nlh->nlmsg_type, s};
        free(nlh);
        return ret;
    }
    free(nlh);
    return {UINT32_MAX, -1, {}};
}

int32_t Client::hookSyscall(const std::vector<uint32_t>& nr) {
    if (empty(nr)) return 0;
    auto fnla = fnla_init();
    fnla_put_u32(fnla, nr.size());
    for (auto n : nr) {
        fnla_put_u32(fnla, n);
    }

    auto rsp = sendAndWaitResponse(NLMSG_HOOK_SYSCALL, NLA_DATA(fnla), NLA_SIZE(fnla), seq_factory.fetch_add(1), 3000);
    fnla_free(fnla);

    int status = 0, ret = 0;
    fnla = fnla_init_with_data((char*) rsp.data.data(), rsp.data.size());
    for (int i = 0; i < nr.size(); ++i) {
        fnla_get_s32(fnla, &status);
        if (status != 0) {
            ret = -1;
            std::cerr << "Hook syscall " << nr[i] << " failed" << std::endl;
        } else {
            std::cout << "Hook syscall " << nr[i] << " success" << std::endl;
        }
    }

    return ret;
}

void Client::addWaiter(uint32_t seq, std::shared_ptr<WaitContext> context) {
    std::lock_guard<std::mutex> lock(mtx_);
    seq_table_[seq] = std::move(context);
}

std::shared_ptr<WaitContext> Client::getWaiter(uint32_t seq) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = seq_table_.find(seq);
    if (it != seq_table_.end()) {
        return it->second;
    }
    return nullptr;
}

void Client::removeWaiter(uint32_t seq) {
    std::lock_guard<std::mutex> lock(mtx_);
    seq_table_.erase(seq);
}

void Client::handleResponse(uint32_t seq, const Packet &response) {
    bool handled = false;
    if (handlers.contains(response.typ)) {
        handlers[response.typ](response);
        handled = true;
    }

    auto context = getWaiter(seq);
    if (context) {
        {
            std::lock_guard<std::mutex> lock(context->mtx);
            context->response = response;
            context->completed = true;
        }
        context->cv.notify_one();  // 唤醒等待者
    } else if (!handled) {
        std::cerr << "No waiter found for seq: " << seq << std::endl;
    }
}

Packet Client::sendAndWaitResponse(int32_t typ, const char *data, size_t len, uint32_t seq, int timeout_ms) {
    auto context = std::make_shared<WaitContext>(seq);

    addWaiter(seq, context);

    send(typ, data, len, seq);

    {
        std::unique_lock<std::mutex> lock(context->mtx);
        if (!context->cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() { return context->completed; })) {
            // 超时
            removeWaiter(seq);
            throw std::runtime_error("Timeout waiting for response");
        }
    }

    removeWaiter(seq);
    return context->response;
}

void Client::loop() {
    auto receiver = [&]() {
        while (true) {
            auto packet = recv();
            handleResponse(packet.seq, packet);
        }
    };
    std::thread t(receiver);
    t.join();
}

Client::~Client() {
    close(sock_fd);
}

void Client::addHandler(int32_t typ, std::function<void(const Packet &)> handler) {
    handlers[typ] = std::move(handler);
}
