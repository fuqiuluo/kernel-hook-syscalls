//
// Created by 13723 on 24-12-22.
//

#include <linux/unistd.h>
#include <thread>
#include "TraceLog.h"
#include "../Parser/Parser.h"
#include "../Client.h"

void TraceLog::checkParams() {
    if (pid == "*") {
        pid.clear();
        if (verbose) {
            std::cout << "Trace all process id." << std::endl;
        }
    }

    if (uid == "*") {
        uid.clear();
        if (verbose) {
            std::cout << "Trace all user id." << std::endl;
        }
    }
}

//void char_to_hex2(const char *input, char *output, size_t length) {
//    const char hex_digits[] = "0123456789ABCDEF";
//    for (size_t i = 0; i < length; i++) {
//        unsigned char byte = (unsigned char)input[i];
//        output[i * 2] = hex_digits[byte >> 4];
//        output[i * 2 + 1] = hex_digits[byte & 0x0F];
//    }
//    output[length * 2] = '\0';
//}

void TraceLog::doCommand(const lyra::group &g) {
    if (show_help) {
        std::cout << g;
        return;
    }

    using namespace trs::parser;
    auto SyscallHandler = [&](const trs::client::Packet &packet) {
//        char* hex = (char*) malloc(packet.data.size() * 2 + 1);
//        char_to_hex2((char*) packet.data.data(), hex, packet.data.size());
//        std::cout << "Data: " << hex << std::endl;
//        free(hex);
        auto fnla = fnla_init_with_data((char*) packet.data.data(), packet.data.size());
        auto syscall = parseSyscallEnd(fnla);
        if (!syscall) {
            std::cerr << "Parse syscall failed." << std::endl;
            fnla_free(fnla);
            return;
        }

        if (!pid.empty() && std::to_string(syscall->pid) != pid) {
            fnla_free(fnla);
            return;
        }

        if (!uid.empty() && std::to_string(syscall->uid) != uid) {
            fnla_free(fnla);
            return;
        }

        std::cout << syscall->toLogString() << std::endl;

        fnla_free(fnla);
    };

    checkParams();
    trs::client::Client client;
    if(client.connect() != 0) {
        std::cerr << "Connect to kernel failed." << std::endl;
        return;
    } else {
        std::cout << "Connect to kernel success." << std::endl;
    }

    client.addHandler(NLMSG_SYSCALL_END, SyscallHandler);
    std::thread loop([&]() {
        client.loop();
    });
    std::thread hook([&]() {
        std::vector<uint32_t> syscalls = {
                __NR_setxattr,
                __NR_lsetxattr,
                __NR_fsetxattr,
                __NR_getxattr,
                __NR_lgetxattr,
                __NR_fgetxattr,
                __NR_listxattr,
                __NR_llistxattr,
                __NR_flistxattr,
                __NR_removexattr,
                __NR_lremovexattr,
                __NR_fremovexattr,
                __NR_getcwd,
                __NR_openat,
                __NR_mkdirat,
                __NR_mknodat,
                __NR_fchownat,
                __NR_unlinkat,
                __NR_renameat,
                __NR_renameat2,
                __NR_linkat,
                __NR_symlinkat,
                __NR_readlinkat,
                __NR_fchmodat,
                __NR_faccessat,
                __NR_utimensat,
                __NR_fstat,
                __NR3264_fstatat,
                __NR_fstatfs,
                __NR_statfs,
                __NR_fcntl,
                __NR_ioctl,
                __NR_dup,
                __NR_dup3,
                __NR_close,
                __NR_read,
                __NR_write,
                __NR_pread64,
                __NR_pwrite64,
                __NR_readv,
                __NR_writev,
                __NR_preadv,
                __NR_pwritev,
                __NR_sendfile,
                __NR_mmap,
                __NR_munmap,
                __NR_mprotect,
                __NR_msync,
                __NR_madvise,
                __NR_mlock,
        };

        client.hookSyscall(syscalls);
    });
    hook.join();
    loop.join();
}
