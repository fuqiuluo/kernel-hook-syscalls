//
// Created by 13723 on 24-12-24.
//

#ifndef TRS_SYSCALLS_H
#define TRS_SYSCALLS_H

#include <string>
#include <memory>
#include <format>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace trs::parser {
    std::string errnoToString(int eno);

    void char_to_hex(const char *input, char *output, size_t length);

    class Syscall {
    public:
        uint32_t pid;
        uint32_t uid;
        std::string syscallName;
        bool finished;
        int64_t ret;

        virtual ~Syscall() = default;

        virtual std::string toLogString() {
            return syscallName + "() -> " + std::to_string(ret) + " [pid = " + std::to_string(pid) + ", uid = " + std::to_string(uid) + "]";
        }
    };

    class IoSetup : public Syscall {
    public:
        uint32_t nr_events;
        uint64_t ctxp;

        std::string toLogString() override {
            std::stringstream ss;

            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";

            ss << syscallName << "(";
            ss << "nr_events = " << nr_events << ", ";
            ss << "ctxp = " << std::format("0x{:x}", ctxp);
            ss << ") -> ";

            ss << ret;

            return ss.str();
        }
    };

    class IoDestroy : public Syscall {
    public:
        uint64_t ctx;

        std::string toLogString() override {
            std::stringstream ss;

            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";

            ss << syscallName << "(";
            ss << "ctx = " << ctx;
            ss << ") -> ";

            ss << ret;

            return ss.str();
        }
    };

    class IoSubmit : public Syscall {
    public:
        uint64_t ctx;
        uint64_t nr;
        uint64_t iocbpp;
        std::vector<std::pair<uintptr_t, struct iocb>> iocbs;

        std::string toLogString() override {
            std::stringstream ss;

            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";

            ss << syscallName << "(";

            ss << "ctx = " << ctx << ", ";
            ss << "nr = " << nr << ", ";
            ss << "iocbpp = " << iocbpp;
            ss << ") -> ";

            ss << ret;

            ss << "\n    -- iocbs --\n    ";
            for (auto &iocb : iocbs) {
                ss << "iocb = { /* ptr = " << std::format("0x{:x}", iocb.first) << " */";
                ss << " \n        ";
                ss << "aio_data = " << std::format("0x{:x}", iocb.second.aio_data)<< ", ";
                ss << " \n        ";
                ss << "aio_lio_opcode = " << iocb.second.aio_lio_opcode << ", ";
                ss << " \n        ";
                ss << "aio_reqprio = " << iocb.second.aio_reqprio << ", ";
                ss << " \n        ";
                ss << "aio_fildes = " << iocb.second.aio_fildes << ", ";
                ss << " \n        ";
                ss << "aio_buf = " << std::format("0x{:x}", iocb.second.aio_buf) << ", ";
                ss << " \n        ";
                ss << "aio_nbytes = " << iocb.second.aio_nbytes << ", ";
                ss << " \n        ";
                ss << "aio_offset = " << iocb.second.aio_offset << ", ";
                ss << " \n        ";
                ss << "aio_flags = " << iocb.second.aio_flags << ", ";
                ss << " \n        ";
                ss << "aio_resfd = " << iocb.second.aio_resfd << ", ";
                ss << " \n        ";
                ss << "aio_lio_opcode = " << iocb.second.aio_lio_opcode;
                ss << "\n    ";
                ss << "}\n    ";
            }

            return ss.str();
        }
    };

    class IoCancel : public Syscall {
    public:
        uint64_t ctx;
        uint64_t iocb_ptr;
        uint64_t result;

        std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "ctx = " << ctx << ", ";
            ss << "iocb = " << std::format("0x{:x}", iocb_ptr) << ", ";
            ss << "result = " << std::format("0x{:x}", result);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoGetEvents : public Syscall {
    public:
        uint64_t ctx;
        uint64_t min_nr;
        uint64_t nr;
        uint64_t events;
        uint64_t timeout;
        int64_t nsec;
        int64_t sec;

        std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(\n";
            ss << "    ctx = " << ctx << ", \n";
            ss << "    min_nr = " << min_nr << ", \n";
            ss << "    nr = " << nr << ", \n";
            ss << "    events = " << std::format("0x{:x}", events) << ", \n";
            ss << "    timeout = struct timespec { /* ptr = " << std::format("0x{:x}", timeout) << " */\n";
            ss << "        tv_sec = " << sec << ", \n";
            ss << "        tv_nsec = " << nsec << "\n";
            ss << "    }\n";
            ss << ") -> ";
            ss << ret;
            ss << "\n";
            return ss.str();
        }
    };

    class Setxattr : public Syscall {
    public:
        std::string path;
        std::string name;
        std::vector<uint8_t> value;
        uintptr_t value_p;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "name = " << name << ", ";
            char* hex = (char*) malloc(value.size() * 2 + 1);
            char_to_hex((char*) value.data(), hex, value.size());
            if(value_p != 0) {
                ss << "value = hex2bytes(\"" << hex << "\"), ";
            } else {
                ss << "value = NULL, ";
            }
            free(hex);
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Lsetxattr : public Setxattr {};

    class Fsetxattr : public Syscall {
    public:
        int32_t fd;
        std::string name;
        uintptr_t value_p;
        std::vector<uint8_t> value;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            char* hex = (char*) malloc(value.size() * 2 + 1);
            char_to_hex((char*) value.data(), hex, value.size());
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "name = " << name << ", ";
            if(value_p != 0) {
                ss << "value = hex2bytes(\"" << hex << "\"), ";
            } else {
                ss << "value = NULL, ";
            }
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            free(hex);
            return ss.str();
        }
    };

    class Getxattr : public Syscall {
    public:
        std::string path;
        std::string name;
        uintptr_t p_value;
        std::vector<uint8_t> value;
        size_t size;

        virtual std::string toLogString() override {
            std::stringstream ss;
            char* hex = (char*) malloc(value.size() * 2 + 1);
            char_to_hex((char*) value.data(), hex, value.size());
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "name = " << name << ", ";
            ss << "value = " << std::format("0x{:x}", p_value) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            ss << "\n    value_buffer = hex2bytes(\"" << hex << "\")\n";
            free(hex);
            return ss.str();
        }
    };

    class Lgetxattr : public Getxattr {
    };

    class Fgetxattr : public Syscall {
    public:
        int32_t fd;
        std::string name;
        uintptr_t p_value;
        std::vector<uint8_t> value;
        size_t size;

        virtual std::string toLogString() override {
            std::stringstream ss;
            char* hex = (char*) malloc(value.size() * 2 + 1);
            char_to_hex((char*) value.data(), hex, value.size());
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "name = " << name << ", ";
            ss << "value = " << std::format("0x{:x}", p_value) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            ss << "\n    value_buffer = hex2bytes(\"" << hex << "\")\n";
            free(hex);
            return ss.str();
        }
    };

    class Listxattr : public Syscall {
    public:
        std::string path;
        uintptr_t list;
        size_t size;
        std::vector<std::string> names;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "list = " << std::format("0x{:x}", list) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            ss << "\n    names = [";
            for (auto &name : names) {
                ss << name << ", ";
            }
            ss << "]\n";
            return ss.str();
        }
    };

    class Llistxattr : public Listxattr {
    };

    class Flistxattr : public Syscall {
    public:
        int32_t fd;
        uintptr_t list;
        size_t size;
        std::vector<std::string> names;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "list = " << std::format("0x{:x}", list) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            ss << "\n    names = [";
            for (auto &name : names) {
                ss << name << ", ";
            }
            ss << "]\n";
            return ss.str();
        }
    };

    class Removexattr : public Syscall {
    public:
        std::string path;
        std::string name;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "name = " << name;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Lremovexattr : public Removexattr {
    };

    class Fremovexattr : public Syscall {
    public:
        int32_t fd;
        std::string name;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "name = " << name;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getcwd : public Syscall {
    public:
        uintptr_t buf;
        size_t size;
        std::string cwd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            ss << "\n    cwd = " << cwd;
            return ss.str();
        }
    };

    class LookupDcookie : public Syscall {
    public:
        uint64_t cookie;
        uint64_t buf;
        uint64_t len;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "cookie = " << cookie << ", ";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EventFd : public Syscall {
    public:
        uint32_t initval;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "initval = " << initval;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EventFd2 : public EventFd {
    public:
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "initval = " << initval << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EpollCreate : public Syscall {
    public:
        int32_t size;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EpollCreate1 : public EpollCreate {
    public:
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "size = " << size << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EpollCtl : public Syscall {
    public:
        int32_t epfd;
        int32_t op;
        int32_t fd;
        uintptr_t event_p;
        struct epoll_event event;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(\n";
            ss << "    epfd = " << epfd << ",\n";
            ss << "    op = " << op << ",\n";
            ss << "    fd = " << fd << ",\n";
            ss << "    event = " << std::format("0x{:x}", event_p) << "\n";
            ss << ") -> ";
            ss << ret;
            ss << "\n    event = struct epoll_event {\n";
            ss << "        events = " << event.events << ",\n";
            ss << "        data = " << event.data.u64 << "\n";
            ss << "    }\n";
            return ss.str();
        }
    };

    class EpollWait : public Syscall {
    public:
        int32_t epfd;
        uintptr_t events;
        int32_t maxevents;
        int32_t timeout;
        std::vector<struct epoll_event> events_value;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(\n";
            ss << "    epfd = " << epfd << ",\n";
            ss << "    events = " << std::format("0x{:x}", events) << ",\n";
            ss << "    maxevents = " << maxevents << ",\n";
            ss << "    timeout = " << timeout << "\n";
            ss << ") -> ";
            ss << ret;
            ss << "\n    events = [\n";
            for (auto &event : events_value) {
                ss << "{ " << event.events << ", " << event.data.u64 << "}, ";
            }
            ss << "]\n";
            return ss.str();
        }
    };

    class EpollPwait : public EpollWait {
    public:
        uintptr_t sigmask_p;
//        sigset_t sigmask;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(\n";
            ss << "    epfd = " << epfd << ",\n";
            ss << "    events = " << std::format("0x{:x}", events) << ",\n";
            ss << "    maxevents = " << maxevents << ",\n";
            ss << "    timeout = " << timeout << ",\n";
            ss << "    sigmask = " << std::format("0x{:x}", sigmask_p) << "\n";
            ss << ") -> ";
            ss << ret;
            ss << "\n    events = [\n";
            for (auto &event : events_value) {
                ss << "{ " << event.events << ", " << event.data.u64 << "}, ";
            }
            ss << "]\n";
//            ss << "    sigmask = ";
//            for (int i = 0; i < sizeof(sigset_t); ++i) {
//                ss << std::format("{:02x}", ((unsigned char*) &sigmask)[i]);
//            }
//            ss << "\n";
            return ss.str();
        }
    };

    class Dup : public Syscall {
    public:
        int32_t oldfd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "dup(";
            ss << "oldfd = " << oldfd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Dup2 : public Dup {
    public:
        int32_t newfd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "dup2(";
            ss << "oldfd = " << oldfd << ", ";
            ss << "newfd = " << newfd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Dup3 : public Dup2 {
    public:
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "dup3(";
            ss << "oldfd = " << oldfd << ", ";
            ss << "newfd = " << newfd << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fnctl : public Syscall {
    public:
        int32_t fd;
        int32_t cmd;
        int32_t arg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "fnctl(";
            ss << "fd = " << fd << ", ";
            ss << "cmd = " << cmd << ", ";
            ss << "arg = " << arg;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class InotifyInit: public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "inotify_init() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class InotifyInit1: public InotifyInit {
    public:
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "inotify_init1(";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class InotifyAddWatch: public Syscall {
    public:
        int32_t fd;
        std::string path;
        uint32_t mask;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "inotify_add_watch(";
            ss << "fd = " << fd << ", ";
            ss << "path = " << path << ", ";
            ss << "mask = " << std::format("0x{:x}", mask);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class InotifyRmWatch: public Syscall {
    public:
        int32_t fd;
        int32_t wd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "inotify_rm_watch(";
            ss << "fd = " << fd << ", ";
            ss << "wd = " << wd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Ioctl : public Syscall {
    public:
        int32_t fd;
        uint32_t request;
        uintptr_t arg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "ioctl(";
            ss << "fd = " << fd << ", ";
            ss << "request = " << std::format("0x{:x}", request) << ", ";
            ss << "arg = " << std::format("0x{:x}", arg);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoprioSet : public Syscall {
    public:
        int32_t which;
        int32_t who;
        int32_t ioprio;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "ioprio_set(";
            ss << "which = " << which << ", ";
            ss << "who = " << who << ", ";
            ss << "ioprio = " << ioprio;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoprioGet : public IoprioSet {
    public:
        int32_t ioprio_p;
        int32_t ioprio_value;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << "ioprio_get(";
            ss << "which = " << which << ", ";
            ss << "who = " << who << ", ";
            ss << "ioprio_p = " << std::format("0x{:x}", ioprio_p) << ", ";
            ss << "ioprio_value = " << ioprio_value;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Flock : public Syscall {
    public:
        int32_t fd;
        int32_t operation;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "op = " << operation;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mknodat : public Syscall {
    public:
        int32_t dfd;
        std::string path;
        uint32_t mode;
        uint64_t dev;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "mode = " << std::format("0{:o}", mode) << ", ";
            ss << "dev = " << std::format("0x{:x}", dev);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mkdirat : public Syscall {
    public:
        int32_t dfd;
        std::string path;
        uint32_t mode;

        std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "mode = " << std::format("0{:o}", mode);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Unlinkat : public Syscall {
    public:
        int32_t dfd;
        std::string path;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Symlinkat : public Syscall {
    public:
        std::string oldname;
        int32_t newdfd;
        std::string newname;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            ss << "oldpath = " << oldname << ", ";
            ss << "newdfd = " << newdfd << ", ";
            ss << "newpath = " << newname;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Linkat : public Syscall {
    public:
        int32_t olddfd;
        std::string oldpath;
        int32_t newdfd;
        std::string newpath;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            if (olddfd == AT_FDCWD) {
                ss << "olddfd = AT_FDCWD, ";
            } else {
                ss << "olddfd = " << olddfd << ", ";
            }
            ss << "oldpath = " << oldpath << ", ";
            if (newdfd == AT_FDCWD) {
                ss << "newdfd = AT_FDCWD, ";
            } else {
                ss << "newdfd = " << newdfd << ", ";
            }
            ss << "newpath = " << newpath << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Renameat : public Syscall {
    public:
        int32_t olddfd;
        std::string oldpath;
        int32_t newdfd;
        std::string newpath;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << "[pid = " << std::to_string(pid) << ", uid = " << std::to_string(uid) << "] ";
            ss << syscallName << "(";
            if (olddfd == AT_FDCWD) {
                ss << "olddfd = AT_FDCWD, ";
            } else {
                ss << "olddfd = " << olddfd << ", ";
            }
            ss << "oldpath = " << oldpath << ", ";
            if (newdfd == AT_FDCWD) {
                ss << "newdfd = AT_FDCWD, ";
            } else {
                ss << "newdfd = " << newdfd << ", ";
            }
            ss << "newpath = " << newpath;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Umount2 : public Syscall {
    public:
        std::string target;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "target = " << target << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mount : public Syscall {
    public:
        std::string dev;
        std::string dir;
        std::string type;
        uint64_t flags;
        uintptr_t data;

        // int mount(const char *source, const char *target,
        //                 const char *filesystemtype, unsigned long mountflags,
        //                 const void *_Nullable data);
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "source = " << dev << ", ";
            ss << "target = " << dir << ", ";
            ss << "filesystemtype = " << type << ", ";
            ss << "mountflags = " << flags << ", ";
            ss << "data = " << std::format("0x{:x}", data);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PrivotRoot : public Syscall {
    public:
        std::string new_root;
        std::string put_old;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "new_root = " << new_root << ", ";
            ss << "put_old = " << put_old;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Nfsservctl: public Syscall {
    public:
        int32_t cmd;
        uintptr_t argp;
        uintptr_t resp;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "cmd = " << cmd << ", ";
            ss << "argp = " << std::format("0x{:x}", argp) << ", ";
            ss << "resp = " << std::format("0x{:x}", resp);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Statfs: public Syscall {
    public:
        std::string path;
        uintptr_t buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "buf = " << std::format("0x{:x}", buf);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fstatfs: public Syscall {
    public:
        int32_t fd;
        uintptr_t buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "buf = " << std::format("0x{:x}", buf);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Truncate: public Syscall {
    public:
        std::string path;
        int64_t length;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "path = " << path << ", ";
            ss << "length = " << length;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Ftruncate: public Syscall {
    public:
        int32_t fd;
        int64_t length;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "length = " << length;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fallocate: public Syscall {
    public:
        int32_t fd;
        int32_t mode;
        int64_t offset;
        int64_t len;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "mode = " << mode << ", ";
            ss << "offset = " << offset << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Faccessat: public Syscall {
    public:
        int32_t dfd;
        std::string path;
        int32_t mode;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "mode = " << mode << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Chdir: public Syscall {
    public:
        std::string path;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "path = " << path;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fchdir: public Syscall {
    public:
        int32_t fd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Chroot: public Syscall {
    public:
        std::string path;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "path = " << path;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fchmod: public Syscall {
    public:
        int32_t fd;
        uint32_t mode;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "mode = " << std::format("0o{:o}", mode);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fchmodat: public Syscall {
    public:
        int32_t dfd;
        std::string path;
        uint32_t mode;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "mode = " << std::format("0o{:o}", mode) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fchown: public Syscall {
    public:
        int32_t fd;
        uint32_t uid;
        uint32_t gid;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "uid = " << uid << ", ";
            ss << "gid = " << gid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fchownat: public Syscall {
    public:
        int32_t dfd;
        std::string path;
        uint32_t uid;
        uint32_t gid;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "uid = " << uid << ", ";
            ss << "gid = " << gid << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Openat: public Syscall {
    public:
        int32_t dfd;
        std::string path;
        int32_t flags;
        uint32_t mode;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            if (dfd == AT_FDCWD) {
                ss << "dfd = AT_FDCWD, ";
            } else {
                ss << "dfd = " << dfd << ", ";
            }
            ss << "path = " << path << ", ";
            ss << "flags = " << flags << ", ";
            ss << "mode = " << std::format("0o{:o}", mode);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Close: public Syscall {
    public:
        int32_t fd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Vhangup: public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Pipe2: public Syscall {
    public:
        int32_t pipefd[2];
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pipefd = [" << pipefd[0] << ", " << pipefd[1] << "], ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Quotactl: public Syscall {
    public:
        int32_t cmd;
        std::string special;
        int32_t id;
        uintptr_t addr;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "cmd = " << cmd << ", ";
            ss << "special = " << special << ", ";
            ss << "id = " << id << ", ";
            ss << "addr = " << std::format("0x{:x}", addr);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getdents64: public Syscall {
    public:
        int32_t fd;
        uintptr_t dirp;
        uint32_t count;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "dirp = " << std::format("0x{:x}", dirp) << ", ";
            ss << "count = " << count;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Lseek: public Syscall {
    public:
        int32_t fd;
        uint64_t offset;
        uint32_t whence;
        uint64_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "offset = " << offset << ", ";
            ss << "whence = " << whence;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Read: public Syscall {
    public:
        int32_t fd;
        uintptr_t buf;
        size_t count;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "count = " << count;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Write: public Read {

    };

    class Readv: public Syscall {
    public:
        int32_t fd;
        uintptr_t iov;
        int32_t iovcnt;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "iov = " << std::format("0x{:x}", iov) << ", ";
            ss << "iovcnt = " << iovcnt;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Writev: public Readv {

    };

    class Pread64: public Read {
    public:
        uint64_t pos;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "count = " << count << ", ";
            ss << "offset = " << pos;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Pwrite64: public Pread64 {

    };

    class Preadv: public Syscall {
    public:
        int32_t fd;
        uintptr_t iov;
        int32_t iovcnt;
        uint64_t pos;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "iov = " << std::format("0x{:x}", iov) << ", ";
            ss << "iovcnt = " << iovcnt << ", ";
            ss << "offset = " << pos;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Pwritev: public Preadv {

    };

    class Sendfile: public Syscall {
    public:
        int32_t out_fd;
        int32_t in_fd;
        uintptr_t offset;
        uint32_t count;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "out_fd = " << out_fd << ", ";
            ss << "in_fd = " << in_fd << ", ";
            ss << "offset = " << std::format("0x{:x}", offset) << ", ";
            ss << "count = " << count;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Pselect6: public Syscall {
    public:
        int32_t nfds;
        uintptr_t readfds;
        uintptr_t writefds;
        uintptr_t exceptfds;
        uintptr_t timeout;
        uintptr_t sigmask;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "nfds = " << nfds << ", ";
            ss << "readfds = " << std::format("0x{:x}", readfds) << ", ";
            ss << "writefds = " << std::format("0x{:x}", writefds) << ", ";
            ss << "exceptfds = " << std::format("0x{:x}", exceptfds) << ", ";
            ss << "timeout = " << std::format("0x{:x}", timeout) << ", ";
            ss << "sigmask = " << std::format("0x{:x}", sigmask);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Ppoll: public Syscall {
    public:
        uintptr_t fds;
        uint32_t nfds;
        uintptr_t timeout_ts;
        uintptr_t sigmask;
        uint32_t sigsetsize;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fds = " << std::format("0x{:x}", fds) << ", ";
            ss << "nfds = " << nfds << ", ";
            ss << "timeout_ts = " << std::format("0x{:x}", timeout_ts) << ", ";
            ss << "sigmask = " << std::format("0x{:x}", sigmask) << ", ";
            ss << "sigsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Signalfd4: public Syscall {
    public:
        int32_t fd;
        uintptr_t mask;
        uint32_t size;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "mask = " << std::format("0x{:x}", mask) << ", ";
            ss << "size = " << size << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Vmsplice: public Syscall {
    public:
        int32_t fd;
        uintptr_t iov;
        uint32_t nr_segs;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "iov = " << std::format("0x{:x}", iov) << ", ";
            ss << "nr_segs = " << nr_segs << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SpliceClient : public Syscall {
    public:
        int32_t fd_in;
        uintptr_t off_in;
        int32_t fd_out;
        uintptr_t off_out;
        uint32_t len;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd_in = " << fd_in << ", ";
            ss << "off_in = " << std::format("0x{:x}", off_in) << ", ";
            ss << "fd_out = " << fd_out << ", ";
            ss << "off_out = " << std::format("0x{:x}", off_out) << ", ";
            ss << "len = " << len << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TeeClient : public Syscall {
    public:
        int32_t fdin;
        int32_t fdout;
        uint32_t len;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fdin = " << fdin << ", ";
            ss << "fdout = " << fdout << ", ";
            ss << "len = " << len << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Readlinkat : public Syscall {
    public:
        int32_t dfd;
        std::string path;
        uintptr_t buf;
        int32_t bufsiz;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "path = " << path << ", ";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "bufsiz = " << bufsiz;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fstatat : public Syscall {
    public:
        int32_t dfd;
        std::string filename;
        uintptr_t statbuf;
        int32_t flag;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = " << filename << ", ";
            ss << "statbuf = " << std::format("0x{:x}", statbuf) << ", ";
            ss << "flag = " << flag;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fstat : public Syscall {
    public:
        int32_t fd;
        uintptr_t statbuf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "statbuf = " << std::format("0x{:x}", statbuf);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Sync : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fsync : public Syscall {
    public:
        int32_t fd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fdatasync : public Syscall {
    public:
        int32_t fd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SyncFileRange2 : public Syscall {
    public:
        int32_t fd;
        uint32_t flags;
        uint64_t offset;
        uint64_t nbytes;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "offset = " << offset << ", ";
            ss << "nbytes = " << nbytes;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SyncFileRange : public Syscall {
    public:
        int32_t fd;
        uint64_t offset;
        uint64_t nbytes;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "offset = " << offset << ", ";
            ss << "nbytes = " << nbytes << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerfdCreate : public Syscall {
    public:
        int32_t clockid;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "clockid = " << clockid << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerfdSettime : public Syscall {
    public:
        int32_t ufd;
        int32_t flags;
        uintptr_t new_value;
        uintptr_t old_value;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ufd = " << ufd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "new_value = " << std::format("0x{:x}", new_value) << ", ";
            ss << "old_value = " << std::format("0x{:x}", old_value);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerfdGettime : public Syscall {
    public:
        int32_t ufd;
        uintptr_t otmr;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ufd = " << ufd << ", ";
            ss << "otmr = " << std::format("0x{:x}", otmr);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Utimensat : public Syscall {
    public:
        int32_t dfd;
        std::string filename;
        uintptr_t utimes;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = \"" << filename << "\", ";
            ss << "utimes = " << std::format("0x{:x}", utimes) << ", ";
            ss << "flags = " << flags;
            ss << ")";
            return ss.str();
        }
    };

    class Acct : public Syscall {
    public:
        std::string name;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "name = \"" << name << "\"";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Capget : public Syscall {
    public:
        uintptr_t header;
        uintptr_t data;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "header = " << std::format("0x{:x}", header) << ", ";
            ss << "data = " << std::format("0x{:x}", data);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Personality : public Syscall {
    public:
        uintptr_t persona;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "persona = " << std::format("0x{:x}", persona);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Exit : public Syscall {
    public:
        int32_t status;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "status = " << status;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ExitGroup : public Syscall {
    public:
        int32_t status;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "status = " << status;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Waitid : public Syscall {
    public:
        int32_t idtype;
        uint32_t id;
        uintptr_t infop;
        int32_t options;
        uintptr_t ru;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "idtype = " << idtype << ", ";
            ss << "id = " << id << ", ";
            ss << "infop = " << std::format("0x{:x}", infop) << ", ";
            ss << "options = " << options << ", ";
            ss << "ru = " << std::format("0x{:x}", ru);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetTidAddress : public Syscall {
    public:
        uintptr_t tidptr;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tidptr = " << std::format("0x{:x}", tidptr);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Unshare : public Syscall {
    public:
        uintptr_t unshare_flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "unshare_flags = " << std::format("0x{:x}", unshare_flags);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetRobustList : public Syscall {
    public:
        uintptr_t head;
        uint32_t len;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "head = " << std::format("0x{:x}", head) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetRobustList : public Syscall {
    public:
        int32_t pid;
        uintptr_t head_ptr;
        uintptr_t len_ptr;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "head_ptr = " << std::format("0x{:x}", head_ptr) << ", ";
            ss << "len_ptr = " << std::format("0x{:x}", len_ptr);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Nanosleep : public Syscall {
    public:
        uintptr_t rqtp;
        struct timespec rqtp_val;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "rqtp = " << std::format("0x{:x}", rqtp) << ", ";
            ss << "rqtp_val = {" << rqtp_val.tv_sec << ", " << rqtp_val.tv_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getitimer : public Syscall {
    public:
        int32_t which;
        uintptr_t value;
        struct itimerval val;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which = " << which << ", ";
            ss << "value = " << std::format("0x{:x}", value) << ", ";
            ss << "val.it_interval = {" << val.it_interval.tv_sec << ", " << val.it_interval.tv_usec << "}, ";
            ss << "val.it_value = {" << val.it_value.tv_sec << ", " << val.it_value.tv_usec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Setitimer : public Syscall {
    public:
        int32_t which;
        uintptr_t new_value;
        uintptr_t old_value;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which = " << which << ", ";
            ss << "new_value = " << std::format("0x{:x}", new_value) << ", ";
            ss << "old_value = " << std::format("0x{:x}", old_value);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class KexecLoad : public Syscall {
    public:
        uintptr_t entry;
        uint64_t nr_segments;
        uintptr_t segments;
        uint64_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "entry = " << std::format("0x{:x}", entry) << ", ";
            ss << "nr_segments = " << nr_segments << ", ";
            ss << "segments = " << std::format("0x{:x}", segments) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class InitModule : public Syscall {
    public:
        uint32_t len;
        std::vector<uint8_t> umod_buf;
        std::string uargs_buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "len = " << len << ", ";
            ss << "umod_buf = [";
            for (size_t i = 0; i < std::min(umod_buf.size(), size_t(10)); ++i) { // Limit the number of bytes printed
                ss << std::format("0x{:02x}", umod_buf[i]);
                if (i != std::min(umod_buf.size(), size_t(10)) - 1) {
                    ss << ", ";
                }
            }
            if (umod_buf.size() > 10) ss << ", ..."; // Indicate more bytes if the buffer is too long
            ss << "], ";
            ss << "uargs_buf = " << uargs_buf;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class DeleteModule : public Syscall {
    public:
        std::string uargs_buf;  // 存储解析后的 name_buf 字符串
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "name_buf = " << uargs_buf << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerCreate : public Syscall {
    public:
        int32_t clockid;
        uintptr_t sevp;
        uintptr_t timerid;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "clockid = " << clockid << ", ";
            ss << "sevp = " << std::format("0x{:x}", sevp) << ", ";
            ss << "timerid = " << std::format("0x{:x}", timerid);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerGetTime : public Syscall {
    public:
        uintptr_t timerid;
        uintptr_t value;  // Pointer to the struct value (likely a pointer to timespec structure)
        struct {
            uint64_t it_interval_sec;
            uint64_t it_interval_nsec;
            uint64_t it_value_sec;
            uint64_t it_value_nsec;
        } timespec_values;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "timerid = " << std::format("0x{:x}", timerid) << ", ";
            ss << "value = " << std::format("0x{:x}", value) << ", ";
            ss << "it_interval = {sec = " << timespec_values.it_interval_sec
               << ", nsec = " << timespec_values.it_interval_nsec << "}, ";
            ss << "it_value = {sec = " << timespec_values.it_value_sec
               << ", nsec = " << timespec_values.it_value_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerGetOverrun : public Syscall {
    public:
        uintptr_t timerid;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "timerid = " << std::format("0x{:x}", timerid);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerSetTime : public Syscall {
    public:
        uintptr_t timerid;
        uint32_t flags;
        uintptr_t new_value;  // Pointer to the new timespec value (likely)
        struct {
            uint64_t it_interval_sec;
            uint64_t it_interval_nsec;
            uint64_t it_value_sec;
            uint64_t it_value_nsec;
        } timespec_values;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "timerid = " << std::format("0x{:x}", timerid) << ", ";
            ss << "flags = " << flags << ", ";
            ss << "new_value = " << std::format("0x{:x}", new_value) << ", ";
            ss << "it_interval = {sec = " << timespec_values.it_interval_sec
               << ", nsec = " << timespec_values.it_interval_nsec << "}, ";
            ss << "it_value = {sec = " << timespec_values.it_value_sec
               << ", nsec = " << timespec_values.it_value_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class TimerDelete : public Syscall {
    public:
        uintptr_t timerid;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "timerid = " << std::format("0x{:x}", timerid);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ClockSetTime : public Syscall {
    public:
        int32_t which_clock;
        uintptr_t tp;  // Pointer to timespec structure
        struct {
            uint64_t tv_sec;
            uint64_t tv_nsec;
        } val;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which_clock = " << which_clock << ", ";
            ss << "tp = " << std::format("0x{:x}", tp) << ", ";
            ss << "val = {sec = " << val.tv_sec << ", nsec = " << val.tv_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ClockGetTime : public Syscall {
    public:
        int32_t which_clock;
        uintptr_t tp;  // Pointer to timespec structure
        struct {
            uint64_t tv_sec;
            uint64_t tv_nsec;
        } val;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which_clock = " << which_clock << ", ";
            ss << "tp = " << std::format("0x{:x}", tp) << ", ";
            ss << "val = {sec = " << val.tv_sec << ", nsec = " << val.tv_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ClockGetRes : public Syscall {
    public:
        int32_t which_clock;
        uintptr_t tp;  // Pointer to timespec structure
        struct {
            uint64_t tv_sec;
            uint64_t tv_nsec;
        } val;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which_clock = " << which_clock << ", ";
            ss << "tp = " << std::format("0x{:x}", tp) << ", ";
            ss << "val = {sec = " << val.tv_sec << ", nsec = " << val.tv_nsec << "}";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ClockNanoSleep : public Syscall {
    public:
        int32_t which_clock;
        int32_t flags;
        uintptr_t rqtp;  // Pointer to timespec structure (requested time)
        uintptr_t rmtp;  // Pointer to timespec structure (remaining time)

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which_clock = " << which_clock << ", ";
            ss << "flags = " << flags << ", ";
            ss << "rqtp = " << std::format("0x{:x}", rqtp) << ", ";
            ss << "rmtp = " << std::format("0x{:x}", rmtp);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Syslog : public Syscall {
    public:
        int32_t type;
        uint32_t len;
        std::string buf_buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "type = " << type << ", ";
            ss << "len = " << len << ", ";
            ss << "buf_buf = \"" << buf_buf << "\"";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Ptrace : public Syscall {
    public:
        int64_t request;
        int64_t pid;
        uint64_t addr;
        uint64_t data;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "request = " << request << ", ";
            ss << "pid = " << pid << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";
            ss << "data = " << std::format("0x{:x}", data);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedSetParam : public Syscall {
    public:
        int32_t pid;
        uintptr_t param;  // Pointer to scheduling parameter structure

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "param = " << std::format("0x{:x}", param);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedSetScheduler : public Syscall {
    public:
        int32_t pid;
        int32_t policy;
        uintptr_t param;  // Pointer to scheduling parameter structure

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "policy = " << policy << ", ";
            ss << "param = " << std::format("0x{:x}", param);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedGetScheduler : public Syscall {
    public:
        int32_t pid;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ")";
            ss << " -> ";
            ss << ret;  // The scheduling policy (return value)
            return ss.str();
        }
    };

    class SchedGetParam : public Syscall {
    public:
        int32_t pid;
        uintptr_t param;  // Pointer to scheduling parameter structure

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "param = " << std::format("0x{:x}", param);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedSetAffinity : public Syscall {
    public:
        int32_t pid;
        uint32_t cpusetsize;
        uintptr_t mask;  // Pointer to the CPU set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "cpusetsize = " << cpusetsize << ", ";
            ss << "mask = " << std::format("0x{:x}", mask);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedGetAffinity : public Syscall {
    public:
        int32_t pid;
        uint32_t cpusetsize;
        uintptr_t mask;  // Pointer to the CPU set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "cpusetsize = " << cpusetsize << ", ";
            ss << "mask = " << std::format("0x{:x}", mask);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedYield : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedGetPriorityMax : public Syscall {
    public:
        int32_t policy;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "policy = " << policy;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedGetPriorityMin : public Syscall {
    public:
        int32_t policy;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "policy = " << policy;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedRRGetInterval : public Syscall {
    public:
        int32_t pid;
        uintptr_t interval;  // Pointer to the time interval structure
        struct timespec val;  // Time interval values (tv_sec, tv_nsec)

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "interval = " << std::format("0x{:x}", interval) << ", ";
            ss << "tv_sec = " << val.tv_sec << ", ";
            ss << "tv_nsec = " << val.tv_nsec;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RestartSyscall : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Kill : public Syscall {
    public:
        int32_t pid;  // Process ID
        int32_t sig;  // Signal number

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "sig = " << sig;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Tkill : public Syscall {
    public:
        int32_t tid;  // Thread ID
        int32_t sig;  // Signal number

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tid = " << tid << ", ";
            ss << "sig = " << sig;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Tgkill : public Syscall {
    public:
        int32_t tgid;  // Target process group ID
        int32_t tid;   // Thread ID
        int32_t sig;   // Signal number

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tgid = " << tgid << ", ";
            ss << "tid = " << tid << ", ";
            ss << "sig = " << sig;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Sigaltstack : public Syscall {
    public:
        uintptr_t uss;  // User stack pointer
        uintptr_t uoss; // Old user stack pointer

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "uss = " << std::format("0x{:x}", uss) << ", ";
            ss << "uoss = " << std::format("0x{:x}", uoss);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigsuspend : public Syscall {
    public:
        uintptr_t mask;        // Signal mask (signal set)
        uint32_t sigsetsize;   // Size of the signal set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "mask = " << std::format("0x{:x}", mask) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigaction : public Syscall {
    public:
        int32_t signum;      // Signal number
        uintptr_t act;       // New signal handler
        uintptr_t oldact;    // Old signal handler
        uint32_t sigsetsize; // Size of the signal set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "signum = " << signum << ", ";
            ss << "act = " << std::format("0x{:x}", act) << ", ";
            ss << "oldact = " << std::format("0x{:x}", oldact) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Sigprocmask : public Syscall {
    public:
        int32_t how;          // Operation type (e.g., SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK)
        uintptr_t set;        // Signal set to be operated on
        uintptr_t oldset;     // Old signal set (before the operation)

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "how = " << how << ", ";
            ss << "set = " << std::format("0x{:x}", set) << ", ";
            ss << "oldset = " << std::format("0x{:x}", oldset);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigprocmask : public Syscall {
    public:
        int32_t how;          // Operation type (e.g., SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK)
        uintptr_t set;        // Signal set to be operated on
        uintptr_t oldset;     // Old signal set (before the operation)
        uint32_t sigsetsize;  // Size of the signal set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "how = " << how << ", ";
            ss << "set = " << std::format("0x{:x}", set) << ", ";
            ss << "oldset = " << std::format("0x{:x}", oldset) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigpending : public Syscall {
    public:
        uintptr_t set;        // Signal set to check pending signals
        uint32_t sigsetsize;  // Size of the signal set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "set = " << std::format("0x{:x}", set) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigtimedwait : public Syscall {
    public:
        uintptr_t set;        // Signal set
        uintptr_t info;       // Signal info
        uintptr_t timeout;    // Timeout
        uint32_t sigsetsize;  // Size of signal set

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "set = " << std::format("0x{:x}", set) << ", ";
            ss << "info = " << std::format("0x{:x}", info) << ", ";
            ss << "timeout = " << std::format("0x{:x}", timeout) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigqueueinfo : public Syscall {
    public:
        int32_t tgid;        // Thread group ID
        int32_t sig;         // Signal number
        uintptr_t info;      // Signal info (pointer to struct)

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tgid = " << tgid << ", ";
            ss << "sig = " << sig << ", ";
            ss << "info = " << std::format("0x{:x}", info) << ", ";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RtSigreturn : public Syscall {
    public:
        uintptr_t ustack;  // Signal stack pointer

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ustack = " << std::format("0x{:x}", ustack) << ", ";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Setpriority : public Syscall {
    public:
        int32_t which;    // Priority category (e.g., PRIO_PROCESS, PRIO_PGRP, PRIO_USER)
        int32_t who;      // Process or thread ID
        int32_t niceval;  // Nice value to set the priority

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which = " << which << ", ";
            ss << "who = " << who << ", ";
            ss << "niceval = " << niceval;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getpriority : public Syscall {
    public:
        int32_t which;  // Priority category (e.g., PRIO_PROCESS, PRIO_PGRP, PRIO_USER)
        int32_t who;    // Process or thread ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which = " << which << ", ";
            ss << "who = " << who;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Reboot : public Syscall {
    public:
        int32_t magic;   // Magic number 1
        int32_t magic2;  // Magic number 2
        uint32_t op;     // Operation type (e.g., REBOOT_HALT, REBOOT_POWER_OFF, etc.)
        uintptr_t arg;   // Argument for the reboot operation (e.g., reboot flags)

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "magic = " << magic << ", ";
            ss << "magic2 = " << magic2 << ", ";
            ss << "op = " << op << ", ";
            ss << "arg = " << std::format("0x{:x}", arg);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetRegid : public Syscall {
    public:
        int32_t rgid;  // Real Group ID
        int32_t egid;  // Effective Group ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "rgid = " << rgid << ", ";
            ss << "egid = " << egid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetGid : public Syscall {
    public:
        int32_t gid;  // Group ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "gid = " << gid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetReuid : public Syscall {
    public:
        int32_t ruid;  // Real User ID
        int32_t euid;  // Effective User ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ruid = " << ruid << ", ";
            ss << "euid = " << euid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetUid : public Syscall {
    public:
        int32_t uid;  // User ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "uid = " << uid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetResUid : public Syscall {
    public:
        int32_t ruid;  // Real User ID
        int32_t euid;  // Effective User ID
        int32_t suid;  // Saved User ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ruid = " << ruid << ", ";
            ss << "euid = " << euid << ", ";
            ss << "suid = " << suid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetResUid : public Syscall {
    public:
        uintptr_t ruid;    // Pointer to real user ID
        int32_t ruid_val;  // Real User ID value
        uintptr_t euid;    // Pointer to effective user ID
        int32_t euid_val;  // Effective User ID value
        uintptr_t suid;    // Pointer to saved user ID
        int32_t suid_val;  // Saved User ID value

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ruid = " << std::format("0x{:x}", ruid) << ", ";
            ss << "ruid_val = " << ruid_val << ", ";
            ss << "euid = " << std::format("0x{:x}", euid) << ", ";
            ss << "euid_val = " << euid_val << ", ";
            ss << "suid = " << std::format("0x{:x}", suid) << ", ";
            ss << "suid_val = " << suid_val;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetResGid : public Syscall {
    public:
        int32_t rgid;  // Real group ID
        int32_t egid;  // Effective group ID
        int32_t sgid;  // Saved group ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "rgid = " << rgid << ", ";
            ss << "egid = " << egid << ", ";
            ss << "sgid = " << sgid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetResGid : public Syscall {
    public:
        uintptr_t rgid;  // Real group ID pointer
        int32_t rgid_val;  // Value of real group ID
        uintptr_t egid;  // Effective group ID pointer
        int32_t egid_val;  // Value of effective group ID
        uintptr_t sgid;  // Saved group ID pointer
        int32_t sgid_val;  // Value of saved group ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "rgid = " << std::format("0x{:x}", rgid) << ", ";
            ss << "rgid_val = " << rgid_val << ", ";
            ss << "egid = " << std::format("0x{:x}", egid) << ", ";
            ss << "egid_val = " << egid_val << ", ";
            ss << "sgid = " << std::format("0x{:x}", sgid) << ", ";
            ss << "sgid_val = " << sgid_val;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetFsUid : public Syscall {
    public:
        int32_t uid;  // Filesystem UID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "uid = " << uid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetFsGid : public Syscall {
    public:
        int32_t gid;  // Filesystem GID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "gid = " << gid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Times : public Syscall {
    public:
        uintptr_t tbuf;  // Pointer to tms struct

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tbuf = " << std::format("0x{:x}", tbuf);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Setpgid : public Syscall {
    public:
        int32_t pid;  // Process ID
        int32_t pgid; // Process Group ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "pgid = " << pgid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getpgid : public Syscall {
    public:
        int32_t pid;  // Process ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getsid : public Syscall {
    public:
        int32_t pid;  // Process ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Setsid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getgroups : public Syscall {
    public:
        int32_t gidsetsize;       // Group list size
        std::vector<int32_t> grouplist;  // Group list

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "gidsetsize = " << gidsetsize << ", ";
            ss << "grouplist = [";
            for (const auto& group : grouplist) {
                ss << group << ", ";
            }
            ss.seekp(-2, ss.cur);  // Remove the last comma and space
            ss << "], ";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Setgroups : public Syscall {
    public:
        int32_t gidsetsize;       // Group list size
        std::vector<int32_t> grouplist;  // Group list

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "gidsetsize = " << gidsetsize << ", ";
            ss << "grouplist = [";
            for (const auto& group : grouplist) {
                ss << group << ", ";
            }
            ss.seekp(-2, ss.cur);  // Remove the last comma and space
            ss << "], ";
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Uname : public Syscall {
    public:
        uintptr_t name;  // System name

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "name = " << std::format("0x{:x}", name);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetHostname : public Syscall {
    public:
        uintptr_t name;
        int32_t len;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "name = " << std::format("0x{:x}", name) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetDomainName : public Syscall {
    public:
        uintptr_t name;
        int32_t len;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "name = " << std::format("0x{:x}", name) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetRlimit : public Syscall {
    public:
        uint32_t resource;
        uintptr_t rlim;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "resource = " << resource << ", ";
            ss << "rlim = " << std::format("0x{:x}", rlim);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetRlimit : public Syscall {
    public:
        uint32_t resource;
        uintptr_t rlim;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "resource = " << resource << ", ";
            ss << "rlim = " << std::format("0x{:x}", rlim);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetRusage : public Syscall {
    public:
        int32_t who;
        uintptr_t ru;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "who = " << who << ", ";
            ss << "ru = " << std::format("0x{:x}", ru);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Umask : public Syscall {
    public:
        int64_t mask;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "mask = " << std::format("0x{:x}", mask) << ")";
            ss << " -> " << ret;
            return ss.str();
        }
    };

    class Prctl : public Syscall {
    public:
        int32_t option;
        uintptr_t arg2;
        uintptr_t arg3;
        uintptr_t arg4;
        uintptr_t arg5;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "option = " << option << ", ";
            ss << "arg2 = " << std::format("0x{:x}", arg2) << ", ";
            ss << "arg3 = " << std::format("0x{:x}", arg3) << ", ";
            ss << "arg4 = " << std::format("0x{:x}", arg4) << ", ";
            ss << "arg5 = " << std::format("0x{:x}", arg5);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Getcpu : public Syscall {
    public:
        uintptr_t cpup;
        uintptr_t nodep;
        uintptr_t tcache;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "cpup = " << std::format("0x{:x}", cpup) << ", ";
            ss << "nodep = " << std::format("0x{:x}", nodep) << ", ";
            ss << "tcache = " << std::format("0x{:x}", tcache);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Gettimeofday : public Syscall {
    public:
        uintptr_t tv;
        uintptr_t tz;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tv = " << std::format("0x{:x}", tv) << ", ";
            ss << "tz = " << std::format("0x{:x}", tz);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Settimeofday : public Syscall {
    public:
        uintptr_t tv;
        uintptr_t tz;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tv = " << std::format("0x{:x}", tv) << ", ";
            ss << "tz = " << std::format("0x{:x}", tz);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Adjtimex : public Syscall {
    public:
        uintptr_t buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "buf = " << std::format("0x{:x}", buf);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Getpid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Getppid : public Syscall {
    public:
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Getuid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Geteuid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Getgid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Getegid : public Syscall {
    public:
        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Gettid : public Syscall {
    public:
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> " << ret;
            return ss.str();
        }
    };

    class Sysinfo : public Syscall {
    public:
        uintptr_t info;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(info = " << std::format("0x{:x}", info) << ") -> " << ret;
            return ss.str();
        }
    };

    class MqOpen : public Syscall {
    public:
        uintptr_t name;
        std::string name_buf;
        int32_t oflag;
        uint32_t mode;
        uintptr_t attr;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(name = " << std::format("0x{:x}", name)
               << ", name_buf = " << name_buf
               << ", oflag = " << oflag
               << ", mode = " << mode
               << ", attr = " << std::format("0x{:x}", attr)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MqUnlink : public Syscall {
    public:
        uintptr_t name;
        std::string name_buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(name = " << std::format("0x{:x}", name)
               << ", name_buf = " << name_buf
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MqTimedSend : public Syscall {
    public:
        int32_t mqdes;
        uintptr_t msg_ptr;
        uint32_t msg_len;
        uint32_t msg_prio;
        uintptr_t abs_timeout;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(mqdes = " << mqdes
               << ", msg_ptr = " << std::format("0x{:x}", msg_ptr)
               << ", msg_len = " << msg_len
               << ", msg_prio = " << msg_prio
               << ", abs_timeout = " << std::format("0x{:x}", abs_timeout)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MqTimedReceive : public Syscall {
    public:
        int32_t mqdes;
        uintptr_t msg_ptr;
        uint32_t msg_len;
        uintptr_t msg_prio;
        uintptr_t abs_timeout;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(mqdes = " << mqdes
               << ", msg_ptr = " << std::format("0x{:x}", msg_ptr)
               << ", msg_len = " << msg_len
               << ", msg_prio = " << std::format("0x{:x}", msg_prio)
               << ", abs_timeout = " << std::format("0x{:x}", abs_timeout)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MqNotify : public Syscall {
    public:
        int32_t mqdes;
        uintptr_t notification;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(mqdes = " << mqdes
               << ", notification = " << std::format("0x{:x}", notification)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MqGetSetAttr : public Syscall {
    public:
        int32_t mqdes;
        uintptr_t mqstat;
        uintptr_t omqstat;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(mqdes = " << mqdes
               << ", mqstat = " << std::format("0x{:x}", mqstat)
               << ", omqstat = " << std::format("0x{:x}", omqstat)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MsgGet : public Syscall {
    public:
        int32_t key;
        int32_t msgflg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(key = " << key
               << ", msgflg = " << msgflg
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MsgCtl : public Syscall {
    public:
        int32_t msqid;
        int32_t cmd;
        uintptr_t buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(msqid = " << msqid
               << ", cmd = " << cmd
               << ", buf = " << std::format("0x{:x}", buf)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MsgSnd : public Syscall {
    public:
        int32_t msqid;
        uintptr_t msgp;
        uint32_t msgsz;
        int32_t msgflg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(msqid = " << msqid
               << ", msgp = " << std::format("0x{:x}", msgp)
               << ", msgsz = " << msgsz
               << ", msgflg = " << msgflg
               << ") -> " << ret;
            return ss.str();
        }
    };

    class MsgRcv : public Syscall {
    public:
        int32_t msqid;
        uintptr_t msgp;
        uint32_t msgsz;
        int64_t msgtyp;
        int32_t msgflg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(msqid = " << msqid
               << ", msgp = " << std::format("0x{:x}", msgp)
               << ", msgsz = " << msgsz
               << ", msgtyp = " << msgtyp
               << ", msgflg = " << msgflg
               << ") -> " << ret;
            return ss.str();
        }
    };

    class SemGet : public Syscall {
    public:
        int32_t key;
        int32_t nsems;
        int32_t semflg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(key = " << key
               << ", nsems = " << nsems
               << ", semflg = " << semflg
               << ") -> " << ret;
            return ss.str();
        }
    };

    class SemCtl : public Syscall {
    public:
        int32_t semid;
        int32_t semnum;
        int32_t cmd;
        uintptr_t arg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(semid = " << semid
               << ", semnum = " << semnum
               << ", cmd = " << cmd
               << ", arg = " << std::format("0x{:x}", arg)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class SemTimedOp : public Syscall {
    public:
        int32_t semid;
        uintptr_t sops;
        uint32_t nsops;
        uintptr_t timeout;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(semid = " << semid
               << ", sops = " << std::format("0x{:x}", sops)
               << ", nsops = " << nsops
               << ", timeout = " << std::format("0x{:x}", timeout)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class SemOp : public Syscall {
    public:
        int32_t semid;
        uintptr_t sops;
        uint32_t nsops;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(semid = " << semid
               << ", sops = " << std::format("0x{:x}", sops)
               << ", nsops = " << nsops
               << ") -> " << ret;
            return ss.str();
        }
    };

    class ShmGet : public Syscall {
    public:
        int32_t key;
        uint32_t size;
        int32_t shmflg;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(key = " << key
               << ", size = " << size
               << ", shmflg = " << shmflg
               << ") -> " << ret;
            return ss.str();
        }
    };

    class ShmCtl : public Syscall {
    public:
        int32_t shmid;
        int32_t cmd;
        uintptr_t buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(shmid = " << shmid
               << ", cmd = " << cmd
               << ", buf = " << std::format("0x{:x}", buf)
               << ") -> " << ret;
            return ss.str();
        }
    };

    class Shmat : public Syscall {
    public:
        int32_t shmid;
        uintptr_t shmaddr;
        int32_t shmflg;
        uintptr_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(shmid = " << shmid
               << ", shmaddr = " << std::format("0x{:x}", shmaddr)
               << ", shmflg = " << shmflg
               << ") -> " << std::format("0x{:x}", ret);
            return ss.str();
        }
    };

    class Shmdt : public Syscall {
    public:
        uintptr_t shmaddr;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "shmaddr = " << std::format("0x{:x}", shmaddr);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Socket : public Syscall {
    public:
        int32_t family;
        int32_t type;
        int32_t protocol;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "family = " << family << ", ";
            ss << "type = " << type << ", ";
            ss << "protocol = " << protocol;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Socketpair : public Syscall {
    public:
        int32_t family;
        int32_t type;
        int32_t protocol;
        uintptr_t usockvec;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "family = " << family << ", ";
            ss << "type = " << type << ", ";
            ss << "protocol = " << protocol << ", ";
            ss << "usockvec = " << std::format("0x{:x}", usockvec);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Bind : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr_p;
        struct sockaddr addr_buf;  // 存储地址信息
        int32_t addrlen;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            if (addr_p == 0) {
                ss << "addr = NULL, ";
            } else {
                ss << "addr = {sa_family = " << addr_buf.sa_family << ", sa_data = " << addr_buf.sa_data << "}, ";
            }
            ss << "addrlen = " << addrlen;
            ss << ") -> " << ret;
            if (addr_p != 0) {
                char *hex = new char[sizeof(struct sockaddr) * 2 + 1];
                char_to_hex((char *) &addr_buf, hex, sizeof(struct sockaddr));
                ss << "\n    -- addr_buf = hex2bytes(\"" << hex << "\")";
                delete[] hex;
                ss << "\n    -- addr_pointer = " << std::format("0x{:x}", addr_p);
            }
            return ss.str();
        }
    };

    class Listen : public Syscall {
    public:
        int32_t sockfd;
        int32_t backlog;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "backlog = " << backlog;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Accept : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr_p;
        struct sockaddr addr_buf;
        int32_t addrlen;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            if (addr_p == 0) {
                ss << "addr = NULL, ";
            } else {
                ss << "addr = {sa_family = " << addr_buf.sa_family << ", sa_data = " << addr_buf.sa_data << "}, ";
            }
            ss << "addrlen = " << addrlen;
            ss << ") -> " << ret;
            if (addr_p != 0) {
                char *hex = new char[sizeof(struct sockaddr) * 2 + 1];
                char_to_hex((char *) &addr_buf, hex, sizeof(struct sockaddr));
                ss << "\n    -- addr_buf = hex2bytes(\"" << hex << "\")";
                delete[] hex;
                ss << "\n    -- addr_pointer = " << std::format("0x{:x}", addr_p);
            }
            return ss.str();
        }
    };

    class Connect : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr_p;
        struct sockaddr addr_buf;
        int32_t addrlen;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            if (addr_p == 0) {
                ss << "addr = NULL, ";
            } else {
                ss << "addr = {sa_family = " << addr_buf.sa_family << ", sa_data = " << addr_buf.sa_data << "}, ";
            }
            ss << "addrlen = " << addrlen;
            ss << ") -> " << ret;
            if (addr_p != 0) {
                char *hex = new char[sizeof(struct sockaddr) * 2 + 1];
                char_to_hex((char *) &addr_buf, hex, sizeof(struct sockaddr));
                ss << "\n    -- addr_buf = hex2bytes(\"" << hex << "\")";
                delete[] hex;
                ss << "\n    -- addr_pointer = " << std::format("0x{:x}", addr_p);
            }
            return ss.str();
        }
    };

    class Getsockname : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr;      // 地址缓冲区的地址
        uintptr_t addrlen;   // 地址长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";  // 输出地址缓冲区的地址
            ss << "addrlen = " << addrlen;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Getpeername : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr;      // 对端套接字地址的缓冲区地址
        uintptr_t addrlen;   // 地址长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";  // 输出地址缓冲区的地址
            ss << "addrlen = " << addrlen;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Sendto : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t buff;              // 数据缓冲区地址
        uint32_t len;                // 数据长度
        int32_t flags;
        uintptr_t dest_addr;         // 目标地址的指针
        int32_t dest_addr_len;       // 目标地址长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "buff = " << std::format("0x{:x}", buff) << ", ";  // 输出缓冲区地址
            ss << "len = " << len << ", ";
            ss << "flags = " << flags << ", ";
            ss << "dest_addr = " << std::format("0x{:x}", dest_addr) << ", ";  // 输出目标地址
            ss << "dest_addr_len = " << dest_addr_len;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Recvfrom : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t buff;              // 数据缓冲区地址
        uint32_t len;                // 接收数据长度
        uint32_t flags;
        uintptr_t addr;              // 存储目标地址的指针
        uintptr_t addr_len;          // 存储目标地址长度的指针

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "buff = " << std::format("0x{:x}", buff) << ", ";  // 输出缓冲区地址
            ss << "len = " << len << ", ";
            ss << "flags = " << flags << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";  // 输出目标地址
            ss << "addr_len = " << addr_len;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Setsockopt : public Syscall {
    public:
        int32_t sockfd;
        int32_t level;
        int32_t optname;
        uintptr_t optval;             // 选项值地址
        uint32_t optlen;              // 选项长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "level = " << level << ", ";
            ss << "optname = " << optname << ", ";
            ss << "optval = " << std::format("0x{:x}", optval) << ", "; // 输出选项值地址
            ss << "optlen = " << optlen;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Getsockopt : public Syscall {
    public:
        int32_t sockfd;
        int32_t level;
        int32_t optname;
        uintptr_t optval;             // 选项值地址
        uintptr_t optlen;             // 选项值长度的地址

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "level = " << level << ", ";
            ss << "optname = " << optname << ", ";
            ss << "optval = " << std::format("0x{:x}", optval) << ", "; // 输出选项值地址
            ss << "optlen = " << std::format("0x{:x}", optlen);         // 输出选项值长度地址
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Shutdown : public Syscall {
    public:
        int32_t sockfd;
        int32_t how;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "how = " << how;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Sendmsg : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t msg;        // 消息的地址
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "msg = " << std::format("0x{:x}", msg) << ", ";  // 输出消息的地址
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Recvmsg : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t msg;        // 消息的地址
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "msg = " << std::format("0x{:x}", msg) << ", ";  // 输出消息的地址
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Readahead : public Syscall {
    public:
        int32_t fd;
        int64_t offset;
        uint32_t count;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "offset = " << offset << ", ";
            ss << "count = " << count;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Brk : public Syscall {
    public:
        uintptr_t addr;  // brk 地址

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "addr = " << std::format("0x{:x}", addr) << ")";
            ss << " -> " << ret;
            return ss.str();
        }
    };

    class Munmap : public Syscall {
    public:
        uintptr_t addr;  // 映射的地址
        uint32_t len;    // 映射的长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";
            ss << "len = " << len;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Mremap : public Syscall {
    public:
        uintptr_t old_addr;  // 原始地址
        uint32_t old_len;    // 原始长度
        uint32_t new_len;    // 新长度
        int32_t flags;       // 标志
        uintptr_t new_addr;  // 新地址

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "old_addr = " << std::format("0x{:x}", old_addr) << ", ";
            ss << "old_len = " << old_len << ", ";
            ss << "new_len = " << new_len << ", ";
            ss << "flags = " << flags << ", ";
            ss << "new_addr = " << std::format("0x{:x}", new_addr);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class AddKey : public Syscall {
    public:
        uintptr_t type;         // 类型
        uintptr_t description;  // 描述
        uintptr_t payload;      // 有效负载
        uint32_t plen;          // 有效负载长度
        uintptr_t keyring;      // 密钥环

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "type = " << std::format("0x{:x}", type) << ", ";
            ss << "description = " << std::format("0x{:x}", description) << ", ";
            ss << "payload = " << std::format("0x{:x}", payload) << ", ";
            ss << "plen = " << plen << ", ";
            ss << "keyring = " << std::format("0x{:x}", keyring);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class RequestKey : public Syscall {
    public:
        uintptr_t type;         // 类型
        uintptr_t description;  // 描述
        uintptr_t callout_info; // 调用信息
        uintptr_t dest_keyring; // 目标密钥环

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "type = " << std::format("0x{:x}", type) << ", ";
            ss << "description = " << std::format("0x{:x}", description) << ", ";
            ss << "callout_info = " << std::format("0x{:x}", callout_info) << ", ";
            ss << "dest_keyring = " << std::format("0x{:x}", dest_keyring);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Keyctl : public Syscall {
    public:
        int32_t operation;  // 操作
        uintptr_t arg2;     // 参数2
        uintptr_t arg3;     // 参数3
        uintptr_t arg4;     // 参数4
        uintptr_t arg5;     // 参数5

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "operation = " << operation << ", ";
            ss << "arg2 = " << std::format("0x{:x}", arg2) << ", ";
            ss << "arg3 = " << std::format("0x{:x}", arg3) << ", ";
            ss << "arg4 = " << std::format("0x{:x}", arg4) << ", ";
            ss << "arg5 = " << std::format("0x{:x}", arg5);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Clone : public Syscall {
    public:
        uintptr_t fn;           // 函数指针
        uintptr_t stack;        // 栈指针
        int32_t flags;          // 标志
        uintptr_t arg;          // 参数
        uintptr_t parent_tid;   // 父进程线程ID
        uintptr_t tls;          // TLS 指针
        uintptr_t child_tid;    // 子进程线程ID

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fn = " << std::format("0x{:x}", fn) << ", ";
            ss << "stack = " << std::format("0x{:x}", stack) << ", ";
            ss << "flags = " << flags << ", ";
            ss << "arg = " << std::format("0x{:x}", arg) << ", ";
            ss << "parent_tid = " << std::format("0x{:x}", parent_tid) << ", ";
            ss << "tls = " << std::format("0x{:x}", tls) << ", ";
            ss << "child_tid = " << std::format("0x{:x}", child_tid);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Execve: public Syscall {
    public:
        uintptr_t filename;  // 文件名
        uintptr_t argv;      // 参数
        uintptr_t envp;      // 环境变量
        std::string filename_buf;

        int argc = 0, envc = 0;

        std::vector<std::string> argv_buf;
        std::vector<std::string> envp_buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "filename = " << std::format("0x{:x}", filename) << ", ";
            ss << "argv = " << std::format("0x{:x}", argv) << ", ";
            ss << "envp = " << std::format("0x{:x}", envp);
            ss << ") -> " << ret;
            ss << "\n    -- filename = \"" << filename_buf << "\"";
            ss << "\n    -- argv = [";
            for (int i = 0; i < argc; i++) {
                ss << "\"" << argv_buf[i] << "\"";
                if (i != argc - 1) {
                    ss << ", ";
                }
            }
            ss << "]";
            ss << "\n    -- envp = [";
            for (int i = 0; i < envc; i++) {
                ss << "\"" << envp_buf[i] << "\"";
                if (i != envc - 1) {
                    ss << ", ";
                }
            }
            ss << "]";
            ss << "\n    -- argc = " << argc;
            ss << "\n    -- envc = " << envc;
            return ss.str();
        }
    };

    class Mmap : public Syscall {
    public:
        uintptr_t addr;    // 内存地址
        uint32_t len;      // 映射长度
        int32_t prot;      // 保护标志
        int32_t flags;     // 映射标志
        int32_t fd;        // 文件描述符
        int64_t offset;    // 偏移量

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";
            ss << "len = " << len << ", ";
            ss << "prot = " << prot << ", ";
            ss << "flags = " << flags << ", ";
            ss << "fd = " << fd << ", ";
            ss << "offset = " << offset;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fadvise64 : public Syscall {
    public:
        int32_t fd;        // 文件描述符
        int64_t offset;    // 偏移量
        uint32_t len;      // 长度
        int32_t advice;    // 建议
        int32_t ret;       // 返回值

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "offset = " << offset << ", ";
            ss << "len = " << len << ", ";
            ss << "advice = " << advice;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Swapon : public Syscall {
    public:
        uintptr_t specialfile;  // 特殊文件的地址
        int32_t swap_flags;     // 交换标志
        std::string path_buf;   // 路径字符串

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "specialfile = " << std::format("0x{:x}", specialfile) << ", ";
            ss << "swap_flags = " << swap_flags;
            if (!path_buf.empty()) {
                ss << ", path = " << path_buf;
            }
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Swapoff : public Syscall {
    public:
        uintptr_t specialfile;  // 特殊文件的地址
        std::string path_buf;   // 路径字符串

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "specialfile = " << std::format("0x{:x}", specialfile);
            if (!path_buf.empty()) {
                ss << ", path = " << path_buf;
            }
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mprotect : public Syscall {
    public:
        uintptr_t start;    // 内存起始地址
        uint32_t len;       // 内存长度
        uintptr_t prot;     // 保护标志

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "prot = " << std::format("0x{:x}", prot);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Msync : public Syscall {
    public:
        uintptr_t start;    // 内存起始地址
        uint32_t len;       // 内存长度
        int32_t flags;      // 同步标志
        int32_t ret;        // 返回值

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mlock : public Syscall {
    public:
        uintptr_t start;    // 内存起始地址
        uint32_t len;       // 内存长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Munlock : public Syscall {
    public:
        uintptr_t start;    // 内存起始地址
        uint32_t len;       // 内存长度

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mlockall : public Syscall {
    public:
        int32_t flags;  // 锁定内存的选项

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Munlockall : public Syscall {
    public:

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "() -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mincore : public Syscall {
    public:
        uintptr_t start;  // 起始地址
        uint32_t len;     // 长度
        uintptr_t vec;    // 存储访问情况的向量

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "vec = " << std::format("0x{:x}", vec);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Madvise : public Syscall {
    public:
        uintptr_t start;     // 起始地址
        uint32_t len;        // 长度
        int32_t behavior;    // 行为标志

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "behavior = " << behavior;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class RemapFilePages : public Syscall {
    public:
        uintptr_t start;     // 起始地址
        uintptr_t size;      // 大小
        uintptr_t prot;      // 保护标志
        uintptr_t pgoff;     // 页面偏移
        uintptr_t flags;     // 标志

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "size = " << size << ", ";
            ss << "prot = " << prot << ", ";
            ss << "pgoff = " << pgoff << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mbind : public Syscall {
    public:
        uintptr_t start;   // 起始地址
        uintptr_t len;     // 长度
        uintptr_t mode;    // 模式
        uintptr_t nmask;   // 节点掩码
        uintptr_t maxnode; // 最大节点数
        uint32_t flags;    // 标志

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "mode = " << mode << ", ";
            ss << "nmask = " << std::format("0x{:x}", nmask) << ", ";
            ss << "maxnode = " << maxnode << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SetMempolicy : public Syscall {
    public:
        int32_t mode;      // 模式
        uintptr_t nmask;   // 节点掩码
        uintptr_t maxnode; // 最大节点数

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "mode = " << mode << ", ";
            ss << "nmask = " << std::format("0x{:x}", nmask) << ", ";
            ss << "maxnode = " << maxnode;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class GetMempolicy : public Syscall {
    public:
        uintptr_t policy;
        uintptr_t nmask;
        uintptr_t maxnode;
        uintptr_t addr;
        uintptr_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "policy = " << std::format("0x{:x}", policy) << ", ";
            ss << "nmask = " << std::format("0x{:x}", nmask) << ", ";
            ss << "maxnode = " << std::format("0x{:x}", maxnode) << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";
            ss << "flags = " << std::format("0x{:x}", flags);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class MigratePages : public Syscall {
    public:
        int32_t pid;
        uintptr_t maxnode;
        uintptr_t old_nodes;
        uintptr_t new_nodes;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "maxnode = " << std::format("0x{:x}", maxnode) << ", ";
            ss << "old_nodes = " << std::format("0x{:x}", old_nodes) << ", ";
            ss << "new_nodes = " << std::format("0x{:x}", new_nodes);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class MovePages : public Syscall {
    public:
        int32_t pid;
        uintptr_t count;
        uintptr_t pages;
        uintptr_t nodes;
        uintptr_t status;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "count = " << count << ", ";
            ss << "pages = " << std::format("0x{:x}", pages) << ", ";
            ss << "nodes = " << std::format("0x{:x}", nodes) << ", ";
            ss << "status = " << std::format("0x{:x}", status) << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class RtTgsigqueueinfo : public Syscall {
    public:
        int32_t tgid;
        int32_t tid;
        int32_t sig;
        uintptr_t uinfo;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "tgid = " << tgid << ", ";
            ss << "tid = " << tid << ", ";
            ss << "sig = " << sig << ", ";
            ss << "uinfo = " << std::format("0x{:x}", uinfo);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class PerfEventOpen : public Syscall {
    public:
        uintptr_t attr_uptr;
        int32_t pid;
        int32_t cpu;
        int32_t group_fd;
        uint64_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "attr_uptr = " << std::format("0x{:x}", attr_uptr) << ", ";
            ss << "pid = " << pid << ", ";
            ss << "cpu = " << cpu << ", ";
            ss << "group_fd = " << group_fd << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Accept4 : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t addr;
        uintptr_t addrlen;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "addr = " << std::format("0x{:x}", addr) << ", ";
            ss << "addrlen = " << std::format("0x{:x}", addrlen) << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Recvmmsg : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t msgvec;
        uint32_t vlen;
        uint32_t flags;
        uintptr_t timeout;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "msgvec = " << std::format("0x{:x}", msgvec) << ", ";
            ss << "vlen = " << vlen << ", ";
            ss << "flags = " << flags << ", ";
            ss << "timeout = " << std::format("0x{:x}", timeout);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class ArchSpecificSyscall : public Syscall {
    public:
        uintptr_t arg1;
        uintptr_t arg2;
        uintptr_t arg3;
        uintptr_t arg4;
        uintptr_t arg5;
        uintptr_t arg6;
        int64_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "arg1 = " << std::format("0x{:x}", arg1) << ", ";
            ss << "arg2 = " << std::format("0x{:x}", arg2) << ", ";
            ss << "arg3 = " << std::format("0x{:x}", arg3) << ", ";
            ss << "arg4 = " << std::format("0x{:x}", arg4) << ", ";
            ss << "arg5 = " << std::format("0x{:x}", arg5) << ", ";
            ss << "arg6 = " << std::format("0x{:x}", arg6);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Wait4 : public Syscall {
    public:
        int32_t pid;
        uintptr_t wstatus;
        int32_t options;
        uintptr_t ru;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "wstatus = " << std::format("0x{:x}", wstatus) << ", ";
            ss << "options = " << options << ", ";
            ss << "ru = " << std::format("0x{:x}", ru);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Prlimit64 : public Syscall {
    public:
        int32_t pid;
        uint32_t resource;
        uintptr_t new_rlim;
        uintptr_t old_rlim;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "resource = " << resource << ", ";
            ss << "new_rlim = " << std::format("0x{:x}", new_rlim) << ", ";
            ss << "old_rlim = " << std::format("0x{:x}", old_rlim);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class FanotifyInit : public Syscall {
    public:
        uint32_t flags;
        uint32_t event_f_flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "flags = " << flags << ", ";
            ss << "event_f_flags = " << event_f_flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class FanotifyMark : public Syscall {
    public:
        int32_t fanotify_fd;
        uint32_t flags;
        uint64_t mask;
        int32_t dirfd;
        uintptr_t pathname;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fanotify_fd = " << fanotify_fd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "mask = " << mask << ", ";
            ss << "dirfd = " << dirfd << ", ";
            ss << "pathname = " << std::format("0x{:x}", pathname);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class NameToHandleAt : public Syscall {
    public:
        int32_t dfd;
        uintptr_t name;
        uintptr_t handle;
        uintptr_t mnt_id;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "name = " << std::format("0x{:x}", name) << ", ";
            ss << "handle = " << std::format("0x{:x}", handle) << ", ";
            ss << "mnt_id = " << std::format("0x{:x}", mnt_id) << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class OpenByHandleAt : public Syscall {
    public:
        int32_t dfd;
        uintptr_t handle;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "handle = " << std::format("0x{:x}", handle) << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class ClockAdjtime : public Syscall {
    public:
        int32_t which_clock;
        uintptr_t tx;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "which_clock = " << which_clock << ", ";
            ss << "tx = " << std::format("0x{:x}", tx);
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Syncfs : public Syscall {
    public:
        int32_t fd;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Setns : public Syscall {
    public:
        int32_t fd;
        int32_t nstype;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "nstype = " << nstype;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Sendmmsg : public Syscall {
    public:
        int32_t sockfd;
        uintptr_t msgvec;
        uint32_t vlen;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "sockfd = " << sockfd << ", ";
            ss << "msgvec = " << std::format("0x{:x}", msgvec) << ", ";
            ss << "vlen = " << vlen << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class ProcessVmReadv : public Syscall {
    public:
        int32_t pid;
        uintptr_t lvec;
        uint64_t liovcnt;
        uintptr_t rvec;
        uint64_t riovcnt;
        uint64_t flags;
        int64_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "lvec = " << std::format("0x{:x}", lvec) << ", ";
            ss << "liovcnt = " << liovcnt << ", ";
            ss << "rvec = " << std::format("0x{:x}", rvec) << ", ";
            ss << "riovcnt = " << riovcnt << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class ProcessVmWritev : public Syscall {
    public:
        int32_t pid;
        uintptr_t lvec;
        uint64_t liovcnt;
        uintptr_t rvec;
        uint64_t riovcnt;
        uint64_t flags;
        int64_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "lvec = " << std::format("0x{:x}", lvec) << ", ";
            ss << "liovcnt = " << liovcnt << ", ";
            ss << "rvec = " << std::format("0x{:x}", rvec) << ", ";
            ss << "riovcnt = " << riovcnt << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class Kcmp : public Syscall {
    public:
        int32_t pid1;
        int32_t pid2;
        int32_t type;
        uint64_t idx1;
        uint64_t idx2;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid1 = " << pid1 << ", ";
            ss << "pid2 = " << pid2 << ", ";
            ss << "type = " << type << ", ";
            ss << "idx1 = " << idx1 << ", ";
            ss << "idx2 = " << idx2;
            ss << ") -> " << ret;
            return ss.str();
        }
    };

    class FinitModule : public Syscall {
    public:
        int32_t fd;
        uintptr_t uargs;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "uargs = " << std::format("0x{:x}", uargs) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedSetattr : public Syscall {
    public:
        int32_t pid;
        uintptr_t attr;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "attr = " << std::format("0x{:x}", attr) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class SchedGetattr : public Syscall {
    public:
        int32_t pid;
        uintptr_t attr;
        uint32_t size;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "attr = " << std::format("0x{:x}", attr) << ", ";
            ss << "size = " << size << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Renameat2 : public Syscall {
    public:
        int32_t olddfd;
        uintptr_t oldname;
        int32_t newdfd;
        uintptr_t newname;
        uint32_t flags;
        std::string oldname_str;
        std::string newname_str;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "olddfd = " << olddfd << ", ";
            ss << "oldname = " << std::format("0x{:x}", oldname) << ", ";
            ss << "newdfd = " << newdfd << ", ";
            ss << "newname = " << std::format("0x{:x}", newname) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            ss << "\n    -- oldname = \"" << oldname_str << "\"";
            ss << "\n    -- newname = \"" << newname_str << "\"";
            return ss.str();
        }
    };

    class Seccomp : public Syscall {
    public:
        uint32_t op;
        uint32_t flags;
        uintptr_t uargs;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "op = " << op << ", ";
            ss << "flags = " << flags << ", ";
            ss << "uargs = " << std::format("0x{:x}", uargs);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Getrandom : public Syscall {
    public:
        uintptr_t buf;
        uint64_t buflen;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "buf = " << std::format("0x{:x}", buf) << ", ";
            ss << "buflen = " << buflen << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class MemfdCreate : public Syscall {
    public:
        uintptr_t uname;
        uint32_t flags;
        int32_t ret;
        std::string name;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "uname = " << std::format("0x{:x}", uname) << ", ";
            ss << "flags = " << flags;
            if (!name.empty()) {
                ss << ", name = " << name;
            }
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Bpf : public Syscall {
    public:
        int32_t cmd;
        uintptr_t attr;
        uint32_t size;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "cmd = " << cmd << ", ";
            ss << "attr = " << std::format("0x{:x}", attr) << ", ";
            ss << "size = " << size;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Execveat: public Syscall {
    public:
        int32_t dfd;
        uintptr_t filename;  // 文件名
        uintptr_t argv;      // 参数
        uintptr_t envp;      // 环境变量
        int32_t flags;
        std::string filename_buf;

        int argc = 0, envc = 0;

        std::vector<std::string> argv_buf;
        std::vector<std::string> envp_buf;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = " << std::format("0x{:x}", filename) << ", ";
            ss << "argv = " << std::format("0x{:x}", argv) << ", ";
            ss << "envp = " << std::format("0x{:x}", envp) << ", ";
            ss << "flags = " << flags;
            ss << ") -> " << ret;
            ss << "\n    -- filename = \"" << filename_buf << "\"";
            ss << "\n    -- argv = [";
            for (int i = 0; i < argc; i++) {
                ss << "\"" << argv_buf[i] << "\"";
                if (i != argc - 1) {
                    ss << ", ";
                }
            }
            ss << "]";
            ss << "\n    -- envp = [";
            for (int i = 0; i < envc; i++) {
                ss << "\"" << envp_buf[i] << "\"";
                if (i != envc - 1) {
                    ss << ", ";
                }
            }
            ss << "]";
            ss << "\n    -- argc = " << argc;
            ss << "\n    -- envc = " << envc;
            return ss.str();
        }
    };

    class Userfaultfd : public Syscall {
    public:
        int32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Membarrier : public Syscall {
    public:
        int32_t cmd;
        uint32_t flags;
        int32_t cpu_id;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "cmd = " << cmd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "cpu_id = " << cpu_id;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Mlock2 : public Syscall {
    public:
        uint64_t start;
        uint64_t len;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class CopyFileRange : public Syscall {
    public:
        int32_t fd_in;
        uintptr_t off_in;
        int32_t fd_out;
        uintptr_t off_out;
        uint64_t len;
        uint32_t flags;
        int64_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd_in = " << fd_in << ", ";
            ss << "off_in = " << std::format("0x{:x}", off_in) << ", ";
            ss << "fd_out = " << fd_out << ", ";
            ss << "off_out = " << std::format("0x{:x}", off_out) << ", ";
            ss << "len = " << len << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Preadv2 : public Syscall {
    public:
        int32_t fd;
        uintptr_t iov;
        int32_t iovcnt;
        int64_t offset;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "iov = " << std::format("0x{:x}", iov) << ", ";
            ss << "iovcnt = " << iovcnt << ", ";
            ss << "offset = " << offset << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Pwritev2 : public Syscall {
    public:
        int32_t fd;
        uintptr_t iov;
        int32_t iovcnt;
        int64_t offset;
        int32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "iov = " << std::format("0x{:x}", iov) << ", ";
            ss << "iovcnt = " << iovcnt << ", ";
            ss << "offset = " << offset << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PkeyMprotect : public Syscall {
    public:
        uintptr_t start;
        uintptr_t len;
        uintptr_t prot;
        int32_t pkey;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "start = " << std::format("0x{:x}", start) << ", ";
            ss << "len = " << len << ", ";
            ss << "prot = " << prot << ", ";
            ss << "pkey = " << pkey;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PkeyAlloc : public Syscall {
    public:
        uint32_t flags;
        uint32_t access_rights;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "flags = " << flags << ", ";
            ss << "access_rights = " << access_rights;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PkeyFree : public Syscall {
    public:
        int32_t pkey;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pkey = " << pkey;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Statx : public Syscall {
    public:
        int32_t dfd;
        uintptr_t path;
        uint32_t flags;
        uint32_t mask;
        uintptr_t buffer;
        std::string path_str;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "path = " << std::format("0x{:x}", path) << ", ";
            ss << "flags = " << flags << ", ";
            ss << "mask = " << mask << ", ";
            ss << "buffer = " << std::format("0x{:x}", buffer);
            ss << ") -> ";
            ss << ret;
            if (!path_str.empty()) {
                ss << ", path_str = " << path_str;
            }
            return ss.str();
        }
    };

    class IoPgetevents : public Syscall {
    public:
        uint64_t ctx_id;
        int64_t min_nr;
        int64_t nr;
        uintptr_t events;
        uintptr_t timeout;
        uintptr_t timespec;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "ctx_id = " << std::format("0x{:x}", ctx_id) << ", ";
            ss << "min_nr = " << min_nr << ", ";
            ss << "nr = " << nr << ", ";
            ss << "events = " << std::format("0x{:x}", events) << ", ";
            ss << "timeout = " << std::format("0x{:x}", timeout) << ", ";
            ss << "timespec = " << std::format("0x{:x}", timespec);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Rseq : public Syscall {
    public:
        uintptr_t rseq;
        uint32_t rseq_len;
        int32_t flags;
        int32_t sig;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "rseq = " << std::format("0x{:x}", rseq) << ", ";
            ss << "rseq_len = " << rseq_len << ", ";
            ss << "flags = " << flags << ", ";
            ss << "sig = " << sig;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class KexecFileLoad : public Syscall {
    public:
        int32_t kernel_fd;
        int32_t initrd_fd;
        uint64_t cmdline_len;
        uintptr_t cmdline;
        uint64_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "kernel_fd = " << kernel_fd << ", ";
            ss << "initrd_fd = " << initrd_fd << ", ";
            ss << "cmdline_len = " << cmdline_len << ", ";
            ss << "cmdline = " << std::format("0x{:x}", cmdline) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PidfdSendSignal : public Syscall {
    public:
        int32_t pidfd;
        int32_t sig;
        uintptr_t info;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pidfd = " << pidfd << ", ";
            ss << "sig = " << sig << ", ";
            ss << "info = " << std::format("0x{:x}", info) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoUringSetup : public Syscall {
    public:
        uint32_t entries;
        uintptr_t p;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "entries = " << entries << ", ";
            ss << "p = " << std::format("0x{:x}", p);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoUringEnter : public Syscall {
    public:
        uint32_t fd;
        uint32_t to_submit;
        uint32_t min_complete;
        uint32_t flags;
        uintptr_t sig;
        uint32_t sigsetsize;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "to_submit = " << to_submit << ", ";
            ss << "min_complete = " << min_complete << ", ";
            ss << "flags = " << flags << ", ";
            ss << "sig = " << std::format("0x{:x}", sig) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class IoUringRegister : public Syscall {
    public:
        uint32_t fd;
        uint32_t opcode;
        uintptr_t arg;
        uint32_t nr_args;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "opcode = " << opcode << ", ";
            ss << "arg = " << std::format("0x{:x}", arg) << ", ";
            ss << "nr_args = " << nr_args;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class OpenTree : public Syscall {
    public:
        int32_t dfd;
        uintptr_t filename;
        uint32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = " << std::format("0x{:x}", filename) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class MoveMount : public Syscall {
    public:
        int32_t from_dfd;
        uintptr_t from_pathname;
        int32_t to_dfd;
        uintptr_t to_pathname;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "from_dfd = " << from_dfd << ", ";
            ss << "from_pathname = " << std::format("0x{:x}", from_pathname) << ", ";
            ss << "to_dfd = " << to_dfd << ", ";
            ss << "to_pathname = " << std::format("0x{:x}", to_pathname) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fsopen : public Syscall {
    public:
        uintptr_t fs_name;
        uint32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fs_name = " << std::format("0x{:x}", fs_name) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fsconfig : public Syscall {
    public:
        int32_t fs_fd;
        uint32_t cmd;
        uintptr_t key;
        uintptr_t value;
        uint32_t aux;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fs_fd = " << fs_fd << ", ";
            ss << "cmd = " << cmd << ", ";
            ss << "key = " << std::format("0x{:x}", key) << ", ";
            ss << "value = " << std::format("0x{:x}", value) << ", ";
            ss << "aux = " << aux;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fsmount : public Syscall {
    public:
        int32_t fs_fd;
        uint32_t flags;
        uint32_t ms_flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fs_fd = " << fs_fd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "ms_flags = " << ms_flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Fspick : public Syscall {
    public:
        int32_t dfd;
        uintptr_t path;
        uint32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "path = " << std::format("0x{:x}", path) << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PidfdOpen : public Syscall {
    public:
        int32_t pid;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pid = " << pid << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Clone3 : public Syscall {
    public:
        uintptr_t uargs;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "uargs = " << std::format("0x{:x}", uargs);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class CloseRange : public Syscall {
    public:
        uint32_t fd;
        uint32_t max_fd;
        uint32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "fd = " << fd << ", ";
            ss << "max_fd = " << max_fd << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Openat2 : public Syscall {
    public:
        int32_t dfd;
        uintptr_t filename;
        uintptr_t how;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = " << std::format("0x{:x}", filename) << ", ";
            ss << "how = " << std::format("0x{:x}", how);
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class PidfdGetfd : public Syscall {
    public:
        int32_t pidfd;
        int32_t fd;
        uint32_t flags;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pidfd = " << pidfd << ", ";
            ss << "fd = " << fd << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class Faccessat2 : public Syscall {
    public:
        int32_t dfd;
        uintptr_t filename;
        int32_t mode;
        int32_t flags;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "dfd = " << dfd << ", ";
            ss << "filename = " << std::format("0x{:x}", filename) << ", ";
            ss << "mode = " << mode << ", ";
            ss << "flags = " << flags;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class ProcessMadvise : public Syscall {
    public:
        int32_t pidfd;
        uint32_t flags;
        uint32_t advice;
        int32_t ret;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "pidfd = " << pidfd << ", ";
            ss << "flags = " << flags << ", ";
            ss << "advice = " << advice;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

    class EpollPwait2 : public Syscall {
    public:
        int32_t epfd;
        uintptr_t events;
        int32_t maxevents;
        int32_t timeout;
        uintptr_t sigmask;
        uint32_t sigsetsize;

        virtual std::string toLogString() override {
            std::stringstream ss;
            ss << syscallName << "(";
            ss << "epfd = " << epfd << ", ";
            ss << "events = " << std::format("0x{:x}", events) << ", ";
            ss << "maxevents = " << maxevents << ", ";
            ss << "timeout = " << timeout << ", ";
            ss << "sigmask = " << std::format("0x{:x}", sigmask) << ", ";
            ss << "sigsetsize = " << sigsetsize;
            ss << ") -> ";
            ss << ret;
            return ss.str();
        }
    };

}

#endif //TRS_SYSCALLS_H
