//
// Created by 13723 on 24-12-22.
//
#include "Parser.h"

#include <iostream>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <vector>

using namespace trs::parser;

#define PARSER(name) { #name, parse_##name }

#define PARSE_REFERER(fnla, name) { \
    int32_t pid;                    \
    uint32_t uid;                   \
    fnla_get_s32(fnla, &pid);       \
    fnla_get_u32(fnla, &uid);       \
    name->pid = pid;                \
    name->uid = uid;                \
}

auto parse_io_setup(fnla_t fnla) {
    auto rt = std::make_unique<IoSetup>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_setup";
    NLA_GET_U32(fnla, nr_events)
    rt->nr_events = nr_events;
    NLA_GET_U64(fnla, ctxp)
    rt->ctxp = ctxp;
    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_io_destroy(fnla_t fnla) {
    auto rt = std::make_unique<IoDestroy>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_destroy";
    NLA_GET_U64(fnla, ctx);
    rt->ctx = ctx;
    NLA_GET_S32(fnla, ret);
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_io_submit(fnla_t fnla) {
    auto rt = std::make_unique<IoSubmit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_submit";
    NLA_GET_U64(fnla, ctx)
    rt->ctx = ctx;
    NLA_GET_U64(fnla, nr)
    rt->nr = nr;
    NLA_GET_U64(fnla, iocbpp)
    rt->iocbpp = iocbpp;
    for (int i = 0; i < nr; ++i) {
        NLA_GET_U32(fnla, status);
        if (status != 0) {
            rt->iocbs.push_back({0, {}});
            continue;
        }
        struct iocb iocb;
        NLA_GET_U64(fnla, iocb_ptr)
        NLA_GET_U64(fnla, aio_data)
        NLA_GET_U32(fnla, aio_lio_opcode)
        NLA_GET_S32(fnla, aio_reqprio)
        NLA_GET_U32(fnla, aio_fildes)
        NLA_GET_U64(fnla, aio_buf)
        NLA_GET_U64(fnla, aio_nbytes)
        NLA_GET_S64(fnla, aio_offset)
        NLA_GET_U64(fnla, aio_reserved2)
        NLA_GET_U32(fnla, aio_flags)
        NLA_GET_U32(fnla, aio_resfd)
        iocb.aio_data = aio_data;
        iocb.aio_lio_opcode = aio_lio_opcode;
        iocb.aio_reqprio = aio_reqprio;
        iocb.aio_fildes = aio_fildes;
        iocb.aio_buf = aio_buf;
        iocb.aio_nbytes = aio_nbytes;
        iocb.aio_offset = aio_offset;
        iocb.aio_reserved2 = aio_reserved2;
        iocb.aio_flags = aio_flags;
        iocb.aio_resfd = aio_resfd;
        rt->iocbs.push_back({iocb_ptr, iocb});
    }
    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_io_cancel(fnla_t fnla) {
    auto rt = std::make_unique<IoCancel>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_cancel";
    NLA_GET_U64(fnla, ctx)
    rt->ctx = ctx;
    NLA_GET_U64(fnla, iocb_ptr)
    rt->iocb_ptr = iocb_ptr;
    NLA_GET_U64(fnla, result)
    rt->result = result;
    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_io_getevents(fnla_t fnla) {
    auto rt = std::make_unique<IoGetEvents>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_getevents";
    NLA_GET_U64(fnla, ctx)
    rt->ctx = ctx;
    NLA_GET_S64(fnla, min_nr)
    rt->min_nr = min_nr;
    NLA_GET_U64(fnla, nr)
    rt->nr = nr;
    NLA_GET_U64(fnla, events)
    rt->events = events;
    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;
    NLA_GET_S64(fnla, sec)
    rt->sec = sec;
    NLA_GET_S64(fnla, nsec)
    rt->nsec = nsec;
    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_setxattr(fnla_t fnla) {
    auto rt = std::make_unique<Setxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setxattr";

    NLA_GET_U64(fnla, path_pointer)
    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    if (path_pointer == 0) {
        rt->path = "NULL";
    } else {
        rt->path = "\"" + std::string(path, path_len) + "\"";
    }
    delete[] path;


    NLA_GET_U64(fnla, name_pointer)
    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    if (name_pointer == 0) {
        rt->name = "NULL";
    } else {
        rt->name = "\"" + std::string(name, name_len) + "\"";
    }
    delete[] name;


    NLA_GET_U64(fnla, value_pointer)
    rt->value_p = value_pointer;
    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_lsetxattr(fnla_t fnla) {
    auto rt = std::make_unique<Lsetxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "lsetxattr";

    NLA_GET_U64(fnla, path_pointer)
    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    if(path_pointer == 0) {
        rt->path = "NULL";
    } else {
        rt->path = "\"" + std::string(path, path_len) + "\"";
    }
    delete[] path;

    NLA_GET_U64(fnla, name_pointer)
    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    if(name_pointer == 0) {
        rt->name = "NULL";
    } else {
        rt->name = "\"" + std::string(name, name_len) + "\"";
    }
    delete[] name;

    NLA_GET_U64(fnla, value_pointer)
    rt->value_p = value_pointer;
    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fsetxattr(fnla_t fnla) {
    auto rt = std::make_unique<Fsetxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fsetxattr";


    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, name_pointer)
    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    if(name_pointer == 0) {
        rt->name = "NULL";
    } else {
        rt->name = "\"" + std::string(name, name_len) + "\"";
    }
    delete[] name;


    NLA_GET_U64(fnla, value_pointer)
    rt->value_p = value_pointer;
    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;


    NLA_GET_S32(fnla, flags)
    rt->flags = flags;


    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_getxattr(fnla_t fnla) {
    auto rt = std::make_unique<Getxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getxattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_U64(fnla, p_value)
    rt->p_value = p_value;

    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_lgetxattr(fnla_t fnla) {
    auto rt = std::make_unique<Lgetxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "lgetxattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_U64(fnla, p_value)
    rt->p_value = p_value;

    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fgetxattr(fnla_t fnla) {
    auto rt = std::make_unique<Fgetxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fgetxattr";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_U64(fnla, p_value)
    rt->p_value = p_value;

    NLA_GET_U32(fnla, value_len)
    char* value = new char[value_len];
    fnla_get_bytes(fnla, value, value_len);
    rt->value = std::vector<uint8_t>(value, value + value_len);
    delete[] value;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_listxattr(fnla_t fnla) {
    auto rt = std::make_unique<Listxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "listxattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, list_p)
    rt->list = list_p;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    if (size != 0 && list_p != 0 && ret > 0) {
        NLA_GET_U32(fnla, list_len)
        char* list = new char[list_len];
        fnla_get_bytes(fnla, list, list_len);
        for (int i = 0; i < list_len; ++i) {
            std::string name;
            while (i < list_len && list[i] != '\0') {
                name.push_back(list[i]);
                i++;
            }
            rt->names.push_back(name);
        }
        delete[] list;
    }

    rt->finished = true;
    return rt;
}

auto parse_llistxattr(fnla_t fnla) {
    auto rt = std::make_unique<Llistxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "llistxattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, list_p)
    rt->list = list_p;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    if (size != 0 && list_p != 0 && ret > 0) {
        NLA_GET_U32(fnla, list_len)
        char* list = new char[list_len];
        fnla_get_bytes(fnla, list, list_len);
        for (int i = 0; i < list_len; ++i) {
            std::string name;
            while (i < list_len && list[i] != '\0') {
                name.push_back(list[i]);
                i++;
            }
            rt->names.push_back(name);
        }
        delete[] list;
    }

    rt->finished = true;
    return rt;
}

auto parse_flistxattr(fnla_t fnla) {
    auto rt = std::make_unique<Flistxattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "flistxattr";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, list_p)
    rt->list = list_p;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    if (size != 0 && list_p != 0 && ret > 0) {
        NLA_GET_U32(fnla, list_len)
        char* list = new char[list_len];
        fnla_get_bytes(fnla, list, list_len);
        for (int i = 0; i < list_len; ++i) {
            std::string name;
            while (i < list_len && list[i] != '\0') {
                name.push_back(list[i]);
                i++;
            }
            rt->names.push_back(name);
        }
        delete[] list;
    }

    rt->finished = true;
    return rt;
}

auto parse_removexattr(fnla_t fnla) {
    auto rt = std::make_unique<Removexattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "removexattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_lremovexattr(fnla_t fnla) {
    auto rt = std::make_unique<Lremovexattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "lremovexattr";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fremovexattr(fnla_t fnla) {
    auto rt = std::make_unique<Fremovexattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fremovexattr";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, name_len)
    char* name = new char[name_len];
    fnla_get_bytes(fnla, name, name_len);
    rt->name = std::string(name, name_len);
    delete[] name;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getcwd(fnla_t fnla) {
    auto rt = std::make_unique<Getcwd>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getcwd";

    NLA_GET_U32(fnla, status)
    if (status == 0) {
        NLA_GET_U64(fnla, ret_p)
        NLA_GET_U32(fnla, cwd_len)
        char* cwd = new char[cwd_len];
        fnla_get_bytes(fnla, cwd, cwd_len);
        rt->cwd = std::string(cwd, cwd_len);
        delete[] cwd;
        rt->ret = ret_p;
        rt->buf = 0;
        rt->size = 0;
    } else if (status == 1) {
        NLA_GET_U64(fnla, buf)
        NLA_GET_U64(fnla, size)
        rt->size = size;
        NLA_GET_U32(fnla, cwd_len)
        char* cwd = new char[cwd_len];
        fnla_get_bytes(fnla, cwd, cwd_len);
        rt->cwd = std::string(cwd, cwd_len);
        delete[] cwd;
        NLA_GET_U64(fnla, ret)
        rt->ret = ret;
    } else {
        NLA_GET_U64(fnla, buf)
        NLA_GET_U64(fnla, size)
        NLA_GET_U64(fnla, ret)
        rt->buf = buf;
        rt->size = size;
        rt->ret = ret;
    }

    rt->finished = true;
    return rt;
}

auto parse_lookup_dcookie(fnla_t fnla) {
    auto rt = std::make_unique<LookupDcookie>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "lookup_dcookie";

    NLA_GET_U64(fnla, cookie)
    rt->cookie = cookie;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_eventfd(fnla_t fnla) {
    auto rt = std::make_unique<EventFd>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "eventfd";

    NLA_GET_U32(fnla, initval)
    rt->initval = initval;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_eventfd2(fnla_t fnla) {
    auto rt = std::make_unique<EventFd2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "eventfd2";

    NLA_GET_U32(fnla, initval)
    rt->initval = initval;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_epoll_create(fnla_t fnla) {
    auto rt = std::make_unique<EpollCreate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_create";

    NLA_GET_S32(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_epoll_create1(fnla_t fnla) {
    auto rt = std::make_unique<EpollCreate1>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_create1";

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, size)
    rt->size = size;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_epoll_ctl(fnla_t fnla) {
    auto rt = std::make_unique<EpollCtl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_ctl";

    NLA_GET_S32(fnla, epfd)
    rt->epfd = epfd;

    NLA_GET_S32(fnla, op)
    rt->op = op;

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, event_p)
    rt->event_p = event_p;

    if (event_p != 0) {
        NLA_GET_U32(fnla, events)
        rt->event.events = events;

        NLA_GET_U64(fnla, data)
        rt->event.data.u64 = data;
    }

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_epoll_wait(fnla_t fnla) {
    auto rt = std::make_unique<EpollWait>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_wait";

    NLA_GET_S32(fnla, epfd)
    rt->epfd = epfd;

    NLA_GET_U64(fnla, events)
    rt->events = events;

    NLA_GET_S32(fnla, maxevents)
    rt->maxevents = maxevents;

    NLA_GET_S32(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (ret > 0) {
        for (int i = 0; i < ret; ++i) {
            struct epoll_event event;
            NLA_GET_U32(fnla, evs)
            event.events = evs;
            NLA_GET_U64(fnla, data)
            event.data.u64 = data;
            rt->events_value.push_back(event);
        }
    }

    rt->finished = true;
    return rt;
}

auto parse_epoll_pwait(fnla_t fnla) {
    auto rt = std::make_unique<EpollPwait>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_pwait";

    NLA_GET_S32(fnla, epfd)
    rt->epfd = epfd;

    NLA_GET_U64(fnla, events)
    rt->events = events;

    NLA_GET_S32(fnla, maxevents)
    rt->maxevents = maxevents;

    NLA_GET_S32(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_U64(fnla, sigmask_p)
    rt->sigmask_p = sigmask_p;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (ret > 0) {
        for (int i = 0; i < ret; ++i) {
            struct epoll_event event;
            NLA_GET_U32(fnla, evs)
            event.events = evs;
            NLA_GET_U64(fnla, data)
            event.data.u64 = data;
            rt->events_value.push_back(event);
        }
    }

//    if(sigmask_p != 0) {
//        sigset_t sig;
//        fnla_get_bytes(fnla, (char*)&sig, sizeof(sigset_t));
//        rt->sigmask = sig;
//    }

    rt->finished = true;
    return rt;
}

auto parse_dup(fnla_t fnla) {
    auto rt = std::make_unique<Dup>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "dup";

    NLA_GET_S32(fnla, oldfd)
    rt->oldfd = oldfd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_dup2(fnla_t fnla) {
    auto rt = std::make_unique<Dup2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "dup2";

    NLA_GET_S32(fnla, oldfd)
    rt->oldfd = oldfd;

    NLA_GET_S32(fnla, newfd)
    rt->newfd = newfd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_dup3(fnla_t fnla) {
    auto rt = std::make_unique<Dup3>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "dup3";

    NLA_GET_S32(fnla, oldfd)
    rt->oldfd = oldfd;

    NLA_GET_S32(fnla, newfd)
    rt->newfd = newfd;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fnctl(fnla_t fnla) {
    auto rt = std::make_unique<Fnctl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fnctl";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_inotify_init(fnla_t fnla) {
    auto rt = std::make_unique<InotifyInit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "inotify_init";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_inotify_init1(fnla_t fnla) {
    auto rt = std::make_unique<InotifyInit1>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "inotify_init1";

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_inotify_add_watch(fnla_t fnla) {
    auto rt = std::make_unique<InotifyAddWatch>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "inotify_add_watch";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, mask)
    rt->mask = mask;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_inotify_rm_watch(fnla_t fnla) {
    auto rt = std::make_unique<InotifyRmWatch>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "inotify_rm_watch";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, wd)
    rt->wd = wd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ioctl(fnla_t fnla) {
    auto rt = std::make_unique<Ioctl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ioctl";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, request)
    rt->request = request;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ioprio_set(fnla_t fnla) {
    auto rt = std::make_unique<IoprioSet>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ioprio_set";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_S32(fnla, who)
    rt->who = who;

    NLA_GET_S32(fnla, ioprio)
    rt->ioprio = ioprio;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ioprio_get(fnla_t fnla) {
    auto rt = std::make_unique<IoprioGet>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ioprio_get";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_S32(fnla, who)
    rt->who = who;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_flock(fnla_t fnla) {
    auto rt = std::make_unique<Flock>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "flock";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, operation)
    rt->operation = operation;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mknodat(fnla_t fnla) {
    auto rt = std::make_unique<Mknodat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mknodat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, mode)
    rt->mode = mode;

    NLA_GET_U64(fnla, dev)
    rt->dev = dev;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mkdirat(fnla_t fnla) {
    auto rt = std::make_unique<Mkdirat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mkdirat";
    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;
    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;
    NLA_GET_U32(fnla, mode)
    rt->mode = mode;
    NLA_GET_S32(fnla, ret)
    rt->ret = ret;
    rt->finished = true;
    return rt;
}

auto parse_unlinkat(fnla_t fnla) {
    auto rt = std::make_unique<Unlinkat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "unlinkat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_symlinkat(fnla_t fnla) {
    auto rt = std::make_unique<Symlinkat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "symlinkat";

    NLA_GET_U32(fnla, oldname_len)
    char* oldname = new char[oldname_len];
    fnla_get_bytes(fnla, oldname, oldname_len);
    rt->oldname = std::string(oldname, oldname_len);
    delete[] oldname;

    NLA_GET_S32(fnla, newdfd)
    rt->newdfd = newdfd;

    NLA_GET_U32(fnla, newname_len)
    char* newname = new char[newname_len];
    fnla_get_bytes(fnla, newname, newname_len);
    rt->newname = std::string(newname, newname_len);
    delete[] newname;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_linkat(fnla_t fnla) {
    auto rt = std::make_unique<Linkat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "linkat";

    NLA_GET_S32(fnla, olddfd)
    rt->olddfd = olddfd;

    NLA_GET_U32(fnla, oldname_len)
    char* oldname = new char[oldname_len];
    fnla_get_bytes(fnla, oldname, oldname_len);
    rt->oldpath = std::string(oldname, oldname_len);
    delete[] oldname;

    NLA_GET_S32(fnla, newdfd)
    rt->newdfd = newdfd;

    NLA_GET_U32(fnla, newname_len)
    char* newname = new char[newname_len];
    fnla_get_bytes(fnla, newname, newname_len);
    rt->newpath = std::string(newname, newname_len);
    delete[] newname;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_renameat(fnla_t fnla) {
    auto rt = std::make_unique<Renameat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "renameat";

    NLA_GET_S32(fnla, olddfd)
    rt->olddfd = olddfd;

    NLA_GET_U32(fnla, oldname_len)
    char* oldname = new char[oldname_len];
    fnla_get_bytes(fnla, oldname, oldname_len);
    rt->oldpath = std::string(oldname, oldname_len);
    delete[] oldname;

    NLA_GET_S32(fnla, newdfd)
    rt->newdfd = newdfd;

    NLA_GET_U32(fnla, newname_len)
    char* newname = new char[newname_len];
    fnla_get_bytes(fnla, newname, newname_len);
    rt->newpath = std::string(newname, newname_len);
    delete[] newname;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_umount2(fnla_t fnla) {
    auto rt = std::make_unique<Umount2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "umount2";

    NLA_GET_U32(fnla, target_len)
    char* target = new char[target_len];
    fnla_get_bytes(fnla, target, target_len);
    rt->target = std::string(target, target_len);
    delete[] target;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mount(fnla_t fnla) {
    auto rt = std::make_unique<Mount>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mount";

    NLA_GET_U32(fnla, dev_name_len)
    char* dev_name = new char[dev_name_len];
    fnla_get_bytes(fnla, dev_name, dev_name_len);
    rt->dev = std::string(dev_name, dev_name_len);
    delete[] dev_name;

    NLA_GET_U32(fnla, dir_name_len)
    char* dir_name = new char[dir_name_len];
    fnla_get_bytes(fnla, dir_name, dir_name_len);
    rt->dir = std::string(dir_name, dir_name_len);
    delete[] dir_name;

    NLA_GET_U32(fnla, type_len)
    char* type = new char[type_len];
    fnla_get_bytes(fnla, type, type_len);
    rt->type = std::string(type, type_len);
    delete[] type;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, data)
    rt->data = data;

    rt->finished = true;
    return rt;
}

auto parse_privot_root(fnla_t fnla) {
    auto rt = std::make_unique<PrivotRoot>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "privot_root";

    NLA_GET_U32(fnla, new_root_len)
    char* new_root = new char[new_root_len];
    fnla_get_bytes(fnla, new_root, new_root_len);
    rt->new_root = std::string(new_root, new_root_len);
    delete[] new_root;

    NLA_GET_U32(fnla, put_old_len)
    char* put_old = new char[put_old_len];
    fnla_get_bytes(fnla, put_old, put_old_len);
    rt->put_old = std::string(put_old, put_old_len);
    delete[] put_old;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_nfsservctl(fnla_t fnla) {
    auto rt = std::make_unique<Nfsservctl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "nfsservctl";

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, argp)
    rt->argp = argp;

    NLA_GET_U64(fnla, resp)
    rt->resp = resp;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_statfs(fnla_t fnla) {
    auto rt = std::make_unique<Statfs>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "statfs";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fstatfs(fnla_t fnla) {
    auto rt = std::make_unique<Fstatfs>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fstatfs";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_truncate(fnla_t fnla) {
    auto rt = std::make_unique<Truncate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "truncate";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, length)
    rt->length = length;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ftruncate(fnla_t fnla) {
    auto rt = std::make_unique<Ftruncate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ftruncate";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, length)
    rt->length = length;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fallocate(fnla_t fnla) {
    auto rt = std::make_unique<Fallocate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fallocate";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, mode)
    rt->mode = mode;

    NLA_GET_U64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_faccessat(fnla_t fnla) {
    auto rt = std::make_unique<Faccessat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "faccessat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_S32(fnla, mode)
    rt->mode = mode;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_chdir(fnla_t fnla) {
    auto rt = std::make_unique<Chdir>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "chdir";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fchdir(fnla_t fnla) {
    auto rt = std::make_unique<Fchdir>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fchdir";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_chroot(fnla_t fnla) {
    auto rt = std::make_unique<Chroot>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "chroot";

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fchmod(fnla_t fnla) {
    auto rt = std::make_unique<Fchmod>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fchmod";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, mode)
    rt->mode = mode;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fchmodat(fnla_t fnla) {
    auto rt = std::make_unique<Fchmodat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fchmodat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, mode)
    rt->mode = mode;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fchown(fnla_t fnla) {
    auto rt = std::make_unique<Fchown>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fchown";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, owner)
    rt->uid = owner;

    NLA_GET_U32(fnla, group)
    rt->gid = group;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fchownat(fnla_t fnla) {
    auto rt = std::make_unique<Fchownat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fchownat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U32(fnla, owner)
    rt->uid = owner;

    NLA_GET_U32(fnla, group)
    rt->gid = group;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_openat(fnla_t fnla) {
    auto rt = std::make_unique<Openat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "openat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, mode)
    rt->mode = mode;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_close(fnla_t fnla) {
    auto rt = std::make_unique<Close>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "close";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_vhangup(fnla_t fnla) {
    auto rt = std::make_unique<Vhangup>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "vhangup";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pipe2(fnla_t fnla) {
    auto rt = std::make_unique<Pipe2>();
    PARSE_REFERER(fnla, rt)

    rt->syscallName = "pipe2";

    NLA_GET_S32(fnla, fildes_buf0)
    rt->pipefd[0] = fildes_buf0;

    NLA_GET_S32(fnla, fildes_buf1)
    rt->pipefd[1] = fildes_buf1;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_quotactl(fnla_t fnla) {
    auto rt = std::make_unique<Quotactl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "quotactl";

    NLA_GET_U32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U32(fnla, special_len)
    char* special = new char[special_len];
    fnla_get_bytes(fnla, special, special_len);
    rt->special = std::string(special, special_len);
    delete[] special;

    NLA_GET_S32(fnla, id)
    rt->id = id;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getdents64(fnla_t fnla) {
    auto rt = std::make_unique<Getdents64>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getdents64";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, dirent)
    rt->dirp = dirent;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_lseek(fnla_t fnla) {
    auto rt = std::make_unique<Lseek>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "lseek";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U32(fnla, whence)
    rt->whence = whence;

    NLA_GET_U64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_read(fnla_t fnla) {
    auto rt = std::make_unique<Read>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "read";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_write(fnla_t fnla) {
    auto rt = std::make_unique<Write>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "write";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_readv(fnla_t fnla) {
    auto rt = std::make_unique<Readv>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "readv";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, vec)
    rt->iov = vec;

    NLA_GET_U32(fnla, vlen)
    rt->iovcnt = vlen;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_writev(fnla_t fnla) {
    auto rt = std::make_unique<Writev>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "writev";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, vec)
    rt->iov = vec;

    NLA_GET_U32(fnla, vlen)
    rt->iovcnt = vlen;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pread64(fnla_t fnla) {
    auto rt = std::make_unique<Pread64>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pread64";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_U64(fnla, pos)
    rt->pos = pos;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pwrite64(fnla_t fnla) {
    auto rt = std::make_unique<Pwrite64>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pwrite64";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_U64(fnla, pos)
    rt->pos = pos;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_preadv(fnla_t fnla) {
    auto rt = std::make_unique<Preadv>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "preadv";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, vec)
    rt->iov = vec;

    NLA_GET_U32(fnla, vlen)
    rt->iovcnt = vlen;

    NLA_GET_U64(fnla, pos)
    rt->pos = pos;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pwritev(fnla_t fnla) {
    auto rt = std::make_unique<Pwritev>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pwritev";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, vec)
    rt->iov = vec;

    NLA_GET_U32(fnla, vlen)
    rt->iovcnt = vlen;

    NLA_GET_U64(fnla, pos)
    rt->pos = pos;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sendfile(fnla_t fnla) {
    auto rt = std::make_unique<Sendfile>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sendfile";

    NLA_GET_S32(fnla, out_fd)
    rt->out_fd = out_fd;

    NLA_GET_S32(fnla, in_fd)
    rt->in_fd = in_fd;

    NLA_GET_U64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pselect6(fnla_t fnla) {
    auto rt = std::make_unique<Pselect6>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pselect6";

    NLA_GET_S32(fnla, nfds)
    rt->nfds = nfds;

    NLA_GET_U64(fnla, readfds)
    rt->readfds = readfds;

    NLA_GET_U64(fnla, writefds)
    rt->writefds = writefds;

    NLA_GET_U64(fnla, exceptfds)
    rt->exceptfds = exceptfds;

    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_U64(fnla, sigmask)
    rt->sigmask = sigmask;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ppoll(fnla_t fnla) {
    auto rt = std::make_unique<Ppoll>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ppoll";

    NLA_GET_U64(fnla, fds)
    rt->fds = fds;

    NLA_GET_U32(fnla, nfds)
    rt->nfds = nfds;

    NLA_GET_U64(fnla, timeout)
    rt->timeout_ts = timeout;

    NLA_GET_U64(fnla, sigmask)
    rt->sigmask = sigmask;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_signalfd4(fnla_t fnla) {
    auto rt = std::make_unique<Signalfd4>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "signalfd4";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, mask)
    rt->mask = mask;

    NLA_GET_U32(fnla, size)
    rt->size = size;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_vmsplice(fnla_t fnla) {
    auto rt = std::make_unique<Vmsplice>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "vmsplice";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, iov)
    rt->iov = iov;

    NLA_GET_U32(fnla, nr_segs)
    rt->nr_segs = nr_segs;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_splice(fnla_t fnla) {
    auto rt = std::make_unique<SpliceClient>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "splice";

    NLA_GET_S32(fnla, fd_in)
    rt->fd_in = fd_in;

    NLA_GET_U64(fnla, off_in)
    rt->off_in = off_in;

    NLA_GET_S32(fnla, fd_out)
    rt->fd_out = fd_out;

    NLA_GET_U64(fnla, off_out)
    rt->off_out = off_out;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_tee(fnla_t fnla) {
    auto rt = std::make_unique<TeeClient>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "tee";

    NLA_GET_S32(fnla, fdin)
    rt->fdin = fdin;

    NLA_GET_S32(fnla, fdout)
    rt->fdout = fdout;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_readlinkat(fnla_t fnla) {
    auto rt = std::make_unique<Readlinkat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "readlinkat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->path = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, bufsiz)
    rt->bufsiz = bufsiz;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fstatat(fnla_t fnla) {
    auto rt = std::make_unique<Fstatat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fstatat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, filename_len)
    char* filename = new char[filename_len];
    fnla_get_bytes(fnla, filename, filename_len);
    rt->filename = std::string(filename, filename_len);
    delete[] filename;

    NLA_GET_U64(fnla, statbuf)
    rt->statbuf = statbuf;

    NLA_GET_S32(fnla, flag)
    rt->flag = flag;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fstat(fnla_t fnla) {
    auto rt = std::make_unique<Fstat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fstat";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, statbuf)
    rt->statbuf = statbuf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sync(fnla_t fnla) {
    auto rt = std::make_unique<Sync>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sync";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fsync(fnla_t fnla) {
    auto rt = std::make_unique<Fsync>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fsync";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fdatasync(fnla_t fnla) {
    auto rt = std::make_unique<Fdatasync>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fdatasync";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sync_file_range2(fnla_t fnla) {
    auto rt = std::make_unique<SyncFileRange2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sync_file_range2";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U64(fnla, nbytes)
    rt->nbytes = nbytes;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sync_file_range(fnla_t fnla) {
    auto rt = std::make_unique<SyncFileRange>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sync_file_range";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U64(fnla, nbytes)
    rt->nbytes = nbytes;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timerfd_create(fnla_t fnla) {
    auto rt = std::make_unique<TimerfdCreate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timerfd_create";

    NLA_GET_S32(fnla, clockid)
    rt->clockid = clockid;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timerfd_settime(fnla_t fnla) {
    auto rt = std::make_unique<TimerfdSettime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timerfd_settime";

    NLA_GET_S32(fnla, ufd)
    rt->ufd = ufd;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, new_value)
    rt->new_value = new_value;

    NLA_GET_U64(fnla, old_value)
    rt->old_value = old_value;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timerfd_gettime(fnla_t fnla) {
    auto rt = std::make_unique<TimerfdGettime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timerfd_gettime";

    NLA_GET_S32(fnla, ufd)
    rt->ufd = ufd;

    NLA_GET_U64(fnla, otmr)
    rt->otmr = otmr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_utimensat(fnla_t fnla) {
    auto rt = std::make_unique<Utimensat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "utimensat";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U32(fnla, path_len)
    char* path = new char[path_len];
    fnla_get_bytes(fnla, path, path_len);
    rt->filename = std::string(path, path_len);
    delete[] path;

    NLA_GET_U64(fnla, utimes)
    rt->utimes = utimes;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    rt->finished = true;
    return rt;
}

auto parse_acct(fnla_t fnla) {
    auto rt = std::make_unique<Acct>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "acct";

    NLA_GET_U32(fnla, name_len)
    char* path = new char[name_len];
    fnla_get_bytes(fnla, path, name_len);
    rt->name = std::string(path, name_len);
    delete[] path;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_capget(fnla_t fnla) {
    auto rt = std::make_unique<Capget>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "capget";

    NLA_GET_U64(fnla, header)
    rt->header = header;

    NLA_GET_U64(fnla, data)
    rt->data = data;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_personality(fnla_t fnla) {
    auto rt = std::make_unique<Personality>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "personality";

    NLA_GET_U64(fnla, persona)
    rt->persona = persona;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_exit(fnla_t fnla) {
    auto rt = std::make_unique<Exit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "exit";

    NLA_GET_S32(fnla, status)
    rt->status = status;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_exit_group(fnla_t fnla) {
    auto rt = std::make_unique<ExitGroup>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "exit_group";

    NLA_GET_S32(fnla, status)
    rt->status = status;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_waitid(fnla_t fnla) {
    auto rt = std::make_unique<Waitid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "waitid";

    NLA_GET_S32(fnla, idtype)
    rt->idtype = idtype;

    NLA_GET_U32(fnla, id)
    rt->id = id;

    NLA_GET_U64(fnla, infop)
    rt->infop = infop;

    NLA_GET_S32(fnla, options)
    rt->options = options;

    NLA_GET_U64(fnla, ru)
    rt->ru = ru;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_set_tid_address(fnla_t fnla) {
    auto rt = std::make_unique<SetTidAddress>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "set_tid_address";

    NLA_GET_U64(fnla, tidptr)
    rt->tidptr = tidptr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_unshare(fnla_t fnla) {
    auto rt = std::make_unique<Unshare>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "unshare";

    NLA_GET_U64(fnla, unshare_flags)
    rt->unshare_flags = unshare_flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_set_robust_list(fnla_t fnla) {
    auto rt = std::make_unique<SetRobustList>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "set_robust_list";

    NLA_GET_U64(fnla, head)
    rt->head = head;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_get_robust_list(fnla_t fnla) {
    auto rt = std::make_unique<GetRobustList>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "get_robust_list";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, head_ptr)
    rt->head_ptr = head_ptr;

    NLA_GET_U64(fnla, len_ptr)
    rt->len_ptr = len_ptr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_nanosleep(fnla_t fnla) {
    auto rt = std::make_unique<Nanosleep>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "nanosleep";

    NLA_GET_U64(fnla, rqtp)
    rt->rqtp = rqtp;

    NLA_GET_U64(fnla, rqtp_valtv_sec)
    rt->rqtp_val.tv_sec = rqtp_valtv_sec;

    NLA_GET_U64(fnla, rqtp_valtv_nsec)
    rt->rqtp_val.tv_nsec = rqtp_valtv_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getitimer(fnla_t fnla) {
    auto rt = std::make_unique<Getitimer>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getitimer";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_U64(fnla, value)
    rt->value = value;

    NLA_GET_U64(fnla, valit_intervaltv_sec)
    rt->val.it_interval.tv_sec = valit_intervaltv_sec;

    NLA_GET_U64(fnla, valit_intervaltv_usec)
    rt->val.it_interval.tv_usec = valit_intervaltv_usec;

    NLA_GET_U64(fnla, valit_valuetv_sec)
    rt->val.it_value.tv_sec = valit_valuetv_sec;

    NLA_GET_U64(fnla, valit_valuetv_usec)
    rt->val.it_value.tv_usec = valit_valuetv_usec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setitimer(fnla_t fnla) {
    auto rt = std::make_unique<Setitimer>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setitimer";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_U64(fnla, new_value)
    rt->new_value = new_value;

    NLA_GET_U64(fnla, old_value)
    rt->old_value = old_value;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_kexec_load(fnla_t fnla) {
    auto rt = std::make_unique<KexecLoad>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "kexec_load";

    NLA_GET_U64(fnla, entry)
    rt->entry = entry;

    NLA_GET_U64(fnla, nr_segments)
    rt->nr_segments = nr_segments;

    NLA_GET_U64(fnla, segments)
    rt->segments = segments;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_init_module(fnla_t fnla) {
    auto rt = std::make_unique<InitModule>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "init_module";

    NLA_GET_U32(fnla, len)
    rt->len = len;

    // Read the umod_buf bytes based on the length
    std::vector<uint8_t> umod(len);
    fnla_get_bytes(fnla, (char*) umod.data(), len);
    rt->umod_buf = std::move(umod);

    NLA_GET_U32(fnla, uargs_len)
    char* uargs = new char[uargs_len + 1]; // Allocate space for string
    fnla_get_bytes(fnla, uargs, uargs_len);
    uargs[uargs_len] = '\0'; // Null-terminate the string
    rt->uargs_buf = std::string(uargs);
    delete[] uargs;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_delete_module(fnla_t fnla) {
    auto rt = std::make_unique<DeleteModule>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "delete_module";

    NLA_GET_U32(fnla, name_len);  // 获取 name_buf 的长度
    char* name_buf = new char[name_len + 1];  // 为字符串分配空间
    fnla_get_bytes(fnla, name_buf, name_len);  // 从消息中获取字节数据
    name_buf[name_len] = '\0';  // 给字符串添加结束符
    rt->uargs_buf = std::string(name_buf);  // 将字节数据转为 std::string
    delete[] name_buf;  // 释放临时分配的内存

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timer_create(fnla_t fnla) {
    auto rt = std::make_unique<TimerCreate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timer_create";

    NLA_GET_S32(fnla, clockid)
    rt->clockid = clockid;

    NLA_GET_U64(fnla, sevp)
    rt->sevp = sevp;

    NLA_GET_U64(fnla, timerid)
    rt->timerid = timerid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timer_gettime(fnla_t fnla) {
    auto rt = std::make_unique<TimerGetTime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timer_gettime";

    NLA_GET_U64(fnla, timerid)
    rt->timerid = timerid;

    NLA_GET_U64(fnla, value)
    rt->value = value;

    // Parse it_interval fields
    NLA_GET_U64(fnla, it_interval_sec)
    rt->timespec_values.it_interval_sec = it_interval_sec;
    NLA_GET_U64(fnla, it_interval_nsec)
    rt->timespec_values.it_interval_nsec = it_interval_nsec;

    // Parse it_value fields
    NLA_GET_U64(fnla, it_value_sec)
    rt->timespec_values.it_value_sec = it_value_sec;
    NLA_GET_U64(fnla, it_value_nsec)
    rt->timespec_values.it_value_nsec = it_value_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timer_getoverrun(fnla_t fnla) {
    auto rt = std::make_unique<TimerGetOverrun>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timer_getoverrun";

    NLA_GET_U64(fnla, timerid)
    rt->timerid = timerid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timer_settime(fnla_t fnla) {
    auto rt = std::make_unique<TimerSetTime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timer_settime";

    NLA_GET_U64(fnla, timerid)
    rt->timerid = timerid;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, new_value)
    rt->new_value = new_value;

    // Parse it_interval fields
    NLA_GET_U64(fnla, it_interval_sec)
    rt->timespec_values.it_interval_sec = it_interval_sec;
    NLA_GET_U64(fnla, it_interval_nsec)
    rt->timespec_values.it_interval_nsec = it_interval_nsec;

    // Parse it_value fields
    NLA_GET_U64(fnla, it_value_sec)
    rt->timespec_values.it_value_sec = it_value_sec;
    NLA_GET_U64(fnla, it_value_nsec)
    rt->timespec_values.it_value_nsec = it_value_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_timer_delete(fnla_t fnla) {
    auto rt = std::make_unique<TimerDelete>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "timer_delete";

    NLA_GET_U64(fnla, timerid)
    rt->timerid = timerid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clock_settime(fnla_t fnla) {
    auto rt = std::make_unique<ClockSetTime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clock_settime";

    NLA_GET_S32(fnla, which_clock)
    rt->which_clock = which_clock;

    NLA_GET_U64(fnla, tp)
    rt->tp = tp;

    // Parse the val.tv_sec and val.tv_nsec fields
    NLA_GET_U64(fnla, tv_sec)
    rt->val.tv_sec = tv_sec;

    NLA_GET_U64(fnla, tv_nsec)
    rt->val.tv_nsec = tv_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clock_gettime(fnla_t fnla) {
    auto rt = std::make_unique<ClockGetTime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clock_gettime";

    NLA_GET_S32(fnla, which_clock)
    rt->which_clock = which_clock;

    NLA_GET_U64(fnla, tp)
    rt->tp = tp;

    // Parse the val.tv_sec and val.tv_nsec fields
    NLA_GET_U64(fnla, tv_sec)
    rt->val.tv_sec = tv_sec;

    NLA_GET_U64(fnla, tv_nsec)
    rt->val.tv_nsec = tv_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clock_getres(fnla_t fnla) {
    auto rt = std::make_unique<ClockGetRes>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clock_getres";

    NLA_GET_S32(fnla, which_clock)
    rt->which_clock = which_clock;

    NLA_GET_U64(fnla, tp)
    rt->tp = tp;

    // Parse the val.tv_sec and val.tv_nsec fields
    NLA_GET_U64(fnla, tv_sec)
    rt->val.tv_sec = tv_sec;

    NLA_GET_U64(fnla, tv_nsec)
    rt->val.tv_nsec = tv_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clock_nanosleep(fnla_t fnla) {
    auto rt = std::make_unique<ClockNanoSleep>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clock_nanosleep";

    NLA_GET_S32(fnla, which_clock)
    rt->which_clock = which_clock;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, rqtp)
    rt->rqtp = rqtp;

    NLA_GET_U64(fnla, rmtp)
    rt->rmtp = rmtp;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_syslog(fnla_t fnla) {
    auto rt = std::make_unique<Syslog>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "syslog";

    NLA_GET_S32(fnla, type)
    rt->type = type;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    // Parse the log message (buf_buf)
    NLA_GET_U32(fnla, blrn)
    char* uargs = new char[blrn]; // Allocate space for string
    fnla_get_bytes(fnla, uargs, blrn);
    rt->buf_buf = std::string(uargs, blrn);
    delete[] uargs;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_ptrace(fnla_t fnla) {
    auto rt = std::make_unique<Ptrace>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "ptrace";

    NLA_GET_S64(fnla, request)
    rt->request = request;

    NLA_GET_S64(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, data)
    rt->data = data;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_setparam(fnla_t fnla) {
    auto rt = std::make_unique<SchedSetParam>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_setparam";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, param)
    rt->param = param;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_setscheduler(fnla_t fnla) {
    auto rt = std::make_unique<SchedSetScheduler>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_setscheduler";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, policy)
    rt->policy = policy;

    NLA_GET_U64(fnla, param)
    rt->param = param;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_getscheduler(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetScheduler>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_getscheduler";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_getparam(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetParam>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_getparam";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, param)
    rt->param = param;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_setaffinity(fnla_t fnla) {
    auto rt = std::make_unique<SchedSetAffinity>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_setaffinity";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U32(fnla, cpusetsize)
    rt->cpusetsize = cpusetsize;

    NLA_GET_U64(fnla, mask)
    rt->mask = mask;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_getaffinity(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetAffinity>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_getaffinity";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U32(fnla, cpusetsize)
    rt->cpusetsize = cpusetsize;

    NLA_GET_U64(fnla, mask)
    rt->mask = mask;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_yield(fnla_t fnla) {
    auto rt = std::make_unique<SchedYield>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_yield";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_get_priority_max(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetPriorityMax>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_get_priority_max";

    NLA_GET_S32(fnla, policy)
    rt->policy = policy;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_get_priority_min(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetPriorityMin>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_get_priority_min";

    NLA_GET_S32(fnla, policy)
    rt->policy = policy;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_rr_get_interval(fnla_t fnla) {
    auto rt = std::make_unique<SchedRRGetInterval>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_rr_get_interval";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, interval)
    rt->interval = interval;

    NLA_GET_U64(fnla, tv_sec)
    rt->val.tv_sec = tv_sec;

    NLA_GET_U64(fnla, tv_nsec)
    rt->val.tv_nsec = tv_nsec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_restart_syscall(fnla_t fnla) {
    auto rt = std::make_unique<RestartSyscall>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "restart_syscall";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_kill(fnla_t fnla) {
    auto rt = std::make_unique<Kill>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "kill";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_tkill(fnla_t fnla) {
    auto rt = std::make_unique<Tkill>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "tkill";

    NLA_GET_S32(fnla, tid)
    rt->tid = tid;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_tgkill(fnla_t fnla) {
    auto rt = std::make_unique<Tgkill>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "tgkill";

    NLA_GET_S32(fnla, tgid)
    rt->tgid = tgid;

    NLA_GET_S32(fnla, tid)
    rt->tid = tid;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sigaltstack(fnla_t fnla) {
    auto rt = std::make_unique<Sigaltstack>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sigaltstack";

    NLA_GET_U64(fnla, uss)
    rt->uss = uss;

    NLA_GET_U64(fnla, uoss)
    rt->uoss = uoss;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigsuspend(fnla_t fnla) {
    auto rt = std::make_unique<RtSigsuspend>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigsuspend";

    NLA_GET_U64(fnla, mask)
    rt->mask = mask;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigaction(fnla_t fnla) {
    auto rt = std::make_unique<RtSigaction>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigaction";

    NLA_GET_S32(fnla, signum)
    rt->signum = signum;

    NLA_GET_U64(fnla, act)
    rt->act = act;

    NLA_GET_U64(fnla, oldact)
    rt->oldact = oldact;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sigprocmask(fnla_t fnla) {
    auto rt = std::make_unique<Sigprocmask>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sigprocmask";

    NLA_GET_S32(fnla, how)
    rt->how = how;

    NLA_GET_U64(fnla, set)
    rt->set = set;

    NLA_GET_U64(fnla, oldset)
    rt->oldset = oldset;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigprocmask(fnla_t fnla) {
    auto rt = std::make_unique<RtSigprocmask>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigprocmask";

    NLA_GET_S32(fnla, how)
    rt->how = how;

    NLA_GET_U64(fnla, set)
    rt->set = set;

    NLA_GET_U64(fnla, oldset)
    rt->oldset = oldset;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigpending(fnla_t fnla) {
    auto rt = std::make_unique<RtSigpending>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigpending";

    NLA_GET_U64(fnla, set)
    rt->set = set;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigtimedwait(fnla_t fnla) {
    auto rt = std::make_unique<RtSigtimedwait>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigtimedwait";

    NLA_GET_U64(fnla, set)
    rt->set = set;

    NLA_GET_U64(fnla, info)
    rt->info = info;

    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigqueueinfo(fnla_t fnla) {
    auto rt = std::make_unique<RtSigqueueinfo>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigqueueinfo";

    NLA_GET_S32(fnla, tgid)
    rt->tgid = tgid;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_U64(fnla, info)
    rt->info = info;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_sigreturn(fnla_t fnla) {
    auto rt = std::make_unique<RtSigreturn>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_sigreturn";

    NLA_GET_U64(fnla, ustack)
    rt->ustack = ustack;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setpriority(fnla_t fnla) {
    auto rt = std::make_unique<Setpriority>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setpriority";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_S32(fnla, who)
    rt->who = who;

    NLA_GET_S32(fnla, niceval)
    rt->niceval = niceval;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getpriority(fnla_t fnla) {
    auto rt = std::make_unique<Getpriority>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getpriority";

    NLA_GET_S32(fnla, which)
    rt->which = which;

    NLA_GET_S32(fnla, who)
    rt->who = who;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_reboot(fnla_t fnla) {
    auto rt = std::make_unique<Reboot>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "reboot";

    NLA_GET_S32(fnla, magic)
    rt->magic = magic;

    NLA_GET_S32(fnla, magic2)
    rt->magic2 = magic2;

    NLA_GET_U32(fnla, op)
    rt->op = op;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setregid(fnla_t fnla) {
    auto rt = std::make_unique<SetRegid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setregid";

    NLA_GET_S32(fnla, rgid)
    rt->rgid = rgid;

    NLA_GET_S32(fnla, egid)
    rt->egid = egid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setgid(fnla_t fnla) {
    auto rt = std::make_unique<SetGid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setgid";

    NLA_GET_S32(fnla, gid)
    rt->gid = gid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setreuid(fnla_t fnla) {
    auto rt = std::make_unique<SetReuid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setreuid";

    NLA_GET_S32(fnla, ruid)
    rt->ruid = ruid;

    NLA_GET_S32(fnla, euid)
    rt->euid = euid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setuid(fnla_t fnla) {
    auto rt = std::make_unique<SetUid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setuid";

    NLA_GET_S32(fnla, uid)
    rt->uid = uid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setresuid(fnla_t fnla) {
    auto rt = std::make_unique<SetResUid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setresuid";

    NLA_GET_S32(fnla, ruid)
    rt->ruid = ruid;

    NLA_GET_S32(fnla, euid)
    rt->euid = euid;

    NLA_GET_S32(fnla, suid)
    rt->suid = suid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getresuid(fnla_t fnla) {
    auto rt = std::make_unique<GetResUid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getresuid";

    NLA_GET_U64(fnla, ruid)
    rt->ruid = ruid;

    NLA_GET_S32(fnla, ruid_val)
    rt->ruid_val = ruid_val;

    NLA_GET_U64(fnla, euid)
    rt->euid = euid;

    NLA_GET_S32(fnla, euid_val)
    rt->euid_val = euid_val;

    NLA_GET_U64(fnla, suid)
    rt->suid = suid;

    NLA_GET_S32(fnla, suid_val)
    rt->suid_val = suid_val;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setresgid(fnla_t fnla) {
    auto rt = std::make_unique<SetResGid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setresgid";

    NLA_GET_S32(fnla, rgid)
    rt->rgid = rgid;

    NLA_GET_S32(fnla, egid)
    rt->egid = egid;

    NLA_GET_S32(fnla, sgid)
    rt->sgid = sgid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getresgid(fnla_t fnla) {
    auto rt = std::make_unique<GetResGid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getresgid";

    // Parse rgid and its value
    NLA_GET_U64(fnla, rgid)
    rt->rgid = rgid;
    NLA_GET_S32(fnla, rgid_val)
    rt->rgid_val = rgid_val;

    // Parse egid and its value
    NLA_GET_U64(fnla, egid)
    rt->egid = egid;
    NLA_GET_S32(fnla, egid_val)
    rt->egid_val = egid_val;

    // Parse sgid and its value
    NLA_GET_U64(fnla, sgid)
    rt->sgid = sgid;
    NLA_GET_S32(fnla, sgid_val)
    rt->sgid_val = sgid_val;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setfsuid(fnla_t fnla) {
    auto rt = std::make_unique<SetFsUid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setfsuid";

    NLA_GET_S32(fnla, uid)
    rt->uid = uid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setfsgid(fnla_t fnla) {
    auto rt = std::make_unique<SetFsGid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setfsgid";

    NLA_GET_S32(fnla, gid)
    rt->gid = gid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_times(fnla_t fnla) {
    auto rt = std::make_unique<Times>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "times";

    NLA_GET_U64(fnla, tbuf)
    rt->tbuf = tbuf;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setpgid(fnla_t fnla) {
    auto rt = std::make_unique<Setpgid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setpgid";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, pgid)
    rt->pgid = pgid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getpgid(fnla_t fnla) {
    auto rt = std::make_unique<Getpgid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getpgid";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getsid(fnla_t fnla) {
    auto rt = std::make_unique<Getsid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getsid";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setsid(fnla_t fnla) {
    auto rt = std::make_unique<Setsid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setsid";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getgroups(fnla_t fnla) {
    auto rt = std::make_unique<Getgroups>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getgroups";

    NLA_GET_S32(fnla, gidsetsize)
    rt->gidsetsize = gidsetsize;

    if (gidsetsize > 0) {
        // Parsing the group list
        for (int i = 0; i < gidsetsize; ++i) {
            NLA_GET_S32(fnla, group)
            rt->grouplist.push_back(group);
        }
    }

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setgroups(fnla_t fnla) {
    auto rt = std::make_unique<Setgroups>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setgroups";

    NLA_GET_S32(fnla, gidsetsize)
    rt->gidsetsize = gidsetsize;

    if (gidsetsize > 0) {
        // Parsing the group list
        for (int i = 0; i < gidsetsize; ++i) {
            NLA_GET_S32(fnla, group)
            rt->grouplist.push_back(group);
        }
    }

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_uname(fnla_t fnla) {
    auto rt = std::make_unique<Uname>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "uname";

    NLA_GET_U64(fnla, name)
    rt->name = name;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setdomainname(fnla_t fnla) {
    auto rt = std::make_unique<SetDomainName>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setdomainname";

    NLA_GET_U64(fnla, name)
    rt->name = name;

    NLA_GET_S32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getrlimit(fnla_t fnla) {
    auto rt = std::make_unique<GetRlimit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getrlimit";

    NLA_GET_U32(fnla, resource)
    rt->resource = resource;

    NLA_GET_U64(fnla, rlim)
    rt->rlim = rlim;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setrlimit(fnla_t fnla) {
    auto rt = std::make_unique<SetRlimit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setrlimit";

    NLA_GET_U32(fnla, resource)
    rt->resource = resource;

    NLA_GET_U64(fnla, rlim)
    rt->rlim = rlim;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getrusage(fnla_t fnla) {
    auto rt = std::make_unique<GetRusage>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getrusage";

    NLA_GET_S32(fnla, who)
    rt->who = who;

    NLA_GET_U64(fnla, ru)
    rt->ru = ru;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_umask(fnla_t fnla) {
    auto rt = std::make_unique<Umask>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "umask";

    NLA_GET_S64(fnla, mask)
    rt->mask = mask;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_prctl(fnla_t fnla) {
    auto rt = std::make_unique<Prctl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "prctl";

    NLA_GET_S32(fnla, option)
    rt->option = option;

    NLA_GET_U64(fnla, arg2)
    rt->arg2 = arg2;

    NLA_GET_U64(fnla, arg3)
    rt->arg3 = arg3;

    NLA_GET_U64(fnla, arg4)
    rt->arg4 = arg4;

    NLA_GET_U64(fnla, arg5)
    rt->arg5 = arg5;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getcpu(fnla_t fnla) {
    auto rt = std::make_unique<Getcpu>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getcpu";

    NLA_GET_U64(fnla, cpup)
    rt->cpup = cpup;

    NLA_GET_U64(fnla, nodep)
    rt->nodep = nodep;

    NLA_GET_U64(fnla, tcache)
    rt->tcache = tcache;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_gettimeofday(fnla_t fnla) {
    auto rt = std::make_unique<Gettimeofday>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "gettimeofday";

    NLA_GET_U64(fnla, tv)
    rt->tv = tv;

    NLA_GET_U64(fnla, tz)
    rt->tz = tz;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_settimeofday(fnla_t fnla) {
    auto rt = std::make_unique<Settimeofday>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "settimeofday";

    NLA_GET_U64(fnla, tv)
    rt->tv = tv;

    NLA_GET_U64(fnla, tz)
    rt->tz = tz;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_adjtimex(fnla_t fnla) {
    auto rt = std::make_unique<Adjtimex>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "adjtimex";

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getpid(fnla_t fnla) {
    auto rt = std::make_unique<Getpid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getpid";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getppid(fnla_t fnla) {
    auto rt = std::make_unique<Getppid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getppid";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getuid(fnla_t fnla) {
    auto rt = std::make_unique<Getuid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getuid";

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_geteuid(fnla_t fnla) {
    auto rt = std::make_unique<Geteuid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "geteuid";

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getgid(fnla_t fnla) {
    auto rt = std::make_unique<Getgid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getgid";

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getegid(fnla_t fnla) {
    auto rt = std::make_unique<Getegid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getegid";

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_gettid(fnla_t fnla) {
    auto rt = std::make_unique<Gettid>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "gettid";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sysinfo(fnla_t fnla) {
    auto rt = std::make_unique<Sysinfo>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sysinfo";

    NLA_GET_U64(fnla, info)
    rt->info = info;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_open(fnla_t fnla) {
    auto rt = std::make_unique<MqOpen>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_open";

    NLA_GET_U64(fnla, name)
    rt->name = name;

    if (name) {
        NLA_GET_U32(fnla, name_len);
        char* uargs = new char[name_len];
        fnla_get_bytes(fnla, uargs, name_len);
        rt->name_buf = std::string(uargs, name_len);
        delete[] uargs;
    }

    NLA_GET_S32(fnla, oflag)
    rt->oflag = oflag;

    NLA_GET_U32(fnla, mode)
    rt->mode = mode;

    NLA_GET_U64(fnla, attr)
    rt->attr = attr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_unlink(fnla_t fnla) {
    auto rt = std::make_unique<MqUnlink>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_unlink";

    NLA_GET_U64(fnla, name)
    rt->name = name;

    if (name) {
        NLA_GET_U32(fnla, name_len);
        char* uargs = new char[name_len]; // Allocate space for string
        fnla_get_bytes(fnla, uargs, name_len);
        rt->name_buf = std::string(uargs, name_len);
        delete[] uargs;
    }

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_timedsend(fnla_t fnla) {
    auto rt = std::make_unique<MqTimedSend>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_timedsend";

    NLA_GET_S32(fnla, mqdes)
    rt->mqdes = mqdes;

    NLA_GET_U64(fnla, msg_ptr)
    rt->msg_ptr = msg_ptr;

    NLA_GET_U32(fnla, msg_len)
    rt->msg_len = msg_len;

    NLA_GET_U32(fnla, msg_prio)
    rt->msg_prio = msg_prio;

    NLA_GET_U64(fnla, abs_timeout)
    rt->abs_timeout = abs_timeout;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_timedreceive(fnla_t fnla) {
    auto rt = std::make_unique<MqTimedReceive>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_timedreceive";

    NLA_GET_S32(fnla, mqdes)
    rt->mqdes = mqdes;

    NLA_GET_U64(fnla, msg_ptr)
    rt->msg_ptr = msg_ptr;

    NLA_GET_U32(fnla, msg_len)
    rt->msg_len = msg_len;

    NLA_GET_U64(fnla, msg_prio)
    rt->msg_prio = msg_prio;

    NLA_GET_U64(fnla, abs_timeout)
    rt->abs_timeout = abs_timeout;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_notify(fnla_t fnla) {
    auto rt = std::make_unique<MqNotify>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_notify";

    NLA_GET_S32(fnla, mqdes)
    rt->mqdes = mqdes;

    NLA_GET_U64(fnla, notification)
    rt->notification = notification;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mq_getsetattr(fnla_t fnla) {
    auto rt = std::make_unique<MqGetSetAttr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mq_getsetattr";

    NLA_GET_S32(fnla, mqdes)
    rt->mqdes = mqdes;

    NLA_GET_U64(fnla, mqstat)
    rt->mqstat = mqstat;

    NLA_GET_U64(fnla, omqstat)
    rt->omqstat = omqstat;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_msgget(fnla_t fnla) {
    auto rt = std::make_unique<MsgGet>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "msgget";

    NLA_GET_S32(fnla, key)
    rt->key = key;

    NLA_GET_S32(fnla, msgflg)
    rt->msgflg = msgflg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_msgctl(fnla_t fnla) {
    auto rt = std::make_unique<MsgCtl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "msgctl";

    NLA_GET_S32(fnla, msqid)
    rt->msqid = msqid;

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_msgsnd(fnla_t fnla) {
    auto rt = std::make_unique<MsgSnd>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "msgsnd";

    NLA_GET_S32(fnla, msqid)
    rt->msqid = msqid;

    NLA_GET_U64(fnla, msgp)
    rt->msgp = msgp;

    NLA_GET_U32(fnla, msgsz)
    rt->msgsz = msgsz;

    NLA_GET_S32(fnla, msgflg)
    rt->msgflg = msgflg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_msgrcv(fnla_t fnla) {
    auto rt = std::make_unique<MsgRcv>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "msgrcv";

    NLA_GET_S32(fnla, msqid)
    rt->msqid = msqid;

    NLA_GET_U64(fnla, msgp)
    rt->msgp = msgp;

    NLA_GET_U32(fnla, msgsz)
    rt->msgsz = msgsz;

    NLA_GET_S64(fnla, msgtyp)
    rt->msgtyp = msgtyp;

    NLA_GET_S32(fnla, msgflg)
    rt->msgflg = msgflg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_semget(fnla_t fnla) {
    auto rt = std::make_unique<SemGet>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "semget";

    NLA_GET_S32(fnla, key)
    rt->key = key;

    NLA_GET_S32(fnla, nsems)
    rt->nsems = nsems;

    NLA_GET_S32(fnla, semflg)
    rt->semflg = semflg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_semctl(fnla_t fnla) {
    auto rt = std::make_unique<SemCtl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "semctl";

    NLA_GET_S32(fnla, semid)
    rt->semid = semid;

    NLA_GET_S32(fnla, semnum)
    rt->semnum = semnum;

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_semtimedop(fnla_t fnla) {
    auto rt = std::make_unique<SemTimedOp>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "semtimedop";

    NLA_GET_S32(fnla, semid)
    rt->semid = semid;

    NLA_GET_U64(fnla, sops)
    rt->sops = sops;

    NLA_GET_U32(fnla, nsops)
    rt->nsops = nsops;

    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_semop(fnla_t fnla) {
    auto rt = std::make_unique<SemOp>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "semop";

    NLA_GET_S32(fnla, semid)
    rt->semid = semid;

    NLA_GET_U64(fnla, sops)
    rt->sops = sops;

    NLA_GET_U32(fnla, nsops)
    rt->nsops = nsops;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_shmget(fnla_t fnla) {
    auto rt = std::make_unique<ShmGet>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "shmget";

    NLA_GET_S32(fnla, key)
    rt->key = key;

    NLA_GET_U32(fnla, size)
    rt->size = size;

    NLA_GET_S32(fnla, shmflg)
    rt->shmflg = shmflg;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_shmctl(fnla_t fnla) {
    auto rt = std::make_unique<ShmCtl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "shmctl";

    NLA_GET_S32(fnla, shmid)
    rt->shmid = shmid;

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_shmat(fnla_t fnla) {
    auto rt = std::make_unique<Shmat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "shmat";

    NLA_GET_S32(fnla, shmid)
    rt->shmid = shmid;

    NLA_GET_U64(fnla, shmaddr)
    rt->shmaddr = shmaddr;

    NLA_GET_S32(fnla, shmflg)
    rt->shmflg = shmflg;

    NLA_GET_U64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_shmdt(fnla_t fnla) {
    auto rt = std::make_unique<Shmdt>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "shmdt";

    NLA_GET_U64(fnla, shmaddr)
    rt->shmaddr = shmaddr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_socket(fnla_t fnla) {
    auto rt = std::make_unique<Socket>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "socket";

    NLA_GET_S32(fnla, family)
    rt->family = family;

    NLA_GET_S32(fnla, type)
    rt->type = type;

    NLA_GET_S32(fnla, protocol)
    rt->protocol = protocol;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_socketpair(fnla_t fnla) {
    auto rt = std::make_unique<Socketpair>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "socketpair";

    NLA_GET_S32(fnla, family)
    rt->family = family;

    NLA_GET_S32(fnla, type)
    rt->type = type;

    NLA_GET_S32(fnla, protocol)
    rt->protocol = protocol;

    NLA_GET_U64(fnla, usockvec)
    rt->usockvec = usockvec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_bind(fnla_t fnla) {
    auto rt = std::make_unique<Bind>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "bind";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr_p = addr;

    if (addr) {
        NLA_GET_U32(fnla, addr_buf_len)
        char* addr_tmp = new char[addr_buf_len];
        fnla_get_bytes(fnla, addr_tmp, addr_buf_len);
        memcpy(&rt->addr_buf, addr_tmp, addr_buf_len);
        delete[] addr_tmp;
    }

    NLA_GET_S32(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_listen(fnla_t fnla) {
    auto rt = std::make_unique<Listen>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "listen";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_S32(fnla, backlog)
    rt->backlog = backlog;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_accept(fnla_t fnla) {
    auto rt = std::make_unique<Accept>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "accept";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr_p = addr;

    if (addr) {
        NLA_GET_U32(fnla, addr_buf_len)
        char* addr_tmp = new char[addr_buf_len];
        fnla_get_bytes(fnla, addr_tmp, addr_buf_len);
        memcpy(&rt->addr_buf, addr_tmp, addr_buf_len);
        delete[] addr_tmp;
    }

    NLA_GET_S32(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_connect(fnla_t fnla) {
    auto rt = std::make_unique<Connect>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "connect";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr_p = addr;

    if (addr) {
        NLA_GET_U32(fnla, addr_buf_len)
        char* addr_tmp = new char[addr_buf_len];
        fnla_get_bytes(fnla, addr_tmp, addr_buf_len);
        memcpy(&rt->addr_buf, addr_tmp, addr_buf_len);
        delete[] addr_tmp;
    }

    NLA_GET_S32(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getsockname(fnla_t fnla) {
    auto rt = std::make_unique<Getsockname>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getsockname";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getpeername(fnla_t fnla) {
    auto rt = std::make_unique<Getpeername>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getpeername";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sendto(fnla_t fnla) {
    auto rt = std::make_unique<Sendto>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sendto";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, buff)
    rt->buff = buff;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, dest_addr)
    rt->dest_addr = dest_addr;

    NLA_GET_S32(fnla, dest_addr_len)
    rt->dest_addr_len = dest_addr_len;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_recvfrom(fnla_t fnla) {
    auto rt = std::make_unique<Recvfrom>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "recvfrom";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, buff)
    rt->buff = buff;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, addr_len)
    rt->addr_len = addr_len;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setsockopt(fnla_t fnla) {
    auto rt = std::make_unique<Setsockopt>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setsockopt";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_S32(fnla, level)
    rt->level = level;

    NLA_GET_S32(fnla, optname)
    rt->optname = optname;

    NLA_GET_U64(fnla, optval)
    rt->optval = optval;

    NLA_GET_U32(fnla, optlen)
    rt->optlen = optlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getsockopt(fnla_t fnla) {
    auto rt = std::make_unique<Getsockopt>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getsockopt";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_S32(fnla, level)
    rt->level = level;

    NLA_GET_S32(fnla, optname)
    rt->optname = optname;

    NLA_GET_U64(fnla, optval)
    rt->optval = optval;

    NLA_GET_U64(fnla, optlen)
    rt->optlen = optlen;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_shutdown(fnla_t fnla) {
    auto rt = std::make_unique<Shutdown>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "shutdown";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_S32(fnla, how)
    rt->how = how;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sendmsg(fnla_t fnla) {
    auto rt = std::make_unique<Sendmsg>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sendmsg";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, msg)
    rt->msg = msg;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_recvmsg(fnla_t fnla) {
    auto rt = std::make_unique<Recvmsg>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "recvmsg";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, msg)
    rt->msg = msg;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_readahead(fnla_t fnla) {
    auto rt = std::make_unique<Readahead>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "readahead";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U32(fnla, count)
    rt->count = count;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_brk(fnla_t fnla) {
    auto rt = std::make_unique<Brk>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "brk";

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_munmap(fnla_t fnla) {
    auto rt = std::make_unique<Munmap>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "munmap";

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mremap(fnla_t fnla) {
    auto rt = std::make_unique<Mremap>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mremap";

    NLA_GET_U64(fnla, old_addr)
    rt->old_addr = old_addr;

    NLA_GET_U32(fnla, old_len)
    rt->old_len = old_len;

    NLA_GET_U32(fnla, new_len)
    rt->new_len = new_len;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, new_addr)
    rt->new_addr = new_addr;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_add_key(fnla_t fnla) {
    auto rt = std::make_unique<AddKey>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "add_key";

    NLA_GET_U64(fnla, type)
    rt->type = type;

    NLA_GET_U64(fnla, description)
    rt->description = description;

    NLA_GET_U64(fnla, payload)
    rt->payload = payload;

    NLA_GET_U32(fnla, plen)
    rt->plen = plen;

    NLA_GET_U64(fnla, keyring)
    rt->keyring = keyring;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_request_key(fnla_t fnla) {
    auto rt = std::make_unique<RequestKey>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "request_key";

    NLA_GET_U64(fnla, type)
    rt->type = type;

    NLA_GET_U64(fnla, description)
    rt->description = description;

    NLA_GET_U64(fnla, callout_info)
    rt->callout_info = callout_info;

    NLA_GET_U64(fnla, dest_keyring)
    rt->dest_keyring = dest_keyring;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_keyctl(fnla_t fnla) {
    auto rt = std::make_unique<Keyctl>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "keyctl";

    NLA_GET_S32(fnla, operation)
    rt->operation = operation;

    NLA_GET_U64(fnla, arg2)
    rt->arg2 = arg2;

    NLA_GET_U64(fnla, arg3)
    rt->arg3 = arg3;

    NLA_GET_U64(fnla, arg4)
    rt->arg4 = arg4;

    NLA_GET_U64(fnla, arg5)
    rt->arg5 = arg5;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clone(fnla_t fnla) {
    auto rt = std::make_unique<Clone>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clone";

    NLA_GET_U64(fnla, fn)
    rt->fn = fn;

    NLA_GET_U64(fnla, stack)
    rt->stack = stack;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_U64(fnla, parent_tid)
    rt->parent_tid = parent_tid;

    NLA_GET_U64(fnla, tls)
    rt->tls = tls;

    NLA_GET_U64(fnla, child_tid)
    rt->child_tid = child_tid;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_execve(fnla_t fnla) {
    auto rt = std::make_unique<Execve>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "execve";

    NLA_GET_U64(fnla, filename)
    rt->filename = filename;

    NLA_GET_U64(fnla, argv)
    rt->argv = argv;

    NLA_GET_U64(fnla, envp)
    rt->envp = envp;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (filename) {
        NLA_GET_U32(fnla, filename_len)
        char* filename_tmp = new char[filename_len];
        fnla_get_bytes(fnla, filename_tmp, filename_len);
        rt->filename_buf = std::string(filename_tmp, filename_len);
        delete[] filename_tmp;
    }

    NLA_GET_S32(fnla, argc)
    rt->argc = argc;

    for (int i = 0; i < argc; ++i) {
        NLA_GET_U64(fnla, argv_p)
        if (argv_p == 0) {
            NLA_GET_U32(fnla, errno_)
            std::cerr << "Parse execve‘s argv failed, error = " << errno_ << ", i = " << i << std::endl;
            continue;
        }
        NLA_GET_U32(fnla, argvi_len)
        char* argvi_tmp = new char[argvi_len];
        fnla_get_bytes(fnla, argvi_tmp, argvi_len);
        rt->argv_buf.push_back(std::string(argvi_tmp, argvi_len));
        delete[] argvi_tmp;
    }

    NLA_GET_S32(fnla, envc)
    rt->envc = envc;

    for (int i = 0; i < envc; ++i) {
        NLA_GET_U64(fnla, envp_p)
        if (envp_p == 0) {
            NLA_GET_U32(fnla, errno_)
            std::cerr << "Parse execve's env failed, error = " << errno_ << ", i = " << i << std::endl;
            continue;
        }
        NLA_GET_U32(fnla, envpi_len)
        char* envpi_tmp = new char[envpi_len];
        fnla_get_bytes(fnla, envpi_tmp, envpi_len);
        rt->envp_buf.push_back(std::string(envpi_tmp, envpi_len));
        delete[] envpi_tmp;
    }

    rt->finished = true;
    return rt;
}

auto parse_mmap(fnla_t fnla) {
    auto rt = std::make_unique<Mmap>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mmap";

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, prot)
    rt->prot = prot;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S64(fnla, offset)
    rt->offset = offset;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fadvise64(fnla_t fnla) {
    auto rt = std::make_unique<Fadvise64>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fadvise64";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S64(fnla, offset)
    rt->offset = offset;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, advice)
    rt->advice = advice;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_swapon(fnla_t fnla) {
    auto rt = std::make_unique<Swapon>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "swapon";

    NLA_GET_U64(fnla, specialfile)
    rt->specialfile = specialfile;

    NLA_GET_S32(fnla, swap_flags)
    rt->swap_flags = swap_flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (specialfile) {
        NLA_GET_U32(fnla, path_len)
        char* path = new char[path_len];
        fnla_get_bytes(fnla, path, path_len);
        rt->path_buf = std::string(path, path_len);
        delete[] path;
    }

    rt->finished = true;
    return rt;
}

auto parse_swapoff(fnla_t fnla) {
    auto rt = std::make_unique<Swapoff>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "swapoff";

    NLA_GET_U64(fnla, specialfile)
    rt->specialfile = specialfile;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    // 解析路径字符串（如果存在）
    if (specialfile) {
        NLA_GET_U32(fnla, path_len)
        char* path = new char[path_len];
        fnla_get_bytes(fnla, path, path_len);
        rt->path_buf = std::string(path, path_len);
        delete[] path;
    }

    rt->finished = true;
    return rt;
}

auto parse_mprotect(fnla_t fnla) {
    auto rt = std::make_unique<Mprotect>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mprotect";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_U64(fnla, prot)
    rt->prot = prot;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_msync(fnla_t fnla) {
    auto rt = std::make_unique<Msync>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "msync";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mlock(fnla_t fnla) {
    auto rt = std::make_unique<Mlock>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mlock";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_munlock(fnla_t fnla) {
    auto rt = std::make_unique<Munlock>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "munlock";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mlockall(fnla_t fnla) {
    auto rt = std::make_unique<Mlockall>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mlockall";

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_munlockall(fnla_t fnla) {
    auto rt = std::make_unique<Munlockall>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "munlockall";

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mincore(fnla_t fnla) {
    auto rt = std::make_unique<Mincore>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mincore";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_U64(fnla, vec)
    rt->vec = vec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_madvise(fnla_t fnla) {
    auto rt = std::make_unique<Madvise>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "madvise";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U32(fnla, len)
    rt->len = len;

    NLA_GET_S32(fnla, behavior)
    rt->behavior = behavior;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_remap_file_pages(fnla_t fnla) {
    auto rt = std::make_unique<RemapFilePages>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "remap_file_pages";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U64(fnla, size)
    rt->size = size;

    NLA_GET_U64(fnla, prot)
    rt->prot = prot;

    NLA_GET_U64(fnla, pgoff)
    rt->pgoff = pgoff;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mbind(fnla_t fnla) {
    auto rt = std::make_unique<Mbind>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mbind";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_U64(fnla, mode)
    rt->mode = mode;

    NLA_GET_U64(fnla, nmask)
    rt->nmask = nmask;

    NLA_GET_U64(fnla, maxnode)
    rt->maxnode = maxnode;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_set_mempolicy(fnla_t fnla) {
    auto rt = std::make_unique<SetMempolicy>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "set_mempolicy";

    NLA_GET_S32(fnla, mode)
    rt->mode = mode;

    NLA_GET_U64(fnla, nmask)
    rt->nmask = nmask;

    NLA_GET_U64(fnla, maxnode)
    rt->maxnode = maxnode;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_get_mempolicy(fnla_t fnla) {
    auto rt = std::make_unique<GetMempolicy>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "get_mempolicy";

    NLA_GET_U64(fnla, policy)
    rt->policy = policy;

    NLA_GET_U64(fnla, nmask)
    rt->nmask = nmask;

    NLA_GET_U64(fnla, maxnode)
    rt->maxnode = maxnode;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_migrate_pages(fnla_t fnla) {
    auto rt = std::make_unique<MigratePages>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "migrate_pages";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, maxnode)
    rt->maxnode = maxnode;

    NLA_GET_U64(fnla, old_nodes)
    rt->old_nodes = old_nodes;

    NLA_GET_U64(fnla, new_nodes)
    rt->new_nodes = new_nodes;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_move_pages(fnla_t fnla) {
    auto rt = std::make_unique<MovePages>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "move_pages";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, count)
    rt->count = count;

    NLA_GET_U64(fnla, pages)
    rt->pages = pages;

    NLA_GET_U64(fnla, nodes)
    rt->nodes = nodes;

    NLA_GET_U64(fnla, status)
    rt->status = status;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rt_tgsigqueueinfo(fnla_t fnla) {
    auto rt = std::make_unique<RtTgsigqueueinfo>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rt_tgsigqueueinfo";

    NLA_GET_S32(fnla, tgid)
    rt->tgid = tgid;

    NLA_GET_S32(fnla, tid)
    rt->tid = tid;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_U64(fnla, uinfo)
    rt->uinfo = uinfo;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_perf_event_open(fnla_t fnla) {
    auto rt = std::make_unique<PerfEventOpen>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "perf_event_open";

    NLA_GET_U64(fnla, attr_uptr)
    rt->attr_uptr = attr_uptr;

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_S32(fnla, cpu)
    rt->cpu = cpu;

    NLA_GET_S32(fnla, group_fd)
    rt->group_fd = group_fd;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_accept4(fnla_t fnla) {
    auto rt = std::make_unique<Accept4>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "accept4";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, addr)
    rt->addr = addr;

    NLA_GET_U64(fnla, addrlen)
    rt->addrlen = addrlen;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_recvmmsg(fnla_t fnla) {
    auto rt = std::make_unique<Recvmmsg>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "recvmmsg";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, msgvec)
    rt->msgvec = msgvec;

    NLA_GET_U32(fnla, vlen)
    rt->vlen = vlen;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_arch_specific_syscall(fnla_t fnla) {
    auto rt = std::make_unique<ArchSpecificSyscall>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "arch_specific_syscall";

    NLA_GET_U64(fnla, arg1)
    rt->arg1 = arg1;

    NLA_GET_U64(fnla, arg2)
    rt->arg2 = arg2;

    NLA_GET_U64(fnla, arg3)
    rt->arg3 = arg3;

    NLA_GET_U64(fnla, arg4)
    rt->arg4 = arg4;

    NLA_GET_U64(fnla, arg5)
    rt->arg5 = arg5;

    NLA_GET_U64(fnla, arg6)
    rt->arg6 = arg6;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_wait4(fnla_t fnla) {
    auto rt = std::make_unique<Wait4>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "wait4";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, wstatus)
    rt->wstatus = wstatus;

    NLA_GET_S32(fnla, options)
    rt->options = options;

    NLA_GET_U64(fnla, ru)
    rt->ru = ru;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_prlimit64(fnla_t fnla) {
    auto rt = std::make_unique<Prlimit64>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "prlimit64";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U32(fnla, resource)
    rt->resource = resource;

    NLA_GET_U64(fnla, new_rlim)
    rt->new_rlim = new_rlim;

    NLA_GET_U64(fnla, old_rlim)
    rt->old_rlim = old_rlim;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fanotify_init(fnla_t fnla) {
    auto rt = std::make_unique<FanotifyInit>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fanotify_init";

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, event_f_flags)
    rt->event_f_flags = event_f_flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fanotify_mark(fnla_t fnla) {
    auto rt = std::make_unique<FanotifyMark>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fanotify_mark";

    NLA_GET_S32(fnla, fanotify_fd)
    rt->fanotify_fd = fanotify_fd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, mask)
    rt->mask = mask;

    NLA_GET_S32(fnla, dirfd)
    rt->dirfd = dirfd;

    NLA_GET_U64(fnla, pathname)
    rt->pathname = pathname;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_name_to_handle_at(fnla_t fnla) {
    auto rt = std::make_unique<NameToHandleAt>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "name_to_handle_at";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, name)
    rt->name = name;

    NLA_GET_U64(fnla, handle)
    rt->handle = handle;

    NLA_GET_U64(fnla, mnt_id)
    rt->mnt_id = mnt_id;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_open_by_handle_at(fnla_t fnla) {
    auto rt = std::make_unique<OpenByHandleAt>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "open_by_handle_at";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, handle)
    rt->handle = handle;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clock_adjtime(fnla_t fnla) {
    auto rt = std::make_unique<ClockAdjtime>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clock_adjtime";

    NLA_GET_S32(fnla, which_clock)
    rt->which_clock = which_clock;

    NLA_GET_U64(fnla, tx)
    rt->tx = tx;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_syncfs(fnla_t fnla) {
    auto rt = std::make_unique<Syncfs>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "syncfs";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_setns(fnla_t fnla) {
    auto rt = std::make_unique<Setns>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "setns";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_S32(fnla, nstype)
    rt->nstype = nstype;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sendmmsg(fnla_t fnla) {
    auto rt = std::make_unique<Sendmmsg>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sendmmsg";

    NLA_GET_S32(fnla, sockfd)
    rt->sockfd = sockfd;

    NLA_GET_U64(fnla, msgvec)
    rt->msgvec = msgvec;

    NLA_GET_U32(fnla, vlen)
    rt->vlen = vlen;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_process_vm_readv(fnla_t fnla) {
    auto rt = std::make_unique<ProcessVmReadv>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "process_vm_readv";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, lvec)
    rt->lvec = lvec;

    NLA_GET_U64(fnla, liovcnt)
    rt->liovcnt = liovcnt;

    NLA_GET_U64(fnla, rvec)
    rt->rvec = rvec;

    NLA_GET_U64(fnla, riovcnt)
    rt->riovcnt = riovcnt;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_process_vm_writev(fnla_t fnla) {
    auto rt = std::make_unique<ProcessVmWritev>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "process_vm_writev";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, lvec)
    rt->lvec = lvec;

    NLA_GET_U64(fnla, liovcnt)
    rt->liovcnt = liovcnt;

    NLA_GET_U64(fnla, rvec)
    rt->rvec = rvec;

    NLA_GET_U64(fnla, riovcnt)
    rt->riovcnt = riovcnt;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_kcmp(fnla_t fnla) {
    auto rt = std::make_unique<Kcmp>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "kcmp";

    NLA_GET_S32(fnla, pid1)
    rt->pid1 = pid1;

    NLA_GET_S32(fnla, pid2)
    rt->pid2 = pid2;

    NLA_GET_S32(fnla, type)
    rt->type = type;

    NLA_GET_U64(fnla, idx1)
    rt->idx1 = idx1;

    NLA_GET_U64(fnla, idx2)
    rt->idx2 = idx2;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_finit_module(fnla_t fnla) {
    auto rt = std::make_unique<FinitModule>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "finit_module";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, uargs)
    rt->uargs = uargs;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_setattr(fnla_t fnla) {
    auto rt = std::make_unique<SchedSetattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_setattr";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, attr)
    rt->attr = attr;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_sched_getattr(fnla_t fnla) {
    auto rt = std::make_unique<SchedGetattr>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "sched_getattr";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U64(fnla, attr)
    rt->attr = attr;

    NLA_GET_U32(fnla, size)
    rt->size = size;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_renameat2(fnla_t fnla) {
    auto rt = std::make_unique<Renameat2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "renameat2";

    NLA_GET_S32(fnla, olddfd)
    rt->olddfd = olddfd;

    NLA_GET_U64(fnla, oldnamea)
    rt->oldname = oldnamea;

    NLA_GET_S32(fnla, newdfd)
    rt->newdfd = newdfd;

    NLA_GET_U64(fnla, newnamea)
    rt->newname = newnamea;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (rt->oldname) {
        NLA_GET_U32(fnla, oldname_len)
        char* oldname = new char[oldname_len];
        fnla_get_bytes(fnla, oldname, oldname_len);
        rt->oldname_str = std::string(oldname, oldname_len);
        delete[] oldname;
    }

    if (rt->newname) {
        NLA_GET_U32(fnla, newname_len)
        char* newname = new char[newname_len];
        fnla_get_bytes(fnla, newname, newname_len);
        rt->newname_str = std::string(newname, newname_len);
        delete[] newname;
    }

    rt->finished = true;
    return rt;
}

auto parse_seccomp(fnla_t fnla) {
    auto rt = std::make_unique<Seccomp>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "seccomp";

    NLA_GET_U32(fnla, op)
    rt->op = op;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, uargs)
    rt->uargs = uargs;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_getrandom(fnla_t fnla) {
    auto rt = std::make_unique<Getrandom>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "getrandom";

    NLA_GET_U64(fnla, buf)
    rt->buf = buf;

    NLA_GET_U64(fnla, buflen)
    rt->buflen = buflen;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_memfd_create(fnla_t fnla) {
    auto rt = std::make_unique<MemfdCreate>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "memfd_create";

    NLA_GET_U64(fnla, uname)
    rt->uname = uname;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    // Parsing the optional "name" field
    if (uname) {
        NLA_GET_U32(fnla, len)

        char* name_buf = new char[len];
        fnla_get_bytes(fnla, name_buf, len);
        rt->name = std::string(name_buf, len);
        delete[] name_buf;
    }

    rt->finished = true;
    return rt;
}

auto parse_bpf(fnla_t fnla) {
    auto rt = std::make_unique<Bpf>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "bpf";

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, attr)
    rt->attr = attr;

    NLA_GET_U32(fnla, size)
    rt->size = size;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_execveat(fnla_t fnla) {
    auto rt = std::make_unique<Execveat>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "execveat";

    NLA_GET_S32(fnla, dfd)
    rt->ret = dfd;

    NLA_GET_U64(fnla, filename)
    rt->filename = filename;

    NLA_GET_U64(fnla, argv)
    rt->argv = argv;

    NLA_GET_U64(fnla, envp)
    rt->envp = envp;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (filename) {
        NLA_GET_U32(fnla, filename_len)
        char* filename_tmp = new char[filename_len];
        fnla_get_bytes(fnla, filename_tmp, filename_len);
        rt->filename_buf = std::string(filename_tmp, filename_len);
        delete[] filename_tmp;
    }

    NLA_GET_S32(fnla, argc)
    rt->argc = argc;

    for (int i = 0; i < argc; ++i) {
        NLA_GET_U64(fnla, argv_p)
        if (argv_p == 0) {
            NLA_GET_U32(fnla, errno_)
            std::cerr << "Parse execve‘s argv failed, error = " << errno_ << ", i = " << i << std::endl;
            continue;
        }
        NLA_GET_U32(fnla, argvi_len)
        char* argvi_tmp = new char[argvi_len];
        fnla_get_bytes(fnla, argvi_tmp, argvi_len);
        rt->argv_buf.push_back(std::string(argvi_tmp, argvi_len));
        delete[] argvi_tmp;
    }

    NLA_GET_S32(fnla, envc)
    rt->envc = envc;

    for (int i = 0; i < envc; ++i) {
        NLA_GET_U64(fnla, envp_p)
        if (envp_p == 0) {
            NLA_GET_U32(fnla, errno_)
            std::cerr << "Parse execve's env failed, error = " << errno_ << ", i = " << i << std::endl;
            continue;
        }
        NLA_GET_U32(fnla, envpi_len)
        char* envpi_tmp = new char[envpi_len];
        fnla_get_bytes(fnla, envpi_tmp, envpi_len);
        rt->envp_buf.push_back(std::string(envpi_tmp, envpi_len));
        delete[] envpi_tmp;
    }

    rt->finished = true;
    return rt;
}

auto parse_userfaultfd(fnla_t fnla) {
    auto rt = std::make_unique<Userfaultfd>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "userfaultfd";

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_membarrier(fnla_t fnla) {
    auto rt = std::make_unique<Membarrier>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "membarrier";

    NLA_GET_S32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, cpu_id)
    rt->cpu_id = cpu_id;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_mlock2(fnla_t fnla) {
    auto rt = std::make_unique<Mlock2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "mlock2";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_copy_file_range(fnla_t fnla) {
    auto rt = std::make_unique<CopyFileRange>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "copy_file_range";

    NLA_GET_S32(fnla, fd_in)
    rt->fd_in = fd_in;

    NLA_GET_U64(fnla, off_in)
    rt->off_in = off_in;

    NLA_GET_S32(fnla, fd_out)
    rt->fd_out = fd_out;

    NLA_GET_U64(fnla, off_out)
    rt->off_out = off_out;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_preadv2(fnla_t fnla) {
    auto rt = std::make_unique<Preadv2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "preadv2";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, iov)
    rt->iov = iov;

    NLA_GET_S32(fnla, iovcnt)
    rt->iovcnt = iovcnt;

    NLA_GET_S64(fnla, offset)
    rt->offset = offset;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pwritev2(fnla_t fnla) {
    auto rt = std::make_unique<Pwritev2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pwritev2";

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U64(fnla, iov)
    rt->iov = iov;

    NLA_GET_S32(fnla, iovcnt)
    rt->iovcnt = iovcnt;

    NLA_GET_S64(fnla, offset)
    rt->offset = offset;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S64(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pkey_mprotect(fnla_t fnla) {
    auto rt = std::make_unique<PkeyMprotect>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pkey_mprotect";

    NLA_GET_U64(fnla, start)
    rt->start = start;

    NLA_GET_U64(fnla, len)
    rt->len = len;

    NLA_GET_U64(fnla, prot)
    rt->prot = prot;

    NLA_GET_S32(fnla, pkey)
    rt->pkey = pkey;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pkey_alloc(fnla_t fnla) {
    auto rt = std::make_unique<PkeyAlloc>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pkey_alloc";

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, access_rights)
    rt->access_rights = access_rights;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pkey_free(fnla_t fnla) {
    auto rt = std::make_unique<PkeyFree>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pkey_free";

    NLA_GET_S32(fnla, pkey)
    rt->pkey = pkey;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_statx(fnla_t fnla) {
    auto rt = std::make_unique<Statx>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "statx";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, path)
    rt->path = path;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, mask)
    rt->mask = mask;

    NLA_GET_U64(fnla, buffer)
    rt->buffer = buffer;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    if (path) {
        NLA_GET_U32(fnla, path_len);
        char* path_str = new char[path_len];
        fnla_get_bytes(fnla, path_str, path_len);
        rt->path_str = std::string(path_str, path_len);
        delete[] path_str;
    }

    rt->finished = true;
    return rt;
}

auto parse_io_pgetevents(fnla_t fnla) {
    auto rt = std::make_unique<IoPgetevents>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_pgetevents";

    NLA_GET_U64(fnla, ctx_id)
    rt->ctx_id = ctx_id;

    NLA_GET_S64(fnla, min_nr)
    rt->min_nr = min_nr;

    NLA_GET_S64(fnla, nr)
    rt->nr = nr;

    NLA_GET_U64(fnla, events)
    rt->events = events;

    NLA_GET_U64(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_U64(fnla, timespec)
    rt->timespec = timespec;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_rseq(fnla_t fnla) {
    auto rt = std::make_unique<Rseq>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "rseq";

    NLA_GET_U64(fnla, rseq)
    rt->rseq = rseq;

    NLA_GET_U32(fnla, rseq_len)
    rt->rseq_len = rseq_len;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_kexec_file_load(fnla_t fnla) {
    auto rt = std::make_unique<KexecFileLoad>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "kexec_file_load";

    NLA_GET_S32(fnla, kernel_fd)
    rt->kernel_fd = kernel_fd;

    NLA_GET_S32(fnla, initrd_fd)
    rt->initrd_fd = initrd_fd;

    NLA_GET_U64(fnla, cmdline_len)
    rt->cmdline_len = cmdline_len;

    NLA_GET_U64(fnla, cmdline)
    rt->cmdline = cmdline;

    NLA_GET_U64(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pidfd_send_signal(fnla_t fnla) {
    auto rt = std::make_unique<PidfdSendSignal>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pidfd_send_signal";

    NLA_GET_S32(fnla, pidfd)
    rt->pidfd = pidfd;

    NLA_GET_S32(fnla, sig)
    rt->sig = sig;

    NLA_GET_U64(fnla, info)
    rt->info = info;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_io_uring_setup(fnla_t fnla) {
    auto rt = std::make_unique<IoUringSetup>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_uring_setup";

    NLA_GET_U32(fnla, entries)
    rt->entries = entries;

    NLA_GET_U64(fnla, p)
    rt->p = p;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_io_uring_enter(fnla_t fnla) {
    auto rt = std::make_unique<IoUringEnter>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_uring_enter";

    NLA_GET_U32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, to_submit)
    rt->to_submit = to_submit;

    NLA_GET_U32(fnla, min_complete)
    rt->min_complete = min_complete;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U64(fnla, sig)
    rt->sig = sig;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_io_uring_register(fnla_t fnla) {
    auto rt = std::make_unique<IoUringRegister>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "io_uring_register";

    NLA_GET_U32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, opcode)
    rt->opcode = opcode;

    NLA_GET_U64(fnla, arg)
    rt->arg = arg;

    NLA_GET_U32(fnla, nr_args)
    rt->nr_args = nr_args;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_open_tree(fnla_t fnla) {
    auto rt = std::make_unique<OpenTree>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "open_tree";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, filename)
    rt->filename = filename;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_move_mount(fnla_t fnla) {
    auto rt = std::make_unique<MoveMount>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "move_mount";

    NLA_GET_S32(fnla, from_dfd)
    rt->from_dfd = from_dfd;

    NLA_GET_U64(fnla, from_pathname)
    rt->from_pathname = from_pathname;

    NLA_GET_S32(fnla, to_dfd)
    rt->to_dfd = to_dfd;

    NLA_GET_U64(fnla, to_pathname)
    rt->to_pathname = to_pathname;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fsopen(fnla_t fnla) {
    auto rt = std::make_unique<Fsopen>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fsopen";

    NLA_GET_U64(fnla, fs_name)
    rt->fs_name = fs_name;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fsconfig(fnla_t fnla) {
    auto rt = std::make_unique<Fsconfig>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fsconfig";

    NLA_GET_S32(fnla, fs_fd)
    rt->fs_fd = fs_fd;

    NLA_GET_U32(fnla, cmd)
    rt->cmd = cmd;

    NLA_GET_U64(fnla, key)
    rt->key = key;

    NLA_GET_U64(fnla, value)
    rt->value = value;

    NLA_GET_U32(fnla, aux)
    rt->aux = aux;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fsmount(fnla_t fnla) {
    auto rt = std::make_unique<Fsmount>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fsmount";

    NLA_GET_S32(fnla, fs_fd)
    rt->fs_fd = fs_fd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, ms_flags)
    rt->ms_flags = ms_flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_fspick(fnla_t fnla) {
    auto rt = std::make_unique<Fspick>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "fspick";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, path)
    rt->path = path;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pidfd_open(fnla_t fnla) {
    auto rt = std::make_unique<PidfdOpen>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pidfd_open";

    NLA_GET_S32(fnla, pid)
    rt->pid = pid;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_clone3(fnla_t fnla) {
    auto rt = std::make_unique<Clone3>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "clone3";

    NLA_GET_U64(fnla, uargs)
    rt->uargs = uargs;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_close_range(fnla_t fnla) {
    auto rt = std::make_unique<CloseRange>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "close_range";

    NLA_GET_U32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, max_fd)
    rt->max_fd = max_fd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_openat2(fnla_t fnla) {
    auto rt = std::make_unique<Openat2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "openat2";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, filename)
    rt->filename = filename;

    NLA_GET_U64(fnla, how)
    rt->how = how;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_pidfd_getfd(fnla_t fnla) {
    auto rt = std::make_unique<PidfdGetfd>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "pidfd_getfd";

    NLA_GET_S32(fnla, pidfd)
    rt->pidfd = pidfd;

    NLA_GET_S32(fnla, fd)
    rt->fd = fd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_faccessat2(fnla_t fnla) {
    auto rt = std::make_unique<Faccessat2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "faccessat2";

    NLA_GET_S32(fnla, dfd)
    rt->dfd = dfd;

    NLA_GET_U64(fnla, filename)
    rt->filename = filename;

    NLA_GET_S32(fnla, mode)
    rt->mode = mode;

    NLA_GET_S32(fnla, flags)
    rt->flags = flags;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_process_madvise(fnla_t fnla) {
    auto rt = std::make_unique<ProcessMadvise>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "process_madvise";

    NLA_GET_S32(fnla, pidfd)
    rt->pidfd = pidfd;

    NLA_GET_U32(fnla, flags)
    rt->flags = flags;

    NLA_GET_U32(fnla, advice)
    rt->advice = advice;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

auto parse_epoll_pwait2(fnla_t fnla) {
    auto rt = std::make_unique<EpollPwait2>();
    PARSE_REFERER(fnla, rt)
    rt->syscallName = "epoll_pwait2";

    NLA_GET_S32(fnla, epfd)
    rt->epfd = epfd;

    NLA_GET_U64(fnla, events)
    rt->events = events;

    NLA_GET_S32(fnla, maxevents)
    rt->maxevents = maxevents;

    NLA_GET_S32(fnla, timeout)
    rt->timeout = timeout;

    NLA_GET_U64(fnla, sigmask)
    rt->sigmask = sigmask;

    NLA_GET_U32(fnla, sigsetsize)
    rt->sigsetsize = sigsetsize;

    NLA_GET_S32(fnla, ret)
    rt->ret = ret;

    rt->finished = true;
    return rt;
}

std::unique_ptr<Syscall> trs::parser::parseSyscallEnd(fnla_t fnla) {
    static std::unordered_map<std::string, std::function<std::unique_ptr<Syscall>(fnla_t)>> m = {
            /* aio.c */
        PARSER(io_setup),
        PARSER(io_destroy),
        PARSER(io_submit),
        PARSER(io_cancel),
        PARSER(io_getevents),
            /* xattr.c */
        PARSER(setxattr),
        PARSER(lsetxattr),
        PARSER(fsetxattr),
        PARSER(getxattr),
        PARSER(lgetxattr),
        PARSER(fgetxattr),
        PARSER(listxattr),
        PARSER(llistxattr),
        PARSER(flistxattr),
        PARSER(removexattr),
        PARSER(lremovexattr),
        PARSER(fremovexattr),
            /* unistd.h */
        PARSER(getcwd),
        PARSER(lookup_dcookie),
            /* eventfd.c */
        PARSER(eventfd),
        PARSER(eventfd2),
            /* epoll.c */
        PARSER(epoll_create),
        PARSER(epoll_create1),
        PARSER(epoll_ctl),
        PARSER(epoll_wait),
        PARSER(epoll_pwait),
            /* fcntl.c */
        PARSER(dup),
        PARSER(dup2),
        PARSER(dup3),
        PARSER(fnctl),
            /* inotify.c */
        PARSER(inotify_init),
        PARSER(inotify_init1),
        PARSER(inotify_add_watch),
        PARSER(inotify_rm_watch),
            /* ioctl.c */
        PARSER(ioctl),
            /* ioprio.c */
        PARSER(ioprio_set),
        PARSER(ioprio_get),
            /* flock.c */
        PARSER(flock),
            /* fs.c */
        PARSER(mknodat),
        PARSER(mkdirat),
        PARSER(unlinkat),
        PARSER(symlinkat),
        PARSER(linkat),
        PARSER(renameat),
        PARSER(umount2),
        PARSER(mount),
        PARSER(privot_root),
            /* nfsctl.c */
        PARSER(nfsservctl),
            /* statfs.c */
        PARSER(statfs),
        PARSER(fstatfs),
            /* truncate.c */
        PARSER(truncate),
        PARSER(ftruncate),
        PARSER(fallocate),
            /* fs.c */
        PARSER(faccessat),
            /* fs.c */
        PARSER(chdir),
        PARSER(fchdir),
        PARSER(chroot),
        PARSER(fchmod),
        PARSER(fchmodat),
        PARSER(fchown),
        PARSER(fchownat),
        PARSER(openat),
        PARSER(close),
        PARSER(vhangup),
        PARSER(pipe2),
        PARSER(quotactl),
        PARSER(getdents64),
        PARSER(lseek),
        PARSER(read),
        PARSER(write),
        PARSER(readv),
        PARSER(writev),
        PARSER(pread64),
        PARSER(pwrite64),
        PARSER(preadv),
        PARSER(pwritev),
        PARSER(sendfile),
        PARSER(pselect6),
        PARSER(ppoll),
        PARSER(signalfd4),
        PARSER(vmsplice),
        PARSER(splice),
        PARSER(tee),
        PARSER(readlinkat),
        PARSER(fstatat),
        PARSER(fstat),
        PARSER(sync),
        PARSER(fsync),
        PARSER(fdatasync),
        PARSER(sync_file_range2),
        PARSER(sync_file_range),
        PARSER(timerfd_create),
        PARSER(timerfd_settime),
        PARSER(timerfd_gettime),
        PARSER(utimensat),
        PARSER(acct),
        PARSER(capget),
        PARSER(personality),
        PARSER(exit),
        PARSER(exit_group),
        PARSER(waitid),
        PARSER(set_tid_address),
        PARSER(unshare),
        PARSER(set_robust_list),
        PARSER(get_robust_list),
        PARSER(nanosleep),
        PARSER(getitimer),
        PARSER(setitimer),
        PARSER(kexec_load),
        PARSER(init_module),
        PARSER(delete_module),
        PARSER(timer_create),
        PARSER(timer_gettime),
        PARSER(timer_getoverrun),
        PARSER(timer_settime),
        PARSER(timer_delete),
        PARSER(clock_settime),
        PARSER(clock_gettime),
        PARSER(clock_getres),
        PARSER(clock_nanosleep),
        PARSER(syslog),
        PARSER(ptrace),
        PARSER(sched_setparam),
        PARSER(sched_setscheduler),
        PARSER(sched_getscheduler),
        PARSER(sched_getparam),
        PARSER(sched_setaffinity),
        PARSER(sched_getaffinity),
        PARSER(sched_yield),
        PARSER(sched_get_priority_max),
        PARSER(sched_get_priority_min),
        PARSER(sched_rr_get_interval),
        PARSER(restart_syscall),
        PARSER(kill),
        PARSER(tkill),
        PARSER(tgkill),
        PARSER(sigaltstack),
        PARSER(rt_sigsuspend),
        PARSER(rt_sigaction),
        PARSER(rt_sigprocmask),
        PARSER(rt_sigpending),
        PARSER(rt_sigtimedwait),
        PARSER(rt_sigqueueinfo),
        PARSER(rt_sigreturn),
        PARSER(setpriority),
        PARSER(getpriority),
        PARSER(reboot),
        PARSER(setregid),
        PARSER(setgid),
        PARSER(setreuid),
        PARSER(setuid),
        PARSER(setresuid),
        PARSER(getresuid),
        PARSER(setresgid),
        PARSER(getresgid),
        PARSER(setfsuid),
        PARSER(setfsgid),
        PARSER(times),
        PARSER(setpgid),
        PARSER(getpgid),
        PARSER(getsid),
        PARSER(setsid),
        PARSER(getgroups),
        PARSER(setgroups),
        PARSER(uname),
        PARSER(setdomainname),
        PARSER(getrlimit),
        PARSER(setrlimit),
        PARSER(getrusage),
        PARSER(umask),
        PARSER(prctl),
        PARSER(getcpu),
        PARSER(gettimeofday),
        PARSER(settimeofday),
        PARSER(adjtimex),
        PARSER(getpid),
        PARSER(getppid),
        PARSER(getuid),
        PARSER(geteuid),
        PARSER(getgid),
        PARSER(getegid),
        PARSER(gettid),
        PARSER(sysinfo),
        PARSER(mq_open),
        PARSER(mq_unlink),
        PARSER(mq_timedsend),
        PARSER(mq_timedreceive),
        PARSER(mq_notify),
        PARSER(mq_getsetattr),
        PARSER(msgget),
        PARSER(msgctl),
        PARSER(msgsnd),
        PARSER(msgrcv),
        PARSER(semget),
        PARSER(semctl),
        PARSER(semtimedop),
        PARSER(semop),
        PARSER(shmget),
        PARSER(shmctl),
        PARSER(shmat),
        PARSER(shmdt),
        PARSER(socket),
        PARSER(socketpair),
        PARSER(bind),
        PARSER(listen),
        PARSER(accept),
        PARSER(connect),
        PARSER(getsockname),
        PARSER(getpeername),
        PARSER(sendto),
        PARSER(recvfrom),
        PARSER(setsockopt),
        PARSER(getsockopt),
        PARSER(shutdown),
        PARSER(sendmsg),
        PARSER(recvmsg),
        PARSER(readahead),
        PARSER(brk),
        PARSER(munmap),
        PARSER(mremap),
        PARSER(add_key),
        PARSER(request_key),
        PARSER(keyctl),
        PARSER(clone),
        PARSER(execve),
        PARSER(mmap),
        PARSER(fadvise64),
        PARSER(swapon),
        PARSER(swapoff),
        PARSER(mprotect),
        PARSER(msync),
        PARSER(mlock),
        PARSER(munlock),
        PARSER(mlockall),
        PARSER(munlockall),
        PARSER(mincore),
        PARSER(madvise),
        PARSER(remap_file_pages),
        PARSER(mbind),
        PARSER(get_mempolicy),
        PARSER(set_mempolicy),
        PARSER(migrate_pages),
        PARSER(move_pages),
        PARSER(rt_tgsigqueueinfo),
        PARSER(perf_event_open),
        PARSER(accept4),
        PARSER(recvmmsg),
        PARSER(arch_specific_syscall),
        PARSER(wait4),
        PARSER(prlimit64),
        PARSER(fanotify_init),
        PARSER(fanotify_mark),
        PARSER(name_to_handle_at),
        PARSER(open_by_handle_at),
        PARSER(clock_adjtime),
        PARSER(syncfs),
        PARSER(setns),
        PARSER(sendmmsg),
        PARSER(process_vm_readv),
        PARSER(process_vm_writev),
        PARSER(kcmp),
        PARSER(finit_module),
        PARSER(sched_setattr),
        PARSER(sched_getattr),
        PARSER(renameat2),
        PARSER(seccomp),
        PARSER(getrandom),
        PARSER(memfd_create),
        PARSER(bpf),
        PARSER(execveat),
        PARSER(userfaultfd),
        PARSER(membarrier),
        PARSER(mlock2),
        PARSER(copy_file_range),
        PARSER(preadv2),
        PARSER(pwritev2),
        PARSER(pkey_mprotect),
        PARSER(pkey_alloc),
        PARSER(pkey_free),
        PARSER(statx),
        PARSER(io_pgetevents),
        PARSER(rseq),
        PARSER(kexec_file_load),
        PARSER(pidfd_send_signal),
        PARSER(io_uring_setup),
        PARSER(io_uring_enter),
        PARSER(io_uring_register),
        PARSER(open_tree),
        PARSER(move_mount),
        PARSER(fsopen),
        PARSER(fsconfig),
        PARSER(fsmount),
        PARSER(fspick),
        PARSER(pidfd_open),
        PARSER(clone3),
        PARSER(close_range),
        PARSER(openat2),
        PARSER(pidfd_getfd),
        PARSER(faccessat2),
        PARSER(process_madvise),
        PARSER(epoll_pwait2),
    };

    NLA_GET_U32(fnla, total_len)
    NLA_GET_U32(fnla, syscall_len)
    char* syscall_name = new char[syscall_len];
    fnla_get_bytes(fnla, syscall_name, syscall_len);
    fnla->pos++; // skip '\0'
    std::string name(syscall_name, syscall_len);
    delete[] syscall_name;
    NLA_GET_U32(fnla, data_len)

    auto it = m.find(name);
    if (it != m.end()) {
       return it->second(fnla);
    } else {
        std::cerr << "Unknown syscall: " << name << std::endl;
    }

    return nullptr;
}