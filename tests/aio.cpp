//
// Created by fuqiuluo on 25-1-7.
//
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/aio_abi.h>
#include <linux/errno.h>
#include <syscall.h>

// io_setup - 创建异步 I/O 上下文
static inline long io_setup(unsigned nr, aio_context_t *ctxp) {
    register long x8 asm("x8") = SYS_io_setup; // 系统调用号放在 x8
    register long x0 asm("x0") = nr;           // 第一个参数放在 x0
    register long x1 asm("x1") = (long)ctxp;   // 第二个参数放在 x1
    asm volatile(
            "svc 0"             // 发出系统调用
            : "+r"(x0)          // x0 是输出，返回值在 x0
            : "r"(x1), "r"(x8)  // x1 是输入参数，x8 是 syscall 号
            : "memory"          // 声明 memory 可能被修改，避免编译器优化
            );
    return x0; // 返回值存储在 x0 中
}


// io_submit - 提交异步 I/O 请求
static inline long io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) {
    register long x8 asm("x8") = SYS_io_submit; // 系统调用号放在 x8
    register long x0 asm("x0") = ctx;           // 第一个参数放在 x0
    register long x1 asm("x1") = nr;            // 第二个参数放在 x1
    register long x2 asm("x2") = (long)iocbpp;  // 第三个参数放在 x2
    asm volatile(
            "svc 0"             // 发出系统调用
            : "+r"(x0)          // x0 是输出，返回值在 x0
            : "r"(x1), "r"(x2), "r"(x8)  // x1, x2 是输入参数，x8 是 syscall 号
            : "memory"          // 声明 memory 可能被修改，避免编译器优化
            );
    return x0; // 返回值存储在 x0 中
}

// io_getevents - 等待异步 I/O 事件完成
static inline long io_getevents(aio_context_t ctx, long min_nr, long max_nr, void *events, void *timeout) {
    register long x8 asm("x8") = SYS_io_getevents; // 系统调用号放在 x8
    register long x0 asm("x0") = ctx;              // 第一个参数放在 x0
    register long x1 asm("x1") = min_nr;           // 第二个参数放在 x1
    register long x2 asm("x2") = max_nr;           // 第三个参数放在 x2
    register long x3 asm("x3") = (long)events;     // 第四个参数放在 x3
    register long x4 asm("x4") = (long)timeout;    // 第五个参数放在 x4
    asm volatile(
            "svc 0"             // 发出系统调用
            : "+r"(x0)          // x0 是输出，返回值在 x0
            : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)  // x1, x2, x3, x4 是输入参数，x8 是 syscall 号
            : "memory"          // 声明 memory 可能被修改，避免编译器优化
            );
    return x0; // 返回值存储在 x0 中
}

static inline long io_destroy(aio_context_t ctx) {
    register long x8 asm("x8") = SYS_io_destroy; // 系统调用号放在 x8
    register long x0 asm("x0") = ctx;            // 第一个参数放在 x0
    asm volatile(
            "svc 0"             // 发出系统调用
            : "+r"(x0)          // x0 是输出，返回值在 x0
            : "r"(x8)           // x8 是 syscall 号
            : "memory"          // 声明 memory 可能被修改，避免编译器优化
            );
    return x0; // 返回值存储在 x0 中
}

int main() {
    aio_context_t ctx;              // io_context_t
    struct iocb iocb;              // IO 控制块
    struct iocb *iocbs[1];         // IO 控制块数组
    char *buffer;                  // 数据缓冲区
    int fd;
    long ret;

    // 分配对齐的缓冲区 (512 字节对齐)
    if (posix_memalign((void **)&buffer, 512, 4096)) {
        perror("posix_memalign");
        return 1;
    }
    strcpy(buffer, "Hello, io_submit from ARM64!\n");

    // 打开文件
    fd = open("output.txt", O_WRONLY | O_CREAT | O_DIRECT, 0644);
    if (fd < 0) {
        perror("open");
        free(buffer);
        return 1;
    }

    // 创建 AIO 上下文
    ret = io_setup(10, &ctx); // 队列深度 = 10
    if (ret < 0) {
        fprintf(stderr, "io_setup failed: %ld\n", ret);
        close(fd);
        free(buffer);
        return 1;
    }

    // 准备 I/O 控制块
    memset(&iocb, 0, sizeof(iocb));
    iocb.aio_lio_opcode = 1;        // IO_CMD_PWRITE
    iocb.aio_fildes = fd;           // 文件描述符
    iocb.aio_buf = (unsigned long)buffer; // 缓冲区地址
    iocb.aio_nbytes = strlen(buffer);     // 写入字节数
    iocb.aio_offset = 0;            // 文件偏移量
    iocbs[0] = &iocb;

    // 提交异步写操作
    ret = io_submit(ctx, 1, iocbs);
    if (ret < 0) {
        fprintf(stderr, "io_submit failed: %ld\n", ret);
        io_destroy(ctx);
        close(fd);
        free(buffer);
        return 1;
    }

    // 等待事件完成
    struct io_event events[1];
    ret = io_getevents(ctx, 1, 1, events, NULL);
    if (ret < 0) {
        fprintf(stderr, "io_getevents failed: %ld\n", ret);
        io_destroy(ctx);
        close(fd);
        free(buffer);
        return 1;
    }

    printf("Write completed: %lld bytes written\n", events[0].res);

    // 关闭文件并释放资源
    io_destroy(ctx);
    close(fd);
    free(buffer);

    return 0;
}
