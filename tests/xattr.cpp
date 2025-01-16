//
// Created by fuqiuluo on 25-1-8.
//
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>

// 创建一个简单的测试文件
void create_test_file(const char* filename) {
    std::ofstream outfile(filename);
    if (outfile.is_open()) {
        outfile << "Hello, Xattr Testing!" << std::endl;
        outfile.close();
    } else {
        std::cerr << "Failed to create file: " << filename << std::endl;
    }
}

// 删除测试文件
void remove_test_file(const char* filename) {
    if (remove(filename) != 0) {
        std::cerr << "Failed to remove file: " << filename << std::endl;
    } else {
        std::cout << "File removed successfully: " << filename << std::endl;
    }
}

// 测试 setxattr
void test_setxattr(const char* filename) {
    const char* name = "user.testattr";
    const char* value = "test_value";
    ssize_t result = setxattr(filename, name, value, strlen(value), 0);
    if (result == 0) {
        std::cout << "setxattr succeeded" << std::endl;
    } else {
        std::cerr << "setxattr failed: " << strerror(errno) << std::endl;
    }
}

// 测试 lsetxattr
void test_lsetxattr(const char* filename) {
    const char* name = "user.testattr";
    const char* value = "test_value_lsetxattr";
    ssize_t result = lsetxattr(filename, name, value, strlen(value), 0);
    if (result == 0) {
        std::cout << "lsetxattr succeeded" << std::endl;
    } else {
        std::cerr << "lsetxattr failed: " << strerror(errno) << std::endl;
    }
}

// 测试 fsetxattr
void test_fsetxattr(const char* filename) {
    const char* name = "user.testattr";
    const char* value = "test_value_fsetxattr";
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        std::cerr << "Failed to open file: " << strerror(errno) << std::endl;
        return;
    }
    ssize_t result = fsetxattr(fd, name, value, strlen(value), 0);
    if (result == 0) {
        std::cout << "fsetxattr succeeded" << std::endl;
    } else {
        std::cerr << "fsetxattr failed: " << strerror(errno) << std::endl;
    }
    close(fd);
}

// 测试 getxattr
void test_getxattr(const char* filename) {
    const char* name = "user.testattr";
    char value[128];
    ssize_t result = getxattr(filename, name, value, sizeof(value));
    if (result == -1) {
        std::cerr << "getxattr failed: " << strerror(errno) << std::endl;
    } else {
        value[result] = '\0';  // Null-terminate the string
        std::cout << "getxattr succeeded: " << value << std::endl;
    }
}

// 测试 listxattr
void test_listxattr(const char* filename) {
    char list[1024];
    ssize_t result = listxattr(filename, list, sizeof(list));
    if (result == -1) {
        std::cerr << "listxattr failed: " << strerror(errno) << std::endl;
    } else {
        std::cout << "listxattr succeeded: " << std::endl;
        char* current_attr = list;
        while (current_attr < list + result) {
            std::cout << "  " << current_attr << std::endl;
            current_attr += strlen(current_attr) + 1;
        }
    }
}

// 测试 removexattr
void test_removexattr(const char* filename) {
    const char* name = "user.testattr";
    ssize_t result = removexattr(filename, name);
    if (result == 0) {
        std::cout << "removexattr succeeded" << std::endl;
    } else {
        std::cerr << "removexattr failed: " << strerror(errno) << std::endl;
    }
}

int main() {
    const char* filename = "testfile.txt";

    // 创建测试文件
    create_test_file(filename);

    // 运行测试
    test_setxattr(filename);
    test_lsetxattr(filename);
    test_fsetxattr(filename);
    test_getxattr(filename);
    test_listxattr(filename);
    test_removexattr(filename);

    // 删除测试文件
    remove_test_file(filename);

    return 0;
}
