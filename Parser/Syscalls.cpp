//
// Created by 13723 on 25-1-3.
//
#include "Syscalls.h"

std::string trs::parser::errnoToString(int eno)  {
    switch (-eno) {
        case EBADF:
            return "EBADF";
        case EPERM:
            return "EPERM";
        case EAGAIN:
            return "EAGAIN";
        case EINVAL:
            return "EINVAL";
        case EFAULT:
            return "EFAULT";
        case ENOMEM:
            return "ENOMEM";
        case ENOSYS:
            return "ENOSYS";
        default:
            return std::to_string(eno);
    }
}

void trs::parser::char_to_hex(const char *input, char *output, size_t length) {
    const char hex_digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        output[i * 2] = hex_digits[byte >> 4];
        output[i * 2 + 1] = hex_digits[byte & 0x0F];
    }
    output[length * 2] = '\0';
}
