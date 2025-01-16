//
// Created by 13723 on 24-12-22.
//

#ifndef TRS_PARSER_H
#define TRS_PARSER_H

#include <string>
#include <memory>
#include "Syscalls.h"
#include "../fnla.h"

namespace trs::parser {
    std::unique_ptr<Syscall> parseSyscallEnd(fnla_t fnla);
}

#endif //TRS_PARSER_H
