//
// Created by fuqiuluo on 24-12-10.
//

#ifndef DAAT_KALLSYMS_H
#define DAAT_KALLSYMS_H

#include <linux/types.h>

uintptr_t my_kallsyms_lookup_name(const char* symbol_name);

uintptr_t* find_syscall_table(void);

#endif //DAAT_KALLSYMS_H
