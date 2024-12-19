//
// Created by fuqiuluo on 24-12-10.
//

#ifndef DAAT_KALLSYMS_H
#define DAAT_KALLSYMS_H

unsigned long my_kallsyms_lookup_name(const char* symbol_name);

unsigned long * find_syscall_table(void);

#endif //DAAT_KALLSYMS_H
