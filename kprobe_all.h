//
// Created by fuqiuluo on 24-12-11.
//

#ifndef DAAT_KPROBE_ALL_H
#define DAAT_KPROBE_ALL_H

#include <linux/kprobes.h>

int kprobe_init(void);
void kprobe_exit(void);

#endif //DAAT_KPROBE_ALL_H
