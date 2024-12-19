//
// Created by fuqiuluo on 24-12-11.
//
#include "kprobe_all.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>

int kprobe_init(void) {

    return 0;
}

void kprobe_exit(void) {
}
