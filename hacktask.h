//
// Created by fuqiuluo on 24-12-24.
//

#ifndef DAAT_HACKTASK_H
#define DAAT_HACKTASK_H

#include "linux/task_work.h"

extern s32 is_pid_alive(pid_t pid);

extern s32 mark_pid_root(pid_t pid);

#endif //DAAT_HACKTASK_H
