//
// Created by fuqiuluo on 24-12-20.
//

#ifndef DAAT_LOG_H
#define DAAT_LOG_H

#define MAX_LOG_SIZE 512

extern int init_log(void);

extern int trace_log(const char *fmt, ...);

extern void release_log(void);

#endif //DAAT_LOG_H
