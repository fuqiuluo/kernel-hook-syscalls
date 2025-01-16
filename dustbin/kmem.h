//
// Created by fuqiuluo on 25-1-5.
//

#ifndef DAAT_KMEM_H
#define DAAT_KMEM_H

#include <linux/types.h>

#define MEMORY_CRITICAL_POINT (1024 * 128)

enum mem_type: u8 {
    MEM_KMALLOC = 0,
    MEM_VMALLOC = 1
};

struct mem_block {
    void *ptr;
    enum mem_type type;
    size_t size;
};

extern void kmem_alloc(size_t size, struct mem_block* result);

extern int kmem_realloc(struct mem_block* block, size_t new_size);

extern int kmem_free(struct mem_block* block);

#endif //DAAT_KMEM_H
