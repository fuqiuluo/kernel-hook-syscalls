//
// Created by fuqiuluo on 25-1-5.
//
#include <linux/slab.h>
#include <linux/vmalloc.h>

void kmem_alloc(size_t size, struct mem_block* result) {
    result->size = 0;
    if (size < MEMORY_CRITICAL_POINT) {
        result->ptr = kmalloc(size, GFP_KERNEL);
        result->type = MEM_KMALLOC;
        if (result->ptr != NULL) {
            result->size = size;
            return;
        }
    }
    result->ptr = vmalloc(size);
    result->type = MEM_VMALLOC;
    if (result->ptr != NULL) {
        result->size = size;
    }
}

int kmem_free(struct mem_block *block) {
    if (block->ptr == NULL) {
        return -1;
    }
    if (block->type == MEM_KMALLOC) {
        kfree(block->ptr);
    } else if (block->type == MEM_VMALLOC) {
        vfree(block->ptr);
    }
    block->ptr = NULL;
    return 0;
}

int kmem_realloc(struct mem_block *block, size_t new_size) {
    if (block->ptr == NULL) {
        return -1;
    }

    void *new_ptr;
    if (block->type == MEM_KMALLOC) {
        new_ptr = krealloc(block->ptr, new_size, GFP_KERNEL);
        if (new_ptr == NULL) {
            new_ptr = vmalloc(new_size);
            if (new_ptr != NULL) {
                memcpy(new_ptr, block->ptr, block->size);
                kfree(block->ptr);
                block->ptr = new_ptr;
                block->type = MEM_VMALLOC;
                block->size = new_size;
                return 0;
            }
            return -1;
        }
        block->ptr = new_ptr;
        block->size = new_size;
        return 0;
    }


    if (block->type == MEM_VMALLOC) {
        new_ptr = vmalloc(new_size);
        if (new_ptr != NULL) {
            memcpy(new_ptr, block->ptr, new_size);
            vfree(block->ptr);
        }
        block->ptr = new_ptr;
        block->size = new_size;
        return 0;
    } else {
        return -1;
    }
}
