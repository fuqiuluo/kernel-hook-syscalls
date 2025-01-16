//
// Created by fuqiuluo on 25-1-1.
//

#ifndef DAAT_FNLA_H
#define DAAT_FNLA_H

#include <linux/types.h>

#define DEFAULT_NLA_SIZE 1024

#define NLA_DATA(fnla) fnla->data
#define NLA_SIZE(fnla) fnla->pos
#define NLA_POS(fnla) fnla->pos

#define FNLA_MEM_KMALLOC 0
#define FNLA_MEM_VMALLOC 1
#define FNLA_MEM_ZSALLOC 2 // not used

typedef struct fnla {
    size_t size;
    size_t pos;
    char* data;
    int mem_type;
}* fnla_t;

fnla_t fnla_alloc(void);

fnla_t fnla_init_with_data(const char* data, size_t len);

fnla_t fnla_expand(fnla_t pFnla, size_t new_size);

fnla_t fnla_put_s32(fnla_t pFnla, int32_t value);

fnla_t fnla_put_s64(fnla_t pFnla, int64_t value);

fnla_t fnla_put_u32(fnla_t pFnla, uint32_t value);

fnla_t fnla_put_u64(fnla_t pFnla, uint64_t value);

fnla_t fnla_put_bytes(fnla_t pFnla, const char* str, size_t len);

fnla_t fnla_put_string(fnla_t fnla, const char* str);

fnla_t fnla_put_nla(fnla_t fnla, fnla_t nla2);

fnla_t fnla_get_s32(fnla_t fnla, int32_t * value);

fnla_t fnla_get_s64(fnla_t fnla, int64_t * value);

fnla_t fnla_get_u32(fnla_t fnla, uint32_t * value);

fnla_t fnla_get_u64(fnla_t fnla, uint64_t * value);

fnla_t fnla_get_bytes(fnla_t fnla, char* str, size_t len);

fnla_t fnla_get_string(fnla_t fnla, char* str, size_t* len);

void fnla_free(fnla_t pFnla);

void fnla_reset(fnla_t fnla);

#endif //DAAT_FNLA_H
