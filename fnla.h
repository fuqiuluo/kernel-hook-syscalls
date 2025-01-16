//
// Created by fuqiuluo on 25-1-1.
//

#ifndef DAAT_FNLA_H
#define DAAT_FNLA_H

#include <cstdint>

#define DEFAULT_NLA_SIZE 1024

#define NLA_DATA(fnla) fnla->data
#define NLA_SIZE(fnla) fnla->pos
#define NLA_POS(fnla) fnla->pos

#define NLA_GET_S32(fnla, out_name) \
    int32_t out_name;              \
    fnla_get_s32(fnla, &out_name);

#define NLA_GET_U32(fnla, out_name) \
    uint32_t out_name;             \
    fnla_get_u32(fnla, &out_name);

#define NLA_GET_S64(fnla, out_name) \
    int64_t out_name;              \
    fnla_get_s64(fnla, &out_name);

#define NLA_GET_U64(fnla, out_name) \
    uint64_t out_name;             \
    fnla_get_u64(fnla, &out_name);

typedef struct fnla {
    size_t size;
    char* data;
    size_t pos;
}* fnla_t;

fnla_t fnla_init();

fnla_t fnla_init_with_data(const char* data, size_t len);

fnla_t fnla_put_s32(fnla_t fnla, int32_t value);

fnla_t fnla_put_s64(fnla_t fnla, int64_t value);

fnla_t fnla_put_u32(fnla_t fnla, uint32_t value);

fnla_t fnla_put_u64(fnla_t fnla, uint64_t value);

fnla_t fnla_put_bytes(fnla_t fnla, const char* str, size_t len);

fnla_t fnla_put_string(fnla_t fnla, const char* str);

fnla_t fnla_put_nla(fnla_t fnla, fnla_t nla2);

fnla_t fnla_get_s32(fnla_t fnla, int32_t * value);

fnla_t fnla_get_s64(fnla_t fnla, int64_t * value);

fnla_t fnla_get_u32(fnla_t fnla, uint32_t * value);

fnla_t fnla_get_u64(fnla_t fnla, uint64_t * value);

fnla_t fnla_get_bytes(fnla_t fnla, char* str, size_t len);

fnla_t fnla_get_string(fnla_t fnla, char* str, size_t* len);

void fnla_free(fnla_t fnla);

void fnla_reset(fnla_t fnla);

#endif //DAAT_FNLA_H
