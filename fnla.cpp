//
// Created by fuqiuluo on 25-1-1.
//
#include <cstdlib>
#include <cstring>
#include "fnla.h"

fnla_t fnla_init() {
    auto fnla = static_cast<fnla_t>(malloc(sizeof(struct fnla)));
    if (!fnla) {
        return nullptr;
    }
    fnla->size = DEFAULT_NLA_SIZE;
    fnla->pos = 0;
    fnla->data = (char*) malloc(fnla->size);
    return fnla;
}

fnla_t fnla_put_bytes(fnla_t fnla, const char* str, size_t len) {
    if (!fnla) {
        return nullptr;
    }
    if (fnla->pos + len > fnla->size) {
        size_t new_size = fnla->size * 2;
        while (new_size < fnla->pos + len) {
            new_size *= 2;
        }
        fnla->data = static_cast<char *>(realloc(fnla->data, new_size));
        if (!fnla->data) {
            return nullptr;
        }
        fnla->size = new_size;
    }
    memcpy(fnla->data + fnla->pos, str, len);
    fnla->pos += len;
    return fnla;
}

fnla_t fnla_put_s32(fnla_t fnla, int32_t in) {
    if (!fnla) {
        return NULL;
    }
    if (fnla->pos + 4 > fnla->size) {
        fnla->data = static_cast<char *>(realloc(fnla->data, fnla->size * 2));
        if (!fnla->data) {
            return NULL;
        }
        fnla->size *= 2;
    }
    unsigned char out[4];
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
    memcpy(fnla->data + fnla->pos, out, 4);
    fnla->pos += 4;
    return fnla;
}

fnla_t fnla_put_u32(fnla_t fnla, uint32_t in) {
    if (!fnla) {
        return NULL;
    }
    if (fnla->pos + 4 > fnla->size) {
        fnla->data = static_cast<char *>(realloc(fnla->data, fnla->size * 2));
        if (!fnla->data) {
            return NULL;
        }
        fnla->size *= 2;
    }
    unsigned char out[4];
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
    memcpy(fnla->data + fnla->pos, out, 4);
    fnla->pos += 4;
    return fnla;
}

fnla_t fnla_put_s64(fnla_t fnla, int64_t in) {
    if (!fnla) {
        return NULL;
    }
    if (fnla->pos + 8 > fnla->size) {
        fnla->data = static_cast<char *>(realloc(fnla->data, fnla->size * 2));
        if (!fnla->data) {
            return NULL;
        }
        fnla->size *= 2;
    }
    unsigned char out[8];
    out[0] = (unsigned char)(in >> 56);  /* 7*8 */
    out[1] = (unsigned char)(in >> 48);  /* 6*8 */
    out[2] = (unsigned char)(in >> 40);  /* 5*8 */
    out[3] = (unsigned char)(in >> 32);  /* 4*8 */
    out[4] = (unsigned char)(in >> 24);  /* 3*8 */
    out[5] = (unsigned char)(in >> 16);  /* 2*8 */
    out[6] = (unsigned char)(in >> 8);   /* 1*8 */
    out[7] = (unsigned char)(in);        /* 0*8 */
    memcpy(fnla->data + fnla->pos, out, 8);
    fnla->pos += 8;
    return fnla;
}

fnla_t fnla_put_u64(fnla_t fnla, uint64_t in) {
    if (!fnla) {
        return NULL;
    }
    if (fnla->pos + 8 > fnla->size) {
        fnla->data = static_cast<char *>(realloc(fnla->data, fnla->size * 2));
        if (!fnla->data) {
            return NULL;
        }
        fnla->size *= 2;
    }
    unsigned char out[8];
    out[0] = (unsigned char)(in >> 56);  /* 7*8 */
    out[1] = (unsigned char)(in >> 48);  /* 6*8 */
    out[2] = (unsigned char)(in >> 40);  /* 5*8 */
    out[3] = (unsigned char)(in >> 32);  /* 4*8 */
    out[4] = (unsigned char)(in >> 24);  /* 3*8 */
    out[5] = (unsigned char)(in >> 16);  /* 2*8 */
    out[6] = (unsigned char)(in >> 8);   /* 1*8 */
    out[7] = (unsigned char)(in);        /* 0*8 */
    memcpy(fnla->data + fnla->pos, out, 8);
    fnla->pos += 8;
    return fnla;
}

void fnla_free(fnla_t fnla) {
    if (fnla) {
        free(fnla->data);
        free(fnla);
    }
}

void fnla_reset(fnla_t fnla) {
    if (fnla) {
        fnla->pos = 0;
    }
}

fnla_t fnla_put_string(fnla_t fnla, const char *str) {
    if (!fnla) {
        return nullptr;
    }
    size_t len = strlen(str) + 1;
    return fnla_put_bytes(fnla, str, len);
}

fnla_t fnla_put_nla(fnla_t fnla, fnla_t nla2) {
    if (!fnla || !nla2) {
        return nullptr;
    }
    return fnla_put_bytes(fnla, NLA_DATA(nla2), NLA_SIZE(nla2));
}

fnla_t fnla_get_s32(fnla_t fnla, int32_t *out) {
    if (!fnla || !out) {
        return NULL;
    }
    if (fnla->pos + 4 > fnla->size) {
        return NULL;
    }
    unsigned char in[4];
    memcpy(in, fnla->data + fnla->pos, 4);
    *out = (int32_t)(in[3]);
    *out |= (int32_t)(in[2]) << 8;
    *out |= (int32_t)(in[1]) << 16;
    *out |= (int32_t)(in[0]) << 24;
    fnla->pos += 4;
    return fnla;
}

fnla_t fnla_get_u32(fnla_t fnla, uint32_t *out) {
    if (!fnla || !out) {
        return NULL;
    }
    if (fnla->pos + 4 > fnla->size) {
        return NULL;
    }
    unsigned char in[4];
    memcpy(in, fnla->data + fnla->pos, 4);
    *out = (uint32_t)(in[3]);
    *out |= (uint32_t)(in[2]) << 8;
    *out |= (uint32_t)(in[1]) << 16;
    *out |= (uint32_t)(in[0]) << 24;
    fnla->pos += 4;
    return fnla;
}

fnla_t fnla_get_s64(fnla_t fnla, int64_t *out) {
    if (!fnla || !out) {
        return NULL;
    }
    if (fnla->pos + 8 > fnla->size) {
        return NULL;
    }
    unsigned char in[8];
    memcpy(in, fnla->data + fnla->pos, 8);
    *out = (int64_t)(in[7]);
    *out |= (int64_t)(in[6]) << 8;
    *out |= (int64_t)(in[5]) << 16;
    *out |= (int64_t)(in[4]) << 24;
    *out |= (int64_t)(in[3]) << 32;
    *out |= (int64_t)(in[2]) << 40;
    *out |= (int64_t)(in[1]) << 48;
    *out |= (int64_t)(in[0]) << 56;
    fnla->pos += 8;
    return fnla;
}

fnla_t fnla_get_u64(fnla_t fnla, uint64_t *out) {
    if (!fnla || !out) {
        return NULL;
    }
    if (fnla->pos + 8 > fnla->size) {
        return NULL;
    }
    unsigned char in[8];
    memcpy(in, fnla->data + fnla->pos, 8);
    *out = (uint64_t)(in[7]);
    *out |= (uint64_t)(in[6]) << 8;
    *out |= (uint64_t)(in[5]) << 16;
    *out |= (uint64_t)(in[4]) << 24;
    *out |= (uint64_t)(in[3]) << 32;
    *out |= (uint64_t)(in[2]) << 40;
    *out |= (uint64_t)(in[1]) << 48;
    *out |= (uint64_t)(in[0]) << 56;
    fnla->pos += 8;
    return fnla;
}

fnla_t fnla_get_bytes(fnla_t fnla, char *str, size_t len) {
    if (!fnla || !str) {
        return NULL;
    }
    if (fnla->pos + len > fnla->size) {
        return NULL;
    }
    memcpy(str, fnla->data + fnla->pos, len);
    fnla->pos += len;
    return fnla;
}

fnla_t fnla_get_string(fnla_t fnla, char *str, size_t* len) {
    if (!fnla || !str) {
        return nullptr;
    }
    size_t size = 0;
    while (fnla->data[fnla->pos + size] != '\0') {
        size++;
    }
    if (fnla->pos + size + 1 > fnla->size) {
        return nullptr;
    }
    memcpy(str, fnla->data + fnla->pos, size + 1);
    fnla->pos += size + 1;
    *len = size;
    return fnla;
}

fnla_t fnla_init_with_data(const char *data, size_t len) {
    auto fnla = static_cast<fnla_t>(malloc(sizeof(struct fnla)));
    if (!fnla) {
        return nullptr;
    }
    fnla->size = len;
    fnla->pos = 0;
    fnla->data = static_cast<char *>(malloc(fnla->size));
    if (!fnla->data) {
        free(fnla);
        return nullptr;
    }
    memcpy(fnla->data, data, len);
    return fnla;
}