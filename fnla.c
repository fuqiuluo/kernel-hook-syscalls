//
// Created by fuqiuluo on 25-1-1.
//
#include <linux/vmalloc.h>
#include "fnla.h"
#include "linux/slab.h"

fnla_t fnla_alloc(void) {
    fnla_t fnla = kmalloc(sizeof(struct fnla), GFP_KERNEL);
    if (!fnla) {
        return NULL;
    }
    fnla->size = DEFAULT_NLA_SIZE;
    fnla->pos = 0;
    fnla->data = kmalloc(fnla->size, GFP_KERNEL);
    if (fnla->data == NULL) {
        fnla->data = vmalloc(fnla->size);
        if (fnla->data == NULL) {
            kfree(fnla);
            return NULL;
        }
        fnla->mem_type = FNLA_MEM_VMALLOC;
    } else {
        fnla->mem_type = FNLA_MEM_KMALLOC;
    }
    return fnla;
}

fnla_t fnla_put_s32(fnla_t pFnla, int32_t in) {
    if (!pFnla) {
        return NULL;
    }
    if (pFnla->pos + 4 > pFnla->size) {
        pFnla = fnla_expand(pFnla, pFnla->size * 2);
        if (!pFnla) {
            return NULL;
        }
    }
    unsigned char out[4];
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
    memcpy(pFnla->data + pFnla->pos, out, 4);
    pFnla->pos += 4;
    return pFnla;
}

fnla_t fnla_put_u32(fnla_t pFnla, uint32_t in) {
    if (!pFnla) {
        return NULL;
    }
    if (pFnla->pos + 4 > pFnla->size) {
        pFnla = fnla_expand(pFnla, pFnla->size * 2);
        if (!pFnla) {
            return NULL;
        }
    }
    unsigned char out[4];
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
    memcpy(pFnla->data + pFnla->pos, out, 4);
    pFnla->pos += 4;
    return pFnla;
}

fnla_t fnla_put_bytes(fnla_t pFnla, const char* str, size_t len) {
    if (!pFnla) {
        return NULL;
    }
    if (pFnla->pos + len > pFnla->size) {
        size_t new_size = pFnla->size * 2;
        while (new_size < pFnla->pos + len) {
            new_size *= 2;
        }
        pFnla = fnla_expand(pFnla, new_size);
        if (!pFnla) {
            return NULL;
        }
    }
    memcpy(pFnla->data + pFnla->pos, str, len);
    pFnla->pos += len;
    return pFnla;
}

fnla_t fnla_put_s64(fnla_t pFnla, int64_t in) {
    if (!pFnla) {
        return NULL;
    }
    if (pFnla->pos + 8 > pFnla->size) {
        pFnla = fnla_expand(pFnla, pFnla->size * 2);
        if (!pFnla)
            return NULL;
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
    memcpy(pFnla->data + pFnla->pos, out, 8);
    pFnla->pos += 8;
    return pFnla;
}

fnla_t fnla_put_u64(fnla_t pFnla, uint64_t in) {
    if (!pFnla) {
        return NULL;
    }
    if (pFnla->pos + 8 > pFnla->size) {
        pFnla = fnla_expand(pFnla, pFnla->size * 2);
        if (!pFnla)
            return NULL;
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
    memcpy(pFnla->data + pFnla->pos, out, 8);
    pFnla->pos += 8;
    return pFnla;
}

void fnla_free(fnla_t pFnla) {
    if (pFnla) {
        if (pFnla->mem_type == FNLA_MEM_KMALLOC) {
            kfree(pFnla->data);
        } else if (pFnla->mem_type == FNLA_MEM_VMALLOC) {
            vfree(pFnla->data);
        }
        kfree(pFnla);
    }
}

void fnla_reset(fnla_t fnla) {
    if (fnla) {
        fnla->pos = 0;
    }
}

fnla_t fnla_put_string(fnla_t fnla, const char *str) {
    if (!fnla) {
        return NULL;
    }
    size_t len = strlen(str) + 1;
    return fnla_put_bytes(fnla, str, len);
}

fnla_t fnla_put_nla(fnla_t fnla, fnla_t nla2) {
    if (!fnla || !nla2) {
        return NULL;
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
        return NULL;
    }
    size_t size = 0;
    while (fnla->data[fnla->pos + size] != '\0') {
        size++;
    }
    if (fnla->pos + size + 1 > fnla->size) {
        return NULL;
    }
    memcpy(str, fnla->data + fnla->pos, size + 1);
    fnla->pos += size + 1;
    *len = size;
    return fnla;
}

fnla_t fnla_init_with_data(const char *data, size_t len) {
    fnla_t fnla = kmalloc(sizeof(struct fnla), GFP_KERNEL);
    if (!fnla) {
        return NULL;
    }
    fnla->size = len;
    fnla->pos = 0;
    fnla->data = kmalloc(fnla->size, GFP_KERNEL);
    if (!fnla->data) {
        fnla->data = vmalloc(fnla->size);
        if (!fnla->data) {
            kfree(fnla);
            return NULL;
        }
        fnla->mem_type = FNLA_MEM_VMALLOC;
    } else {
        fnla->mem_type = FNLA_MEM_KMALLOC;
    }
    memcpy(fnla->data, data, len);
    return fnla;
}

fnla_t fnla_expand(fnla_t pFnla, size_t new_size) {
    if (!pFnla) {
        return NULL;
    }
    if (new_size <= pFnla->size) {
        return pFnla;
    }
    if (pFnla->mem_type == FNLA_MEM_KMALLOC) {
        char* np = krealloc(pFnla->data, new_size, GFP_KERNEL);
        if (np == NULL) {
            np = vmalloc(new_size);
            if (np == NULL) {
                return NULL;
            }
            memcpy(np, pFnla->data, pFnla->size);
            kfree(pFnla->data);
            pFnla->data = np;
            pFnla->size = new_size;
            pFnla->mem_type = FNLA_MEM_VMALLOC;
            return pFnla;
        }
        pFnla->data = np;
        pFnla->size = new_size;
        return pFnla;
    }
    if (pFnla->mem_type == FNLA_MEM_VMALLOC) {
        char* np = vmalloc(new_size);
        if (np == NULL) {
            return NULL;
        }
        memcpy(np, pFnla->data, pFnla->size);
        vfree(pFnla->data);
        pFnla->data = np;
        pFnla->size = new_size;
        return pFnla;
    }

    return NULL;
}
