/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include "prov/der.h"

/*
 * All functions return the same:
 * == 0 : error
 * >  0 : total length so far
 */

static int int_der_alloc(unsigned char **pp, size_t *cnt,
                         const unsigned char *start,
                         size_t n)
{
    if (pp != NULL) {
        if (*pp - n < start)
            return 0;
        *pp -= n;
    }
    *cnt += n;
    return 1;
}

static int int_der_w_bytes(unsigned char **pp, size_t *cnt,
                           const unsigned char *start,
                           const unsigned char *bytes, size_t bytes_n)
{
    if (!int_der_alloc(pp, cnt, start, bytes_n))
        return 0;
    if (pp != NULL)
        memcpy(*pp, bytes, bytes_n);
    return 1;
}

static int int_der_w_byte(unsigned char **pp, size_t *cnt,
                          const unsigned char *start,
                          unsigned char byte)
{
    if (!int_der_alloc(pp, cnt, start, 1))
        return 0;
    if (pp != NULL)
        **pp = byte;
    return 1;
}

static int int_der_w_length(unsigned char **pp, size_t *cnt,
                            const unsigned char *start,
                            size_t n)
{
    if (n > 0xFFFF)
        return 0;           /* Unsupported until we find a use case */

    if (n > 0xFF) {
        if (!int_der_w_byte(pp, cnt, start, (unsigned char)(n & 0xFF)))
            return 0;
        n >>= 8;
        if (!int_der_w_byte(pp, cnt, start, (unsigned char)(n & 0xFF))
            || !int_der_w_byte(pp, cnt, start, 0x82))
            return 0;
    } else if (n > 0x7f) {
        if (!int_der_w_byte(pp, cnt, start, (unsigned char)(n & 0xFF))
            || !int_der_w_byte(pp, cnt, start, 0x81))
            return 0;
    } else {
        if (!int_der_w_byte(pp, cnt, start, (unsigned char)(n & 0xFF)))
            return 0;
    }
    return 1;
}

int DER_w_precompiled(unsigned char **pp, size_t *cnt,
                      const unsigned char *start,
                      const unsigned char *precompiled, size_t precompiled_n)
{
    return int_der_w_bytes(pp, cnt, start, precompiled, precompiled_n);
}

int DER_w_boolean(unsigned char **pp, size_t *cnt, const unsigned char *start,
                  int b)
{
    if (b) {
        if (!int_der_w_byte(pp, cnt, start, 0xFF)
            || !int_der_w_length(pp, cnt, start, 1))
            return 0;
    } else {
        if (!int_der_w_length(pp, cnt, start, 0))
            return 0;
    }
    if (!int_der_w_byte(pp, cnt, start, DER_P_BOOLEAN))
        return 0;
    return 1;
}

/* For integers, we only support unsigned values for now */
int DER_w_ulong(unsigned char **pp, size_t *cnt, const unsigned char *start,
                unsigned long v)
{
    size_t n = 0;

    while (v != 0) {
        if (!int_der_w_byte(pp, cnt, start, (unsigned char)(v & 0xFF)))
            return 0;
        n++;
        v >>= 8;
    }
    if (n == 0 || (pp != NULL && **pp > 0x7F)) {
        if (!int_der_w_byte(pp, cnt, start, 0))
            return 0;
        n++;
    }
    if (!int_der_w_length(pp, cnt, start, n)
        || !int_der_w_byte(pp, cnt, start, DER_P_INTEGER))
        return 0;
    return 1;
}

int DER_w_bn(unsigned char **pp, size_t *cnt, const unsigned char *start,
             BIGNUM *v)
{
    size_t n = 0;

    if (v == NULL || BN_is_negative(v))
        return 0;
    if (BN_is_zero(v)) {
        if (!int_der_w_byte(pp, cnt, start, 0))
            return 0;
        n = 1;
    } else {
        /* The BIGNUM limbs are in LE order */
        unsigned int top_byte;

        n = BN_num_bytes(v);
        top_byte =
            ((bn_get_words(v) [n / BN_BYTES]) >> (8 * (n % BN_BYTES)))
            & 0x7F;

        if (!int_der_alloc(pp, cnt, start, n))
            return 0;
        if (pp != NULL)
            BN_bn2bin(v, *pp);

        if (top_byte > 0x7F) {
            /* Double check that we got the top byte correctly */
            if (pp != NULL && !ossl_assert(top_byte == **pp))
                return 0;

            if (!int_der_w_byte(pp, cnt, start, 0))
                return 0;
            n++;
        }
    }
    if (!int_der_w_length(pp, cnt, start, n)
        || !int_der_w_byte(pp, cnt, start, DER_P_INTEGER))
        return 0;
    return 1;
}

int DER_w_null(unsigned char **pp, size_t *cnt, const unsigned char *start)
{
    if (!int_der_w_length(pp, cnt, start, 0)
        || !int_der_w_byte(pp, cnt, start, DER_P_NULL))
        return 0;
    return 1;
}

int DER_w_sequence(unsigned char **pp, size_t *cnt, const unsigned char *start)
{
    if (!int_der_w_length(pp, cnt, start, *cnt)
        || !int_der_w_byte(pp, cnt, start, DER_F_CONSTRUCTED|DER_P_SEQUENCE))
        return 0;
    return 1;
}

/* NEVER use the same variable for |*cnt| and |n| */
int DER_w_sequence_n(unsigned char **pp, size_t *cnt,
                     const unsigned char *start,
                     size_t n)
{
    *cnt += n;
    return DER_w_sequence(pp, cnt, start);
}

int DER_w_context(unsigned char **pp, size_t *cnt, const unsigned char *start,
                  int num)
{
    if (num < 0 || num >= 30)
        return 0;
    if (!int_der_w_length(pp, cnt, start, *cnt)
        || !int_der_w_byte(pp, cnt, start, DER_C_CONTEXT|num))
        return 0;
    return 1;
}

/* NEVER use the same variable for |*cnt| and |n| */
int DER_w_context_n(unsigned char **pp, size_t *cnt,
                    const unsigned char *start,
                    int num, size_t n)
{
    *cnt += n;
    return DER_w_context(pp, cnt, start, num);
}

