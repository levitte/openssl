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

static size_t int_der_alloc(unsigned char **pp, const unsigned char *start,
                            size_t n)
{
    if (pp != NULL) {
        if (*pp - n < start)
            return 0;
        *pp -= n;
    }
    return n;
}

static size_t int_der_w_bytes(unsigned char **pp, const unsigned char *start,
                              const unsigned char *bytes, size_t bytes_n)
{
    size_t a = 0;

    a = int_der_alloc(pp, start, bytes_n);
    if (pp != NULL)
        memcpy(*pp, bytes, bytes_n);
    return a;
}

static size_t int_der_w_byte(unsigned char **pp, const unsigned char *start,
                             unsigned char byte)
{
    size_t a = 0;

    CHECKED(a, int_der_alloc(pp, start, 1));
    if (pp != NULL)
        **pp = byte;
    return a;
}

static size_t int_der_w_length(unsigned char **pp, const unsigned char *start,
                               size_t n)
{
    size_t a = 0;

    if (n > 0xFFFF)
        return 0;           /* Unsupported until we find a use case */

    if (n > 0xFF) {
        CHECKED(a, int_der_w_byte(pp, start, (unsigned char)(n & 0xFF)));
        n >>= 8;
        CHECKED(a, int_der_w_byte(pp, start, (unsigned char)(n & 0xFF)));
        CHECKED(a, int_der_w_byte(pp, start, 0x82));
    } else if (n > 0x7f) {
        CHECKED(a, int_der_w_byte(pp, start, (unsigned char)(n & 0xFF)));
        CHECKED(a, int_der_w_byte(pp, start, 0x81));
    } else {
        CHECKED(a, int_der_w_byte(pp, start, (unsigned char)(n & 0xFF)));
    }
    return a;
}

size_t DER_w_precompiled(unsigned char **pp, const unsigned char *start,
                         const unsigned char *precompiled, size_t precompiled_n)
{
    return int_der_w_bytes(pp, start, precompiled, precompiled_n);
}

size_t DER_w_boolean(unsigned char **pp, const unsigned char *start, int b)
{
    size_t a = 0;

    if (b) {
        CHECKED(a, int_der_w_byte(pp, start, 0xFF));
        CHECKED(a, int_der_w_length(pp, start, 1));
    } else {
        CHECKED(a, int_der_w_length(pp, start, 0));
    }
    CHECKED(a, int_der_w_byte(pp, start, DER_P_BOOLEAN));
    return a;
}

/* For integers, we only support unsigned values for now */
size_t DER_w_ulong(unsigned char **pp, const unsigned char *start,
                   unsigned long v)
{
    size_t a = 0;
    size_t n = 0;

    while (v != 0) {
        CHECKED(a, int_der_w_byte(pp, start, (unsigned char)(v & 0xFF)));
        n++;
        v >>= 8;
    }
    if (n == 0 || (pp != NULL && **pp > 0x7F)) {
        CHECKED(a, int_der_w_byte(pp, start, 0));
        n++;
    }
    CHECKED(a, int_der_w_length(pp, start, n));
    CHECKED(a, int_der_w_byte(pp, start, DER_P_INTEGER));
    return a;
}

size_t DER_w_bn(unsigned char **pp, const unsigned char *start, BIGNUM *v)
{
    size_t a = 0;
    size_t n = 0;

    if (v == NULL || BN_is_negative(v))
        return 0;
    if (BN_is_zero(v)) {
        CHECKED(a, int_der_w_byte(pp, start, 0));
        n = 1;
    } else {
        /* The BIGNUM limbs are in LE order */
        unsigned int top_byte;

        n = BN_num_bytes(v);
        top_byte =
            ((bn_get_words(v) [n / BN_BYTES]) >> (8 * (n % BN_BYTES)))
            & 0x7F;

        CHECKED(a, int_der_alloc(pp, start, n));
        if (pp != NULL)
            BN_bn2bin(v, *pp);

        if (top_byte > 0x7F) {
            /* Double check that we got the top byte correctly */
            if (pp != NULL && !ossl_assert(top_byte == **pp))
                return 0;

            CHECKED(a, int_der_w_byte(pp, start, 0));
            n++;
        }
    }
    CHECKED(a, int_der_w_length(pp, start, n));
    CHECKED(a, int_der_w_byte(pp, start, DER_P_INTEGER));
    return a;
}

size_t DER_w_null(unsigned char **pp, const unsigned char *start)
{
    size_t a = 0;

    CHECKED(a, int_der_w_length(pp, start, 0));
    CHECKED(a, int_der_w_byte(pp, start, DER_P_NULL));
    return a;
}

size_t DER_w_sequence(unsigned char **pp, const unsigned char *start,
                      size_t n)
{
    size_t a = 0;

    CHECKED(a, int_der_w_length(pp, start, n));
    CHECKED(a, int_der_w_byte(pp, start, DER_F_CONSTRUCTED|DER_P_SEQUENCE));
    return a;
}

size_t DER_w_context(unsigned char **pp, const unsigned char *start,
                     int num, size_t length)
{
    size_t a = 0;

    if (num < 0 || num >= 30)
        return 0;
    CHECKED(a, int_der_w_length(pp, start, length));
    CHECKED(a, int_der_w_byte(pp, start, DER_C_CONTEXT|num));
    return a;
}
