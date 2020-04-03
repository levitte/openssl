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
#include "internal/der.h"
#include "crypto/bn.h"

static int int_write_bytes(WPACKET *pkt,
                           const unsigned char *bytes, size_t bytes_n)
{
    unsigned char *p = NULL;

    if (!WPACKET_allocate_bytes(pkt, bytes_n, &p))
        return 0;
    if (p != NULL)
        memcpy(p, bytes, bytes_n);
    return 1;
}

static int int_start_context(WPACKET *pkt, int cont)
{
    if (cont < 0)
        return 1;
    return WPACKET_start_sub_packet(pkt);
}

static int int_end_context(WPACKET *pkt, int cont)
{
    if (cont < 0)
        return 1;
    return WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_C_CONTEXT|cont);
}

int DER_w_precompiled(WPACKET *pkt, int cont,
                      const unsigned char *precompiled, size_t precompiled_n)
{
    return int_start_context(pkt, cont)
        && int_write_bytes(pkt, precompiled, precompiled_n)
        && int_end_context(pkt, cont);
}

int DER_w_boolean(WPACKET *pkt, int cont, int b)
{
    return int_start_context(pkt, cont)
        && WPACKET_start_sub_packet(pkt)
        && (!b || WPACKET_put_bytes_u8(pkt, 0xFF))
        && !WPACKET_close(pkt)
        && !WPACKET_put_bytes_u8(pkt, DER_P_BOOLEAN)
        && int_end_context(pkt, cont);
}

/* For integers, we only support unsigned values for now */
int DER_w_ulong(WPACKET *pkt, int cont, unsigned long v)
{
    size_t n = 0;
    unsigned long tmp = v;

    while (tmp != 0) {
        n++;
        tmp >>= 8;
    }
    if (n == 0)
        n = 1;

    return int_start_context(pkt, cont)
        && WPACKET_start_sub_packet(pkt)
        && WPACKET_put_bytes__(pkt, v, n)
        && WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_P_INTEGER)
        && int_end_context(pkt, cont);
}

int DER_w_bn(WPACKET *pkt, int cont, const BIGNUM *v)
{
    size_t n = 0;
    unsigned int top_byte;
    unsigned char *p = NULL;

    if (v == NULL || BN_is_negative(v))
        return 0;
    if (BN_is_zero(v))
        return DER_w_ulong(pkt, cont, 0);

    /* The BIGNUM limbs are in LE order */
    n = BN_num_bytes(v);
    top_byte =
        ((bn_get_words(v) [(n - 1) / BN_BYTES]) >> (8 * ((n - 1) % BN_BYTES)))
        & 0xFF;
    if (top_byte > 0x7F)
        n++;

    if (!int_start_context(pkt, cont)
        || !WPACKET_start_sub_packet(pkt)
        || !WPACKET_allocate_bytes(pkt, n, &p))
        return 0;

    if (p != NULL) {
        BN_bn2binpad(v, p, n);

        /* Double check that we got the top byte correctly */
        if (top_byte > 0x7F && !ossl_assert(top_byte == p[1]))
            return 0;
    }

    return WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_P_INTEGER)
        && int_end_context(pkt, cont);
}

int DER_w_null(WPACKET *pkt, int cont)
{
    return int_start_context(pkt, cont)
        && WPACKET_start_sub_packet(pkt)
        && WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_P_INTEGER)
        && int_end_context(pkt, cont);
}

/* Constructed things need a start and an end */
int DER_w_begin_sequence(WPACKET *pkt, int cont)
{
    return int_start_context(pkt, cont)
        && WPACKET_start_sub_packet(pkt);
}

int DER_w_end_sequence(WPACKET *pkt, int cont)
{
    return WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_F_CONSTRUCTED|DER_P_SEQUENCE)
        && int_end_context(pkt, cont);
}
