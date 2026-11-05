/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_BYTESTRING_QUIC_H
#define OSSL_INTERNAL_BYTESTRING_QUIC_H
#pragma once

#include <openssl/e_os2.h>

#include "internal/bytestring.h"
#include "internal/quic_vlint.h"

#ifndef OPENSSL_NO_QUIC
/*
 * Decodes a QUIC variable-length integer in |cbs| and stores the result in
 * |data|.
 */
__owur static ossl_inline int CBS_get_quic_vlint(CBS *cbs,
    uint64_t *data)
{
    size_t enclen;

    if (CBS_len(cbs) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*CBS_data(cbs));

    if (CBS_len(cbs) < enclen)
        return 0;

    *data = ossl_quic_vlint_decode_unchecked(CBS_data(cbs));
    return CBS_skip(cbs, enclen);
}

/*
 * Decodes a QUIC variable-length integer in |cbs| and stores the result in
 * |data|. Unlike CBS_get_quic_vlint, this does not advance the current
 * position. If was_minimal is non-NULL, *was_minimal is set to 1 if the integer
 * was encoded using the minimal possible number of bytes and 0 otherwise.
 */
__owur static ossl_inline int CBS_peek_quic_vlint_ex(const CBS *cbs,
    uint64_t *data,
    int *was_minimal)
{
    size_t enclen;

    if (CBS_len(cbs) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*CBS_data(cbs));

    if (CBS_len(cbs) < enclen)
        return 0;

    *data = ossl_quic_vlint_decode_unchecked(CBS_data(cbs));

    if (was_minimal != NULL)
        *was_minimal = (enclen == ossl_quic_vlint_encode_len(*data));

    return 1;
}

__owur static ossl_inline int CBS_peek_quic_vlint(const CBS *cbs,
    uint64_t *data)
{
    return CBS_peek_quic_vlint_ex(cbs, data, NULL);
}

/*
 * Skips over a QUIC variable-length integer in |cbs| without decoding it.
 */
__owur static ossl_inline int CBS_skip_quic_vlint(CBS *cbs)
{
    size_t enclen;

    if (CBS_len(cbs) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*CBS_data(cbs));

    return CBS_skip(cbs, enclen);
}

/*
 * Reads a variable-length vector prefixed with a QUIC variable-length integer
 * denoting the length, and stores the contents in |sub|. |cbs| can equal
 * |sub|. Data is not copied: the |sub| CBS will share its underlying
 * buffer with the original |cbs|, so data wrapped by |cbs| must outlive
 * |sub|. Upon failure, the original |cbs| and |sub| are not modified.
 */
__owur static ossl_inline int CBS_get_quic_length_prefixed(CBS *cbs,
    CBS *sub)
{
    uint64_t length;
    CBS tmp;

    CBS_dup(cbs, &tmp);
    if (!CBS_get_quic_vlint(&tmp, &length)
        || length > SIZE_MAX
        || !CBS_get_bytes(&tmp, sub, (size_t)length))
        return 0;

    *cbs = tmp;
    return 1;
}
#endif /* OPENSSL_NO_QUIC */
#endif /* OSSL_INTERNAL_BYTESTRING_QUIC_H */
