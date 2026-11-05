/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "internal/bytestring.h"
#include "crypto/lms.h"
#include "crypto/lms_util.h"

/**
 * @brief Calculate the size of a public key in XDR format.
 *
 * @param data A byte array of XDR data for a LMS public key.
 *             The first 4 bytes are looked at.
 * @param datalen The size of |data|.
 * @returns The calculated size, or 0 on error.
 */
size_t ossl_lms_pubkey_length(const unsigned char *data, size_t datalen)
{
    CBS pkt;
    uint32_t lms_type;
    const LMS_PARAMS *params;

    CBS_init(&pkt, data, datalen);
    if (!CBS_get_u32(&pkt, &lms_type)
        || (params = ossl_lms_params_get(lms_type)) == NULL)
        return 0;
    return LMS_SIZE_LMS_TYPE + LMS_SIZE_OTS_TYPE + LMS_SIZE_I + params->n;
}

/*
 * @brief Decode LMS public key data in XDR format into a LMS_KEY object.
 *
 * See RFC 8554 Algorithm 6: Steps 1 & 2.
 * The XDR format is lms_type[4] || ots_type[4] || I[16] || K[n]
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of CBS_get API's.
 * This function may be called multiple times.
 *
 * @param pkt The packet to read public key data in XDR format from.
 * @param lmskey The object to store the public key into
 * @return 1 on success or 0 otherwise.
 */
static int lms_pubkey_from_pkt(LMS_KEY *lmskey, const unsigned char *pubkeydata,
    size_t publen)
{
    uint32_t lms_type;
    uint32_t ots_type;
    LMS_PUB_KEY *key = &lmskey->pub;
    CBS pkt, Id, K;

    CBS_init(&pkt, pubkeydata, publen);
    key->encoded = (unsigned char *)CBS_data(&pkt);
    if (!CBS_get_u32(&pkt, &lms_type))
        goto err;
    lmskey->lms_params = ossl_lms_params_get(lms_type);
    if (lmskey->lms_params == NULL
        || !CBS_get_u32(&pkt, &ots_type))
        goto err;
    lmskey->ots_params = ossl_lm_ots_params_get(ots_type);
    if (lmskey->ots_params == NULL)
        goto err;

    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(lmskey->ots_params, lmskey->lms_params)
        || !CBS_get_bytes(&pkt, &Id, LMS_SIZE_I)
        || !CBS_get_bytes(&pkt, &K, lmskey->lms_params->n))
        goto err;
    lmskey->Id = (unsigned char *)CBS_data(&Id);
    key->K = (unsigned char *)CBS_data(&K);
    key->encodedlen = (unsigned char *)CBS_data(&pkt) - key->encoded;
    return CBS_len(&pkt) == 0;
err:
    return 0;
}

/*
 * @brief Decode LMS public key data in XDR format into a LMS_KEY object.
 * Used by the LMS public key decoder.
 * The XDR format is lms_type[4] || ots_type[4] || I[16] || K[n]
 *
 * @param pub byte array of public key data in XDR format.
 * @param publen is the size of |pub|.
 * @param lmskey The LMS_KEY object to store the public key into.
 * @returns 1 on success, or 0 otherwise. 0 is returned if either |pub| is
 * invalid or |publen| is not the correct size (i.e. trailing data is not allowed)
 */
int ossl_lms_pubkey_decode(const unsigned char *pub, size_t publen,
    LMS_KEY *lmskey)
{
    LMS_PUB_KEY *pkey = &lmskey->pub;

    if (pkey->encoded != NULL) {
        OPENSSL_free(pkey->encoded);
        pkey->encodedlen = 0;
    }
    pkey->encoded = OPENSSL_memdup(pub, publen);
    if (pkey->encoded == NULL)
        return 0;

    if (!lms_pubkey_from_pkt(lmskey, pkey->encoded, publen))
        goto err;
    pkey->encodedlen = publen;
    return 1;
err:
    OPENSSL_free(pkey->encoded);
    pkey->encoded = NULL;
    pkey->encodedlen = 0;
    return 0;
}

/**
 * @brief Load a LMS public key from OSSL_PARAM data.
 *
 * @param params An array of OSSL_PARAM
 * @param lmskey The LMS_KEY to load the public key data into.
 * @returns 1 on success, or 0 otherwise.
 */
int ossl_lms_pubkey_from_params(const OSSL_PARAM *pub, LMS_KEY *lmskey)
{
    /*
     * An LMS_KEY with no public key material is unusable - lms_params
     * and ots_params would remain NULL and any subsequent consumer op
     * (lms_get_params -> ossl_lms_key_get_pub_len, lms_verify_msg_init
     * -> setdigest, ...) would dereference NULL.  Require the caller
     * to supply a well-formed OSSL_PKEY_PARAM_PUB_KEY.
     */
    if (pub == NULL
        || pub->data == NULL
        || pub->data_type != OSSL_PARAM_OCTET_STRING
        || !ossl_lms_pubkey_decode(pub->data, pub->data_size, lmskey))
        return 0;
    return 1;
}
