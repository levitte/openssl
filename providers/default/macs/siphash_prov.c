/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SIPHASH

# include <string.h>
# include <openssl/core_numbers.h>
# include <openssl/core_names.h>
# include <openssl/params.h>
# include <openssl/evp.h>
# include <openssl/err.h>

# include "internal/siphash.h"
# include "../../../crypto/siphash/siphash_local.h"

# include "internal/providercommonerr.h"
# include "internal/provider_algs.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_OP_mac_newctx_fn siphash_new;
static OSSL_OP_mac_dupctx_fn siphash_dup;
static OSSL_OP_mac_freectx_fn siphash_free;
static OSSL_OP_mac_ctx_set_param_types_fn siphash_set_param_types;
static OSSL_OP_mac_ctx_set_params_fn siphash_set_params;
static OSSL_OP_mac_size_fn siphash_size;
static OSSL_OP_mac_init_fn siphash_init;
static OSSL_OP_mac_update_fn siphash_update;
static OSSL_OP_mac_final_fn siphash_final;

struct siphash_data_st {
    void *provctx;
    SIPHASH siphash;             /* Siphash data */
};

static void *siphash_new(void *provctx)
{
    struct siphash_data_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    ctx->provctx = provctx;
    return ctx;
}

static void siphash_free(void *vmacctx)
{
    OPENSSL_free(vmacctx);
}

static void *siphash_dup(void *vsrc)
{
    struct siphash_data_st *ssrc = vsrc;
    struct siphash_data_st *sdst = siphash_new(ssrc->provctx);

    if (sdst == NULL)
        return NULL;

    sdst->siphash = ssrc->siphash;
    return sdst;
}

static size_t siphash_size(void *vmacctx)
{
    struct siphash_data_st *ctx = vmacctx;

    return SipHash_hash_size(&ctx->siphash);
}

static int siphash_init(void *vmacctx)
{
    /* Not much to do here, actual initialization happens through controls */
    return 1;
}

static int siphash_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct siphash_data_st *ctx = vmacctx;

    SipHash_Update(&ctx->siphash, data, datalen);
    return 1;
}

static int siphash_final(void *vmacctx, unsigned char *out, size_t *outl,
                         size_t outsize)
{
    struct siphash_data_st *ctx = vmacctx;
    size_t hlen = siphash_size(ctx);

    if (outsize < hlen)
        return 0;

    *outl = hlen;
    return SipHash_Final(&ctx->siphash, out, hlen);
}

static const OSSL_PARAM known_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_OUTLEN, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL), /* Same as "outlen" */
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_DIGESTSIZE, NULL), /* Same as "outlen" */
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *siphash_set_param_types(void)
{
    return known_params;
}

static int siphash_set_params(void *vmacctx, const OSSL_PARAM *params)
{
    struct siphash_data_st *ctx = vmacctx;
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_OUTLEN)) != NULL
        || ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGESTSIZE))
            != NULL)
        || ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE))
            != NULL)) {
        size_t size;

        if (!OSSL_PARAM_get_size_t(p, &size)
            || !SipHash_set_hash_size(&ctx->siphash, size))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != SIPHASH_KEY_SIZE
            || !SipHash_Init(&ctx->siphash, p->data, 0, 0))
            return 0;
    return 1;
}

const OSSL_DISPATCH siphash_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))siphash_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))siphash_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))siphash_free },
    { OSSL_FUNC_MAC_SIZE, (void (*)(void))siphash_size },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))siphash_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))siphash_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))siphash_final },
    { OSSL_FUNC_MAC_CTX_SET_PARAM_TYPES,
      (void (*)(void))siphash_set_param_types },
    { OSSL_FUNC_MAC_CTX_SET_PARAMS, (void (*)(void))siphash_set_params },
    { 0, NULL }
};

#endif
