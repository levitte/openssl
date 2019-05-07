/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/ossl_typ.h>
#include "internal/nelem.h"
#include "internal/evp_int.h"
#include "internal/provider.h"
#include "evp_locl.h"

EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac)
{
    EVP_MAC_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_MAC_CTX));

    if (ctx == NULL
        || (ctx->data = mac->newctx(ossl_provider_ctx(mac->prov))) == NULL) {
        EVPerr(EVP_F_EVP_MAC_CTX_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = mac;
    }
    return ctx;
}

void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx)
{
    if (ctx != NULL && ctx->data != NULL) {
        ctx->meth->freectx(ctx->data);
        ctx->data = NULL;
    }
    OPENSSL_free(ctx);
}

EVP_MAC_CTX *EVP_MAC_CTX_dup(const EVP_MAC_CTX *src)
{
    EVP_MAC_CTX *dst;

    if (src->data == NULL)
        return NULL;

    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL) {
        EVPerr(EVP_F_EVP_MAC_CTX_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dst = *src;

    dst->data = src->meth->dupctx(src->data);
    if (dst->data == NULL) {
        EVP_MAC_CTX_free(dst);
        return NULL;
    }

    return dst;
}

EVP_MAC *EVP_MAC_CTX_mac(EVP_MAC_CTX *ctx)
{
    return ctx->meth;
}

size_t EVP_MAC_size(EVP_MAC_CTX *ctx)
{
    if (ctx->data != NULL)
        return ctx->meth->size(ctx->data);
    /* If the MAC hasn't been initialized yet, we return zero */
    return 0;
}

int EVP_MAC_init(EVP_MAC_CTX *ctx)
{
    return ctx->meth->init(ctx->data);
}

int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)
{
    if (datalen == 0)
        return 1;
    return ctx->meth->update(ctx->data, data, datalen);
}

int EVP_MAC_final(EVP_MAC_CTX *ctx,
                  unsigned char *out, size_t *outl, size_t outsize)
{
    int l = EVP_MAC_size(ctx);

    if (l < 0)
        return 0;
    if (outl != NULL)
        *outl = l;
    if (out == NULL)
        return 1;
    return ctx->meth->final(ctx->data, out, outl, outsize);
}

int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[])
{
    return ctx->meth->ctx_get_params(ctx->data, params);
}

int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[])
{
    return ctx->meth->ctx_set_params(ctx->data, params);
}
