#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include "internal/evp_int.h"
#include "internal/provider.h"
#include "evp_locl.h"

static int evp_mac_up_ref(void *vmac)
{
    EVP_MAC *mac = vmac;
    int ref = 0;

    CRYPTO_UP_REF(&mac->refcnt, &ref, mac->lock);
    return 1;
}

static void evp_mac_free(void *vmac)
{
    EVP_MAC *mac = vmac;
    int ref = 0;

    if (mac == NULL)
        return;

    CRYPTO_DOWN_REF(&mac->refcnt, &ref, mac->lock);
    if (ref > 0)
        return;
    ossl_provider_free(mac->prov);
    OPENSSL_free(mac->name);
    CRYPTO_THREAD_lock_free(mac->lock);
    OPENSSL_free(mac);
}

static void *evp_mac_new(void)
{
    EVP_MAC *mac = NULL;

    if ((mac = OPENSSL_zalloc(sizeof(*mac))) == NULL
        || (mac->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        evp_mac_free(mac);
        return NULL;
    }

    mac->refcnt = 1;

    return mac;
}

static void *evp_mac_from_dispatch(const char *name, const OSSL_DISPATCH *fns,
                                   OSSL_PROVIDER *prov)
{
    EVP_MAC *mac = NULL;
    int fnmaccnt = 0, fnctxcnt = 0;

    if ((mac = evp_mac_new()) == NULL
        || (mac->name = OPENSSL_strdup(name)) == NULL) {
        EVP_MAC_free(mac);
        return NULL;
    }

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_MAC_NEWCTX:
            if (mac->newctx != NULL)
                break;
            mac->newctx = OSSL_get_OP_mac_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_MAC_DUPCTX:
            if (mac->dupctx != NULL)
                break;
            mac->dupctx = OSSL_get_OP_mac_dupctx(fns);
            break;
        case OSSL_FUNC_MAC_FREECTX:
            if (mac->freectx != NULL)
                break;
            mac->freectx = OSSL_get_OP_mac_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_MAC_SIZE:
            if (mac->size != NULL)
                break;
            mac->size = OSSL_get_OP_mac_size(fns);
            break;
        case OSSL_FUNC_MAC_INIT:
            if (mac->init != NULL)
                break;
            mac->init = OSSL_get_OP_mac_init(fns);
            fnmaccnt++;
            break;
        case OSSL_FUNC_MAC_UPDATE:
            if (mac->update != NULL)
                break;
            mac->update = OSSL_get_OP_mac_update(fns);
            fnmaccnt++;
            break;
        case OSSL_FUNC_MAC_FINAL:
            if (mac->final != NULL)
                break;
            mac->final = OSSL_get_OP_mac_final(fns);
            fnmaccnt++;
            break;
        case OSSL_FUNC_MAC_CTX_GET_PARAM_TYPES:
            if (mac->ctx_get_param_types != NULL)
                break;
            mac->ctx_get_param_types =
                OSSL_get_OP_mac_ctx_get_param_types(fns);
            break;
        case OSSL_FUNC_MAC_CTX_SET_PARAM_TYPES:
            if (mac->ctx_set_param_types != NULL)
                break;
            mac->ctx_set_param_types =
                OSSL_get_OP_mac_ctx_set_param_types(fns);
            break;
        case OSSL_FUNC_MAC_CTX_GET_PARAMS:
            if (mac->ctx_get_params != NULL)
                break;
            mac->ctx_get_params = OSSL_get_OP_mac_ctx_get_params(fns);
            break;
        case OSSL_FUNC_MAC_CTX_SET_PARAMS:
            if (mac->ctx_set_params != NULL)
                break;
            mac->ctx_set_params = OSSL_get_OP_mac_ctx_set_params(fns);
            break;
        }
    }
    if (fnmaccnt != 3
        || fnctxcnt != 2
        || mac->size == NULL) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "mac" functions, and a complete set of context
         * management functions, as well as the size function.
         */
        evp_mac_free(mac);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    mac->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return mac;
}

EVP_MAC *EVP_MAC_fetch(OPENSSL_CTX *libctx, const char *algorithm,
                       const char *properties)
{
    return evp_generic_fetch(libctx, OSSL_OP_MAC, algorithm, properties,
                             evp_mac_from_dispatch, evp_mac_up_ref,
                             evp_mac_free);
}

int EVP_MAC_up_ref(EVP_MAC *mac)
{
    return evp_mac_up_ref(mac);
}

void EVP_MAC_free(EVP_MAC *mac)
{
    evp_mac_free(mac);
}

const char *EVP_MAC_name(const EVP_MAC *mac)
{
    return mac->name;
}

const OSSL_PROVIDER *EVP_MAC_provider(const EVP_MAC *mac)
{
    return mac->prov;
}

const OSSL_PARAM *EVP_MAC_CTX_get_param_types(const EVP_MAC *mac)
{
    if (mac->ctx_get_param_types == NULL)
        return NULL;
    return mac->ctx_get_param_types();
}

const OSSL_PARAM *EVP_MAC_CTX_set_param_types(const EVP_MAC *mac)
{
    if (mac->ctx_set_param_types == NULL)
        return NULL;
    return mac->ctx_set_param_types();
}
