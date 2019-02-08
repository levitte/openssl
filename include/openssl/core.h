/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_H
# define OSSL_CORE_H

# include <stddef.h>

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Base types
 * ----------
 *
 * These are the types that the OpenSSL core and providers have in common
 * to communicate data between them.
 */

/*
 * Dispatch table element.  function_id numbers are defined further down,
 * see macros with '_FUNC' in their names.
 *
 * An array of these is always terminated by function_id == 0
 */
struct ossl_dispatch_st {
    int function_id;
    void (*function)(void);
};

/*
 * Other items, essentially an int<->pointer map element.
 * We could have used this as the dispatch table element as well, if it
 * wasn't for certain compilers that warn with you store a function pointer
 * in a non-function pointer variable.
 *
 * This is used whenever we need to pass things like a table of error reason
 * codes <-> reason string maps, parameter name <-> parameter type maps, ...
 *
 * Usage determines which field works as key if any, rather than field order.
 *
 * An array of these is always terminated by id == 0 && ptr == NULL
 */
struct ossl_item_st {
    int id;
    void *ptr;
};

/*
 * Type to tie together algorithm name, property definition string and
 * the algorithm implementation in form of a dispatch table.
 *
 * An array of these is always terminated by algorithm_name == NULL
 */
struct ossl_algorithm_st {
    const char *algorithm_name;      /* key */
    const char *property_definition; /* key */
    const OSSL_DISPATCH *implementation;
};

/*
 * Type to pass object data in a uniform way, without exposing the object
 * structure.
 *
 * An array of these is always terminated by key == NULL
 */
struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned char data_type;     /* declare what kind of content is in buffer */
    void *buffer;                /* value being passed in or out */
    size_t buffer_size;          /* buffer size */
    size_t *return_size;         /* OPTIONAL: address to content size */
};

/* Currently supported OSSL_PARAM data types */
/*
 * OSSL_PARAM_INTEGER and OSSL_PARAM_UNSIGNED_INTEGER
 * are arbitrary length and therefore require an arbitrarily sized buffer,
 * since they may be used to pass numbers larger than what is natively
 * available.
 *
 * The number must be buffered in native form, i.e. MSB first on B_ENDIAN
 * systems and LSB first on L_ENDIAN systems.  This means that arbitrary
 * native integers can be stored in the buffer, just make sure that the
 * buffer size is correct and the buffer itself is properly aligned (for
 * example by having the buffer field point at an C integer).
 */
# define OSSL_PARAM_INTEGER              1
# define OSSL_PARAM_UNSIGNED_INTEGER     2
/*-
 * OSSL_PARAM_REAL
 * is a C binary floating point values in native form and alignment.
 */
# define OSSL_PARAM_REAL                 3
/*-
 * OSSL_PARAM_UTF8_STRING
 * is a printable string.  Is expteced to be printed as it is.
 */
# define OSSL_PARAM_UTF8_STRING          4
/*-
 * OSSL_PARAM_OCTET_STRING
 * is a string of bytes with no further specification.  Is expected to be
 * printed as a hexdump.
 */
# define OSSL_PARAM_OCTET_STRING         5

/*-
 * Pointer types for strings.
 * These can be used in place of OSSL_PARAM_UTF8_STRING and
 * OSSL_PARAM_OCTET_STRING.  The buffer will contain a simple
 * pointer to the actual string, and the buffer size is always
 * sizeof(void *).
 *
 * WARNING!  Using these is FRAGILE, as it assumes that the actual
 * string and its location are constant.
 */
# define OSSL_PARAM_UTF8_STRING_PTR      6
# define OSSL_PARAM_OCTET_STRING_PTR     7

# ifdef __cplusplus
}
# endif

#endif
