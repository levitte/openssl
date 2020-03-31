/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>

/* Well known primitive tags */

#define DER_P_EOC                       0 /* BER End Of Contents tag */
#define DER_P_BOOLEAN                   1
#define DER_P_INTEGER                   2
#define DER_P_BIT_STRING                3
#define DER_P_OCTET_STRING              4
#define DER_P_NULL                      5
#define DER_P_OBJECT                    6
#define DER_P_OBJECT_DESCRIPTOR         7
#define DER_P_EXTERNAL                  8
#define DER_P_REAL                      9
#define DER_P_ENUMERATED               10
#define DER_P_UTF8STRING               12
#define DER_P_SEQUENCE                 16
#define DER_P_SET                      17
#define DER_P_NUMERICSTRING            18
#define DER_P_PRINTABLESTRING          19
#define DER_P_T61STRING                20
#define DER_P_VIDEOTEXSTRING           21
#define DER_P_IA5STRING                22
#define DER_P_UTCTIME                  23
#define DER_P_GENERALIZEDTIME          24
#define DER_P_GRAPHICSTRING            25
#define DER_P_ISO64STRING              26
#define DER_P_GENERALSTRING            27
#define DER_P_UNIVERSALSTRING          28
#define DER_P_BMPSTRING                30

#define DER_F_PRIMITIVE              0x00
#define DER_F_CONSTRUCTED            0x20

#define DER_C_UNIVERSAL              0x00
#define DER_C_APPLICATION            0x40
#define DER_C_CONTEXT                0x80
#define DER_C_PRIVATE                0xC0

/* Helper macros */
#define CHECKEDret(l, r, f)                     \
    do {                                        \
        (r) = (f);                              \
        if ((r) == 0) return (r);                \
        (l) += (r);                             \
    } while (0)
#define CHECKED(l, f)                           \
    do {                                        \
        int __der_ret;                          \
        CHECKEDret((l), __der_ret, (f));        \
    } while (0)

/*
 * Run-time constructors.
 *
 * They all construct DER backwards, so care should be taken to use them
 * that way.
 */

#if 0                        /* Example code should not be compiled */

/* Example:
 * To build the RSASSA-PSS AlgorithmIndentifier with the restrictions
 * hashAlgorithm = SHA256, maskGenAlgorithm = mgf1SHA256, saltLength = 20,
 * this is the expected code:
 */

const unsigned char der_oid_sha256[N]; /* N is to be determined */

/* buf is the buffer we write the DER content into, sz is its size */
unsigned char *p = buf + sz;
const unsigned char *start = buf; /* For boundary checking */
size_t length = 0;
size_t c2_length = 0;
size_t c1_length = 0;
size_t c0_length = 0;

CHECKED(c2_length, DER_w_ulong(&p, start, 20));
CHECKED(c2_length, DER_w_context(&p, start, 2, c2_length));

CHECKED(c1_length, DER_w_precompiled(&p, start, der_oid_sha256,
                                     sizeof(der_oid_sha256)));
CHECKED(c1_length, DER_w_sequence(&p, start, c1_length));
CHECKED(c1_length, DER_w_precompiled(&p, start, der_oid_mgf1,
                                     sizeof(der_oid_mgf1)));
CHECKED(c1_length, DER_w_sequence(&p, start, c1_length));
CHECKED(c1_length, DER_w_context(&p, start, 1, c1_length));

CHECKED(c0_length, DER_w_precompiled(&p, start, der_oid_sha256,
                                     sizeof(der_oid_sha256)));
CHECKED(c0_length, DER_w_sequence(&p, start, c0_length));

CHECKED(length, DER_w_sequence(&p, start, c0_length + c1_length + c2_length));

CHECKED(length, DER_w_precompiled(&p, start, der_oid_rsassaPss,
                                  sizeof(der_oid_rsassaPss)));
CHECKED(length, DER_w_sequence(&p, start, length));

/* At this point, |p| is the start of the DER blob and |length| is its length */

#endif

size_t DER_w_precompiled(unsigned char **pp, const unsigned char *start,
                       const unsigned char *precompiled, size_t precompiled_n);

size_t DER_w_boolean(unsigned char **pp, const unsigned char *start,
                     int b);
size_t DER_w_ulong(unsigned char **pp, const unsigned char *start,
                 unsigned long v);
size_t DER_w_bn(unsigned char **pp, const unsigned char *start,
                BIGNUM *v);
size_t DER_w_null(unsigned char **pp, const unsigned char *start);
size_t DER_w_sequence(unsigned char **pp, const unsigned char *start,
                      size_t n);
size_t DER_w_context(unsigned char **pp, const unsigned char *start,
                     int num, size_t length);
