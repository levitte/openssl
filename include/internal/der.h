/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#include "internal/packet.h"

/*
 * NOTE: X.690 numbers the identifier octet bits 1 to 8.
 * We use the same numbering in comments here.
 */

/* Well known primitive tags */

/*
 * DER UNIVERSAL tags, occupying bits 1-5 in the DER identifier byte
 * These are only valid for the UNIVERSAL class.  With the other classes,
 * these bits have a different meaning.
 */
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

/* DER Flags, occupying bit 6 in the DER identifier byte */
#define DER_F_PRIMITIVE              0x00
#define DER_F_CONSTRUCTED            0x20

/* DER classes tags, occupying bits 7-8 in the DER identifier byte */
#define DER_C_UNIVERSAL              0x00
#define DER_C_APPLICATION            0x40
#define DER_C_CONTEXT                0x80
#define DER_C_PRIVATE                0xC0

/*
 * Run-time constructors.
 *
 * They all construct DER backwards, so care should be taken to use them
 * that way.
 */

/* This can be used for all items that don't have a context */
#define DER_NO_CONTEXT  -1

int DER_w_precompiled(WPACKET *pkt, int cont,
                      const unsigned char *precompiled, size_t precompiled_n);

int DER_w_boolean(WPACKET *pkt, int cont, int b);
int DER_w_ulong(WPACKET *pkt, int cont, unsigned long v);
int DER_w_bn(WPACKET *pkt, int cont, const BIGNUM *v);
int DER_w_null(WPACKET *pkt, int cont);

/*
 * All constructors for constructed elements have a start and a stop function
 */
int DER_w_start_sequence(WPACKET *pkt, int cont);
int DER_w_end_sequence(WPACKET *pkt, int cont);



#if 0                        /* Example code should not be compiled */

/*
 * Example:
 * To build the RSASSA-PSS AlgorithmIndentifier with the restrictions
 * hashAlgorithm = SHA256, maskGenAlgorithm = mgf1SHA256, saltLength = 20,
 * this is the expected code:
 *
 * Reminder:
 * RSASSA-PSS-params ::= SEQUENCE {
 *     hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
 *     maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
 *     saltLength         [2] INTEGER            DEFAULT 20,
 *     trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 * }
 */

const unsigned char der_oid_sha256[N]; /* N is to be determined */

/* buf is the buffer we write the DER content into, sz is its size */
WPACKET pkt;

unsigned char *p = buf + sz;

if (!WPACKET_init_der(&pkt, buf, sz)
    /* AlgorithmIdentifier SEQUENCE subpacket */
    || (!DER_w_start_sequence(&pkt, DER_NO_CONTEXT)
        /* Parameter subpacket */
        || (!DER_w_start_sequence(&pkt, DER_NO_CONTEXT)
            /* Context 2 */
            || !DER_w_ulong(&pkt, 2, 20)
            /* Context 1 */
            || !DER_w_precompiled(&pkt, 1,
                                  der_oid_mgf1, sizeof(der_oid_mgf1))
            /* Context 0 */
            || !DER_w_precompiled(&pkt, 0,
                                  der_oid_sha256, sizeof(der_oid_sha256))
            || !DER_w_end_sequence(&pkt, DER_NO_CONTEXT))
        || !DER_w_precompiled(&pkt, DER_NO_CONTEXT,
                              der_oid_rsassaPss, sizeof(der_oid_rsassaPss))
        || !DER_w_end_sequence(&pkt, DER_NO_CONTEXT))
    || !WPACKET_finish(&pkt)
    || !WPACKET_get_total_written(&pkt, &length)
    || (p = WPACKET_get_curr(&pkt)) == NULL)
    /* ERROR */ ;

/* At this point, |p| is the start of the DER blob and |length| is its length */

#endif

