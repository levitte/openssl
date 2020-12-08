/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1t.h>

typedef struct {
    ASN1_STRING *invalidDirString;
} INVALIDTEMPLATE;

ASN1_SEQUENCE(INVALIDTEMPLATE) = {
    /*
     * DirectoryString is a CHOICE type so it must use explicit tagging -
     * but we deliberately use implicit here, which makes this template invalid.
     */
    ASN1_IMP(INVALIDTEMPLATE, invalidDirString, DIRECTORYSTRING, 12)
} ASN1_SEQUENCE_END(INVALIDTEMPLATE)

static int i2d_INVALIDTEMPLATE(INVALIDTEMPLATE *a, unsigned char **out)
{
        return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(INVALIDTEMPLATE));
}
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(INVALIDTEMPLATE)

static int test_invalid_template(void)
{
    INVALIDTEMPLATE *temp = INVALIDTEMPLATE_new();
    int ret;

    if (temp == NULL) {
        printf("FAILED: Unabled to construct INVALIDTEMPLATE object\n");
        return 0;
    }

    ret = i2d_INVALIDTEMPLATE(temp, NULL);

    INVALIDTEMPLATE_free(temp);

    if (ret >= 0)
        printf("FAILED: i2d_INVALIDTEMPLATE succeeded when it should fail\n");

    /* We expect the i2d operation to fail */
    return ret < 0;
}

int main(void)
{

    if (!test_invalid_template()) {
        printf("Failed: test_invalid_template failed\n");
        return 1;
    }
    return 0;
}
