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

static INVALIDTEMPLATE *d2i_INVALIDTEMPLATE(INVALIDTEMPLATE **a,
                                            const unsigned char **in, long len)
{
    return (INVALIDTEMPLATE *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                            ASN1_ITEM_rptr(INVALIDTEMPLATE));
}
static void INVALIDTEMPLATE_free(INVALIDTEMPLATE *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(INVALIDTEMPLATE));
}

/* Empty sequence for invalid template test */
static unsigned char t_invalid_template[] = {
    0x30, 0x03,                  /* SEQUENCE tag + length */
    0x0c, 0x01, 0x41             /* UTF8String, length 1, "A" */
};

static int test_invalid_template(void)
{
    const unsigned char *p = t_invalid_template;
    INVALIDTEMPLATE *tmp = d2i_INVALIDTEMPLATE(NULL, &p,
                                               sizeof(t_invalid_template));

    /* We expect a NULL pointer return */
    if (tmp == NULL)
        return 1;

    INVALIDTEMPLATE_free(tmp);
    printf("FAILED: d2i_INVALIDTEMPLATE returned a value we did not expect\n");

    return 0;
}

int main(void)
{
    if (!test_invalid_template())
        return 1;

    return 0;
}
