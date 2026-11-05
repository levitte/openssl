/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PACKET_H
#define OSSL_INTERNAL_PACKET_H
#pragma once

#include <string.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>

#include "internal/numbers.h"

/* Writable packets */

typedef struct wpacket_sub WPACKET_SUB;
struct wpacket_sub {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    WPACKET_SUB *parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t pwritten;

    /* Flags for this sub-packet */
    unsigned int flags;
};

typedef struct wpacket_st WPACKET;
struct wpacket_st {
    /* The buffer where we store the output data */
    BUF_MEM *buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char *staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t curr;

    /* Number of bytes written so far */
    size_t written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t maxsize;

    /* Our sub-packets (always at least one if not finished) */
    WPACKET_SUB *subs;

    /* Writing from the end first? */
    unsigned int endfirst : 1;
};

/* Flags */

/* Default */
#define WPACKET_FLAGS_NONE 0

/* Error on WPACKET_close() if no data written to the WPACKET */
#define WPACKET_FLAGS_NON_ZERO_LENGTH 1

/*
 * Abandon all changes on WPACKET_close() if no data written to the WPACKET,
 * i.e. this does not write out a zero packet length
 */
#define WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH 2

/* QUIC variable-length integer length prefix */
#define WPACKET_FLAGS_QUIC_VLINT 4

/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes);

/*
 * Same as WPACKET_init_len except there is no preallocation of the WPACKET
 * length.
 */
int WPACKET_init(WPACKET *pkt, BUF_MEM *buf);

/*
 * Same as WPACKET_init_len except there is no underlying buffer. No data is
 * ever actually written. We just keep track of how much data would have been
 * written if a buffer was there.
 */
int WPACKET_init_null(WPACKET *pkt, size_t lenbytes);

/*
 * Same as WPACKET_init_null except we set the WPACKET to assume DER length
 * encoding for sub-packets.
 */
int WPACKET_init_null_der(WPACKET *pkt);

/*
 * Same as WPACKET_init_len except we do not use a growable BUF_MEM structure.
 * A fixed buffer of memory |buf| of size |len| is used instead. A failure will
 * occur if you attempt to write beyond the end of the buffer
 */
int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
    size_t lenbytes);

/*
 * Same as WPACKET_init_static_len except lenbytes is always 0, and we set the
 * WPACKET to write to the end of the buffer moving towards the start and use
 * DER length encoding for sub-packets.
 */
int WPACKET_init_der(WPACKET *pkt, unsigned char *buf, size_t len);

/*
 * Set the flags to be applied to the current sub-packet
 */
int WPACKET_set_flags(WPACKET *pkt, unsigned int flags);

/*
 * Closes the most recent sub-packet. It also writes out the length of the
 * packet to the required location (normally the start of the WPACKET) if
 * appropriate. The top level WPACKET should be closed using WPACKET_finish()
 * instead of this function.
 */
int WPACKET_close(WPACKET *pkt);

/*
 * The same as WPACKET_close() but only for the top most WPACKET. Additionally
 * frees memory resources for this WPACKET.
 */
int WPACKET_finish(WPACKET *pkt);

/*
 * Iterate through all the sub-packets and write out their lengths as if they
 * were being closed. The lengths will be overwritten with the final lengths
 * when the sub-packets are eventually closed (which may be different if more
 * data is added to the WPACKET). This function fails if a sub-packet is of 0
 * length and WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH is set.
 */
int WPACKET_fill_lengths(WPACKET *pkt);

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the current position in |pkt| to store the sub-packets length once we know
 * it. The sub-packet start is set at |offset| from current position in |pkt|
 * Don't call this directly. Use the convenience macros below instead.
 */
int WPACKET_start_sub_packet_at_offset_len__(WPACKET *pkt, size_t lenbytes,
    size_t offset);

#define WPACKET_start_sub_packet_u24_at_offset(pkt, offset) \
    WPACKET_start_sub_packet_at_offset_len__((pkt), 3, (offset))

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the start of the sub-packet to store its length once we know it. Don't
 * call this directly. Use the convenience macros below instead.
 */
int WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes);

/*
 * Convenience macros for calling WPACKET_start_sub_packet_len with different
 * lengths
 */
#define WPACKET_start_sub_packet_u8(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 1)
#define WPACKET_start_sub_packet_u16(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 2)
#define WPACKET_start_sub_packet_u24(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 3)
#define WPACKET_start_sub_packet_u32(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 4)

/*
 * Same as WPACKET_start_sub_packet_len__() except no bytes are pre-allocated
 * for the sub-packet length.
 */
int WPACKET_start_sub_packet(WPACKET *pkt);

/*
 * Allocate bytes in the WPACKET for the output. This reserves the bytes
 * and counts them as "written", but doesn't actually do the writing. A pointer
 * to the allocated bytes is stored in |*allocbytes|. |allocbytes| may be NULL.
 * WARNING: the allocated bytes must be filled in immediately, without further
 * WPACKET_* calls. If not then the underlying buffer may be realloc'd and
 * change its location.
 */
int WPACKET_allocate_bytes(WPACKET *pkt, size_t len,
    unsigned char **allocbytes);

/*
 * The same as WPACKET_allocate_bytes() except additionally a new sub-packet is
 * started for the allocated bytes, and then closed immediately afterwards. The
 * number of length bytes for the sub-packet is in |lenbytes|. Don't call this
 * directly. Use the convenience macros below instead.
 */
int WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes);

/*
 * Convenience macros for calling WPACKET_sub_allocate_bytes with different
 * lengths
 */
#define WPACKET_sub_allocate_bytes_u8(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_allocate_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_allocate_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_allocate_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 4)

/*
 * The same as WPACKET_allocate_bytes() except the reserved bytes are not
 * actually counted as written. Typically this will be for when we don't know
 * how big arbitrary data is going to be up front, but we do know what the
 * maximum size will be. If this function is used, then it should be immediately
 * followed by a WPACKET_allocate_bytes() call before any other WPACKET
 * functions are called (unless the write to the allocated bytes is abandoned).
 *
 * For example: If we are generating a signature, then the size of that
 * signature may not be known in advance. We can use WPACKET_reserve_bytes() to
 * handle this:
 *
 *  if (!WPACKET_sub_reserve_bytes_u16(&pkt, EVP_PKEY_get_size(pkey), &sigbytes1)
 *          || EVP_SignFinal(md_ctx, sigbytes1, &siglen, pkey) <= 0
 *          || !WPACKET_sub_allocate_bytes_u16(&pkt, siglen, &sigbytes2)
 *          || sigbytes1 != sigbytes2)
 *      goto err;
 */
int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes);

/*
 * The "reserve_bytes" equivalent of WPACKET_sub_allocate_bytes__()
 */
int WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes);

/*
 * Convenience macros for  WPACKET_sub_reserve_bytes with different lengths
 */
#define WPACKET_sub_reserve_bytes_u8(pkt, len, bytes) \
    WPACKET_reserve_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_reserve_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_reserve_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_reserve_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 4)

/*
 * Write the value stored in |val| into the WPACKET. The value will consume
 * |bytes| amount of storage. An error will occur if |val| cannot be
 * accommodated in |bytes| storage, e.g. attempting to write the value 256 into
 * 1 byte will fail. Don't call this directly. Use the convenience macros below
 * instead.
 */
int WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t bytes);

/*
 * Convenience macros for calling WPACKET_put_bytes with different
 * lengths
 */
#define WPACKET_put_bytes_u8(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 1)
#define WPACKET_put_bytes_u16(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 2)
#define WPACKET_put_bytes_u24(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 3)
#define WPACKET_put_bytes_u32(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 4)
#define WPACKET_put_bytes_u48(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 6)
#define WPACKET_put_bytes_u64(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 8)

/* Set a maximum size that we will not allow the WPACKET to grow beyond */
int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize);

/* Copy |len| bytes of data from |*src| into the WPACKET. */
int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len);

/* Set |len| bytes of data to |ch| into the WPACKET. */
int WPACKET_memset(WPACKET *pkt, int ch, size_t len);

/*
 * Copy |len| bytes of data from |*src| into the WPACKET and prefix with its
 * length (consuming |lenbytes| of data for the length). Don't call this
 * directly. Use the convenience macros below instead.
 */
int WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len,
    size_t lenbytes);

/* Convenience macros for calling WPACKET_sub_memcpy with different lengths */
#define WPACKET_sub_memcpy_u8(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 1)
#define WPACKET_sub_memcpy_u16(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 2)
#define WPACKET_sub_memcpy_u24(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 3)
#define WPACKET_sub_memcpy_u32(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 4)

/*
 * Return the total number of bytes written so far to the underlying buffer
 * including any storage allocated for length bytes
 */
int WPACKET_get_total_written(WPACKET *pkt, size_t *written);

/*
 * Returns the length of the current sub-packet. This excludes any bytes
 * allocated for the length itself.
 */
int WPACKET_get_length(WPACKET *pkt, size_t *len);

/*
 * Returns a pointer to the current write location, but does not allocate any
 * bytes.
 */
unsigned char *WPACKET_get_curr(WPACKET *pkt);

/* Returns true if the underlying buffer is actually NULL */
int WPACKET_is_null_buf(WPACKET *pkt);

/* Release resources in a WPACKET if a failure has occurred. */
void WPACKET_cleanup(WPACKET *pkt);

#endif /* OSSL_INTERNAL_PACKET_H */
