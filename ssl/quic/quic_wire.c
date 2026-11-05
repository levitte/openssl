/*
 * Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/macros.h>
#include <openssl/objects.h>
#include "internal/quic_ssl.h"
#include "internal/quic_vlint.h"
#include "internal/quic_wire.h"
#include "internal/quic_error.h"

OSSL_SAFE_MATH_UNSIGNED(uint64_t, uint64_t)

int ossl_quic_frame_ack_contains_pn(const OSSL_QUIC_FRAME_ACK *ack, QUIC_PN pn)
{
    size_t i;

    for (i = 0; i < ack->num_ack_ranges; ++i)
        if (pn >= ack->ack_ranges[i].start
            && pn <= ack->ack_ranges[i].end)
            return 1;

    return 0;
}

/*
 * QUIC Wire Format Encoding
 * =========================
 */

int ossl_quic_wire_encode_padding(WPACKET *pkt, size_t num_bytes)
{
    /*
     * PADDING is frame type zero, which as a variable-length integer is
     * represented as a single zero byte. As an optimisation, just use memset.
     */
    return WPACKET_memset(pkt, 0, num_bytes);
}

static int encode_frame_hdr(WPACKET *pkt, uint64_t frame_type)
{
    return WPACKET_quic_write_vlint(pkt, frame_type);
}

int ossl_quic_wire_encode_frame_ping(WPACKET *pkt)
{
    return encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PING);
}

int ossl_quic_wire_encode_frame_ack(WPACKET *pkt,
    uint32_t ack_delay_exponent,
    const OSSL_QUIC_FRAME_ACK *ack)
{
    uint64_t frame_type = ack->ecn_present ? OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN
                                           : OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN;

    uint64_t largest_ackd, first_ack_range, ack_delay_enc;
    uint64_t i, num_ack_ranges = ack->num_ack_ranges;
    OSSL_TIME delay;

    if (num_ack_ranges == 0)
        return 0;

    delay = ossl_time_divide(ossl_time_divide(ack->delay_time, OSSL_TIME_US),
        (uint64_t)1 << ack_delay_exponent);
    ack_delay_enc = ossl_time2ticks(delay);

    largest_ackd = ack->ack_ranges[0].end;
    first_ack_range = ack->ack_ranges[0].end - ack->ack_ranges[0].start;

    if (!encode_frame_hdr(pkt, frame_type)
        || !WPACKET_quic_write_vlint(pkt, largest_ackd)
        || !WPACKET_quic_write_vlint(pkt, ack_delay_enc)
        || !WPACKET_quic_write_vlint(pkt, num_ack_ranges - 1)
        || !WPACKET_quic_write_vlint(pkt, first_ack_range))
        return 0;

    for (i = 1; i < num_ack_ranges; ++i) {
        uint64_t gap, range_len;

        gap = ack->ack_ranges[i - 1].start - ack->ack_ranges[i].end - 2;
        range_len = ack->ack_ranges[i].end - ack->ack_ranges[i].start;

        if (!WPACKET_quic_write_vlint(pkt, gap)
            || !WPACKET_quic_write_vlint(pkt, range_len))
            return 0;
    }

    if (ack->ecn_present)
        if (!WPACKET_quic_write_vlint(pkt, ack->ect0)
            || !WPACKET_quic_write_vlint(pkt, ack->ect1)
            || !WPACKET_quic_write_vlint(pkt, ack->ecnce))
            return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_reset_stream(WPACKET *pkt,
    const OSSL_QUIC_FRAME_RESET_STREAM *f)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_RESET_STREAM)
        || !WPACKET_quic_write_vlint(pkt, f->stream_id)
        || !WPACKET_quic_write_vlint(pkt, f->app_error_code)
        || !WPACKET_quic_write_vlint(pkt, f->final_size))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_stop_sending(WPACKET *pkt,
    const OSSL_QUIC_FRAME_STOP_SENDING *f)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_STOP_SENDING)
        || !WPACKET_quic_write_vlint(pkt, f->stream_id)
        || !WPACKET_quic_write_vlint(pkt, f->app_error_code))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_crypto_hdr(WPACKET *pkt,
    const OSSL_QUIC_FRAME_CRYPTO *f)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_CRYPTO)
        || !WPACKET_quic_write_vlint(pkt, f->offset)
        || !WPACKET_quic_write_vlint(pkt, f->len))
        return 0;

    return 1;
}

size_t ossl_quic_wire_get_encoded_frame_len_crypto_hdr(const OSSL_QUIC_FRAME_CRYPTO *f)
{
    size_t a, b, c;

    a = ossl_quic_vlint_encode_len(OSSL_QUIC_FRAME_TYPE_CRYPTO);
    b = ossl_quic_vlint_encode_len(f->offset);
    c = ossl_quic_vlint_encode_len(f->len);
    if (a == 0 || b == 0 || c == 0)
        return 0;

    return a + b + c;
}

void *ossl_quic_wire_encode_frame_crypto(WPACKET *pkt,
    const OSSL_QUIC_FRAME_CRYPTO *f)
{
    unsigned char *p = NULL;

    if (!ossl_quic_wire_encode_frame_crypto_hdr(pkt, f)
        || f->len > SIZE_MAX /* sizeof(uint64_t) > sizeof(size_t)? */
        || !WPACKET_allocate_bytes(pkt, (size_t)f->len, &p))
        return NULL;

    if (f->data != NULL)
        memcpy(p, f->data, (size_t)f->len);

    return p;
}

int ossl_quic_wire_encode_frame_new_token(WPACKET *pkt,
    const unsigned char *token,
    size_t token_len)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_NEW_TOKEN)
        || !WPACKET_quic_write_vlint(pkt, token_len)
        || !WPACKET_memcpy(pkt, token, token_len))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_stream_hdr(WPACKET *pkt,
    const OSSL_QUIC_FRAME_STREAM *f)
{
    uint64_t frame_type = OSSL_QUIC_FRAME_TYPE_STREAM;

    if (f->offset != 0)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_OFF;
    if (f->has_explicit_len)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_LEN;
    if (f->is_fin)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_FIN;

    if (!encode_frame_hdr(pkt, frame_type)
        || !WPACKET_quic_write_vlint(pkt, f->stream_id))
        return 0;

    if (f->offset != 0 && !WPACKET_quic_write_vlint(pkt, f->offset))
        return 0;

    if (f->has_explicit_len && !WPACKET_quic_write_vlint(pkt, f->len))
        return 0;

    return 1;
}

size_t ossl_quic_wire_get_encoded_frame_len_stream_hdr(const OSSL_QUIC_FRAME_STREAM *f)
{
    size_t a, b, c, d;

    a = ossl_quic_vlint_encode_len(OSSL_QUIC_FRAME_TYPE_STREAM);
    b = ossl_quic_vlint_encode_len(f->stream_id);
    if (a == 0 || b == 0)
        return 0;

    if (f->offset > 0) {
        c = ossl_quic_vlint_encode_len(f->offset);
        if (c == 0)
            return 0;
    } else {
        c = 0;
    }

    if (f->has_explicit_len) {
        d = ossl_quic_vlint_encode_len(f->len);
        if (d == 0)
            return 0;
    } else {
        d = 0;
    }

    return a + b + c + d;
}

void *ossl_quic_wire_encode_frame_stream(WPACKET *pkt,
    const OSSL_QUIC_FRAME_STREAM *f)
{

    unsigned char *p = NULL;

    if (!ossl_quic_wire_encode_frame_stream_hdr(pkt, f)
        || f->len > SIZE_MAX /* sizeof(uint64_t) > sizeof(size_t)? */)
        return NULL;

    if (!WPACKET_allocate_bytes(pkt, (size_t)f->len, &p))
        return NULL;

    if (f->data != NULL)
        memcpy(p, f->data, (size_t)f->len);

    return p;
}

int ossl_quic_wire_encode_frame_max_data(WPACKET *pkt,
    uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_MAX_DATA)
        || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_max_stream_data(WPACKET *pkt,
    uint64_t stream_id,
    uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA)
        || !WPACKET_quic_write_vlint(pkt, stream_id)
        || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_max_streams(WPACKET *pkt,
    char is_uni,
    uint64_t max_streams)
{
    if (!encode_frame_hdr(pkt, is_uni ? OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI : OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI)
        || !WPACKET_quic_write_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_data_blocked(WPACKET *pkt,
    uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED)
        || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_stream_data_blocked(WPACKET *pkt,
    uint64_t stream_id,
    uint64_t max_stream_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED)
        || !WPACKET_quic_write_vlint(pkt, stream_id)
        || !WPACKET_quic_write_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_streams_blocked(WPACKET *pkt,
    char is_uni,
    uint64_t max_streams)
{
    if (!encode_frame_hdr(pkt, is_uni ? OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI : OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI)
        || !WPACKET_quic_write_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_new_conn_id(WPACKET *pkt,
    const OSSL_QUIC_FRAME_NEW_CONN_ID *f)
{
    if (f->conn_id.id_len < 1
        || f->conn_id.id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID)
        || !WPACKET_quic_write_vlint(pkt, f->seq_num)
        || !WPACKET_quic_write_vlint(pkt, f->retire_prior_to)
        || !WPACKET_put_bytes_u8(pkt, f->conn_id.id_len)
        || !WPACKET_memcpy(pkt, f->conn_id.id, f->conn_id.id_len)
        || !WPACKET_memcpy(pkt, f->stateless_reset.token,
            sizeof(f->stateless_reset.token)))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_retire_conn_id(WPACKET *pkt,
    uint64_t seq_num)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID)
        || !WPACKET_quic_write_vlint(pkt, seq_num))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_path_challenge(WPACKET *pkt,
    uint64_t data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE)
        || !WPACKET_put_bytes_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_path_response(WPACKET *pkt,
    uint64_t data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE)
        || !WPACKET_put_bytes_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_conn_close(WPACKET *pkt,
    const OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    if (!encode_frame_hdr(pkt, f->is_app ? OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP : OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT)
        || !WPACKET_quic_write_vlint(pkt, f->error_code))
        return 0;

    /*
     * RFC 9000 s. 19.19: The application-specific variant of CONNECTION_CLOSE
     * (type 0x1d) does not include this field.
     */
    if (!f->is_app && !WPACKET_quic_write_vlint(pkt, f->frame_type))
        return 0;

    if (!WPACKET_quic_write_vlint(pkt, f->reason_len)
        || !WPACKET_memcpy(pkt, f->reason, f->reason_len))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_handshake_done(WPACKET *pkt)
{
    return encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE);
}

unsigned char *ossl_quic_wire_encode_transport_param_bytes(WPACKET *pkt,
    uint64_t id,
    const unsigned char *value,
    size_t value_len)
{
    unsigned char *b = NULL;

    if (!WPACKET_quic_write_vlint(pkt, id)
        || !WPACKET_quic_write_vlint(pkt, value_len))
        return NULL;

    if (value_len == 0)
        b = WPACKET_get_curr(pkt);
    else if (!WPACKET_allocate_bytes(pkt, value_len, (unsigned char **)&b))
        return NULL;

    if (value != NULL)
        memcpy(b, value, value_len);

    return b;
}

int ossl_quic_wire_encode_transport_param_int(WPACKET *pkt,
    uint64_t id,
    uint64_t value)
{
    if (!WPACKET_quic_write_vlint(pkt, id)
        || !WPACKET_quic_write_vlint(pkt, ossl_quic_vlint_encode_len(value))
        || !WPACKET_quic_write_vlint(pkt, value))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_transport_param_cid(WPACKET *wpkt,
    uint64_t id,
    const QUIC_CONN_ID *cid)
{
    if (cid->id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if (ossl_quic_wire_encode_transport_param_bytes(wpkt, id,
            cid->id,
            cid->id_len)
        == NULL)
        return 0;

    return 1;
}

/*
 * QUIC Wire Format Decoding
 * =========================
 */
int ossl_quic_wire_peek_frame_header(CBS *pkt, uint64_t *type,
    int *was_minimal)
{
    return CBS_peek_quic_vlint_ex(pkt, type, was_minimal);
}

int ossl_quic_wire_skip_frame_header(CBS *pkt, uint64_t *type)
{
    return CBS_get_quic_vlint(pkt, type);
}

static int expect_frame_header_mask(CBS *pkt,
    uint64_t expected_frame_type,
    uint64_t mask_bits,
    uint64_t *actual_frame_type)
{
    uint64_t actual_frame_type_;

    if (!ossl_quic_wire_skip_frame_header(pkt, &actual_frame_type_)
        || (actual_frame_type_ & ~mask_bits) != expected_frame_type)
        return 0;

    if (actual_frame_type != NULL)
        *actual_frame_type = actual_frame_type_;

    return 1;
}

static int expect_frame_header(CBS *pkt, uint64_t expected_frame_type)
{
    uint64_t actual_frame_type;

    if (!ossl_quic_wire_skip_frame_header(pkt, &actual_frame_type)
        || actual_frame_type != expected_frame_type)
        return 0;

    return 1;
}

int ossl_quic_wire_peek_frame_ack_num_ranges(const CBS *orig_pkt,
    uint64_t *total_ranges)
{
    CBS pkt = *orig_pkt;
    uint64_t ack_range_count, i;

    if (!expect_frame_header_mask(&pkt, OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN,
            1, NULL)
        || !CBS_skip_quic_vlint(&pkt)
        || !CBS_skip_quic_vlint(&pkt)
        || !CBS_get_quic_vlint(&pkt, &ack_range_count))
        return 0;

    /*
     * Ensure the specified number of ack ranges listed in the ACK frame header
     * actually are available in the frame data. This naturally bounds the
     * number of ACK ranges which can be requested by the MDPL, and therefore by
     * the MTU. This ensures we do not allocate memory for an excessive number
     * of ACK ranges.
     */
    for (i = 0; i < ack_range_count; ++i)
        if (!CBS_skip_quic_vlint(&pkt)
            || !CBS_skip_quic_vlint(&pkt))
            return 0;

    /* (cannot overflow because QUIC vlints can only encode up to 2**62-1) */
    *total_ranges = ack_range_count + 1;
    return 1;
}

int ossl_quic_wire_decode_frame_ack(CBS *pkt,
    uint32_t ack_delay_exponent,
    OSSL_QUIC_FRAME_ACK *ack,
    uint64_t *total_ranges)
{
    uint64_t frame_type, largest_ackd, ack_delay_raw;
    uint64_t ack_range_count, first_ack_range, start, end, i;

    /* This call matches both ACK_WITHOUT_ECN and ACK_WITH_ECN. */
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN,
            1, &frame_type)
        || !CBS_get_quic_vlint(pkt, &largest_ackd)
        || !CBS_get_quic_vlint(pkt, &ack_delay_raw)
        || !CBS_get_quic_vlint(pkt, &ack_range_count)
        || !CBS_get_quic_vlint(pkt, &first_ack_range))
        return 0;

    if (first_ack_range > largest_ackd)
        return 0;

    if (ack_range_count > SIZE_MAX /* sizeof(uint64_t) > sizeof(size_t)? */)
        return 0;

    start = largest_ackd - first_ack_range;

    if (ack != NULL) {
        int err = 0;
        ack->delay_time
            = ossl_time_multiply(ossl_ticks2time(OSSL_TIME_US),
                safe_mul_uint64_t(ack_delay_raw,
                    (uint64_t)1 << ack_delay_exponent,
                    &err));
        if (err)
            ack->delay_time = ossl_time_infinite();

        if (ack->num_ack_ranges > 0) {
            ack->ack_ranges[0].end = largest_ackd;
            ack->ack_ranges[0].start = start;
        }
    }

    for (i = 0; i < ack_range_count; ++i) {
        uint64_t gap, len;

        if (!CBS_get_quic_vlint(pkt, &gap)
            || !CBS_get_quic_vlint(pkt, &len))
            return 0;

        end = start - gap - 2;
        if (start < gap + 2 || len > end)
            return 0;

        if (ack != NULL && i + 1 < ack->num_ack_ranges) {
            ack->ack_ranges[i + 1].start = start = end - len;
            ack->ack_ranges[i + 1].end = end;
        }
    }

    if (ack != NULL && ack_range_count + 1 < ack->num_ack_ranges)
        ack->num_ack_ranges = (size_t)ack_range_count + 1;

    if (total_ranges != NULL)
        *total_ranges = ack_range_count + 1;

    if (frame_type == OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN) {
        uint64_t ect0, ect1, ecnce;

        if (!CBS_get_quic_vlint(pkt, &ect0)
            || !CBS_get_quic_vlint(pkt, &ect1)
            || !CBS_get_quic_vlint(pkt, &ecnce))
            return 0;

        if (ack != NULL) {
            ack->ect0 = ect0;
            ack->ect1 = ect1;
            ack->ecnce = ecnce;
            ack->ecn_present = 1;
        }
    } else if (ack != NULL) {
        ack->ecn_present = 0;
    }

    return 1;
}

int ossl_quic_wire_decode_frame_reset_stream(CBS *pkt,
    OSSL_QUIC_FRAME_RESET_STREAM *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_RESET_STREAM)
        || !CBS_get_quic_vlint(pkt, &f->stream_id)
        || !CBS_get_quic_vlint(pkt, &f->app_error_code)
        || !CBS_get_quic_vlint(pkt, &f->final_size))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stop_sending(CBS *pkt,
    OSSL_QUIC_FRAME_STOP_SENDING *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_STOP_SENDING)
        || !CBS_get_quic_vlint(pkt, &f->stream_id)
        || !CBS_get_quic_vlint(pkt, &f->app_error_code))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_crypto(CBS *pkt,
    int nodata,
    OSSL_QUIC_FRAME_CRYPTO *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_CRYPTO)
        || !CBS_get_quic_vlint(pkt, &f->offset)
        || !CBS_get_quic_vlint(pkt, &f->len)
        || f->len > SIZE_MAX /* sizeof(uint64_t) > sizeof(size_t)? */)
        return 0;

    if (f->offset + f->len > (((uint64_t)1) << 62) - 1)
        /* RFC 9000 s. 19.6 */
        return 0;

    if (nodata) {
        f->data = NULL;
    } else {
        if (CBS_len(pkt) < f->len)
            return 0;

        f->data = CBS_data(pkt);

        if (!CBS_skip(pkt, (size_t)f->len))
            return 0;
    }

    return 1;
}

int ossl_quic_wire_decode_frame_new_token(CBS *pkt,
    const unsigned char **token,
    size_t *token_len)
{
    uint64_t token_len_;

    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_NEW_TOKEN)
        || !CBS_get_quic_vlint(pkt, &token_len_))
        return 0;

    if (token_len_ > SIZE_MAX)
        return 0;

    *token = CBS_data(pkt);
    *token_len = (size_t)token_len_;

    if (!CBS_skip(pkt, (size_t)token_len_))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stream(CBS *pkt,
    int nodata,
    OSSL_QUIC_FRAME_STREAM *f)
{
    uint64_t frame_type;

    /* This call matches all STREAM values (low 3 bits are masked). */
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_STREAM,
            OSSL_QUIC_FRAME_FLAG_STREAM_MASK,
            &frame_type)
        || !CBS_get_quic_vlint(pkt, &f->stream_id))
        return 0;

    if ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_OFF) != 0) {
        if (!CBS_get_quic_vlint(pkt, &f->offset))
            return 0;
    } else {
        f->offset = 0;
    }

    f->has_explicit_len = ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_LEN) != 0);
    f->is_fin = ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_FIN) != 0);

    if (f->has_explicit_len) {
        if (!CBS_get_quic_vlint(pkt, &f->len))
            return 0;
    } else {
        if (nodata)
            f->len = 0;
        else
            f->len = CBS_len(pkt);
    }

    /*
     * RFC 9000 s. 19.8: "The largest offset delivered on a stream -- the sum of
     * the offset and data length -- cannot exceed 2**62 - 1, as it is not
     * possible to provide flow control credit for that data."
     */
    if (f->offset + f->len > (((uint64_t)1) << 62) - 1)
        return 0;

    if (nodata) {
        f->data = NULL;
    } else {
        f->data = CBS_data(pkt);

        if (f->len > SIZE_MAX /* sizeof(uint64_t) > sizeof(size_t)? */
            || !CBS_skip(pkt, (size_t)f->len))
            return 0;
    }

    return 1;
}

int ossl_quic_wire_decode_frame_max_data(CBS *pkt,
    uint64_t *max_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_MAX_DATA)
        || !CBS_get_quic_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_max_stream_data(CBS *pkt,
    uint64_t *stream_id,
    uint64_t *max_stream_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA)
        || !CBS_get_quic_vlint(pkt, stream_id)
        || !CBS_get_quic_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_max_streams(CBS *pkt,
    uint64_t *max_streams)
{
    /* This call matches both MAX_STREAMS_BIDI and MAX_STREAMS_UNI. */
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI,
            1, NULL)
        || !CBS_get_quic_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_data_blocked(CBS *pkt,
    uint64_t *max_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED)
        || !CBS_get_quic_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stream_data_blocked(CBS *pkt,
    uint64_t *stream_id,
    uint64_t *max_stream_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED)
        || !CBS_get_quic_vlint(pkt, stream_id)
        || !CBS_get_quic_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_streams_blocked(CBS *pkt,
    uint64_t *max_streams)
{
    /* This call matches both STREAMS_BLOCKED_BIDI and STREAMS_BLOCKED_UNI. */
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI,
            1, NULL)
        || !CBS_get_quic_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_new_conn_id(CBS *pkt,
    OSSL_QUIC_FRAME_NEW_CONN_ID *f)
{
    uint8_t len;

    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID)
        || !CBS_get_quic_vlint(pkt, &f->seq_num)
        || !CBS_get_quic_vlint(pkt, &f->retire_prior_to)
        || f->seq_num < f->retire_prior_to
        || !CBS_get_u8(pkt, &len)
        || len < 1
        || len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    f->conn_id.id_len = (unsigned char)len;
    if (!CBS_copy_bytes(pkt, f->conn_id.id, len))
        return 0;

    /* Clear unused bytes to allow consistent memcmp. */
    if (len < QUIC_MAX_CONN_ID_LEN)
        memset(f->conn_id.id + len, 0, QUIC_MAX_CONN_ID_LEN - len);

    if (!CBS_copy_bytes(pkt, f->stateless_reset.token,
            sizeof(f->stateless_reset.token)))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_retire_conn_id(CBS *pkt,
    uint64_t *seq_num)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID)
        || !CBS_get_quic_vlint(pkt, seq_num))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_path_challenge(CBS *pkt,
    uint64_t *data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE)
        || !CBS_get_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_path_response(CBS *pkt,
    uint64_t *data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE)
        || !CBS_get_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_conn_close(CBS *pkt,
    OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    uint64_t frame_type, reason_len;
    CBS reason;

    /* This call matches both CONN_CLOSE_TRANSPORT and CONN_CLOSE_APP. */
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT,
            1, &frame_type)
        || !CBS_get_quic_vlint(pkt, &f->error_code))
        return 0;

    f->is_app = ((frame_type & 1) != 0);

    if (!f->is_app) {
        if (!CBS_get_quic_vlint(pkt, &f->frame_type))
            return 0;
    } else {
        f->frame_type = 0;
    }

    if (!CBS_get_quic_vlint(pkt, &reason_len)
        || reason_len > SIZE_MAX)
        return 0;

    if (!CBS_get_bytes(pkt, &reason, (size_t)reason_len))
        return 0;

    f->reason = (char *)CBS_data(&reason);
    f->reason_len = (size_t)reason_len;
    return 1;
}

size_t ossl_quic_wire_decode_padding(CBS *pkt)
{
    const unsigned char *start = CBS_data(pkt), *end = start + CBS_len(pkt),
                        *p = start;

    while (p < end && *p == 0)
        ++p;

    if (!CBS_skip(pkt, p - start))
        return 0;

    return p - start;
}

int ossl_quic_wire_decode_frame_ping(CBS *pkt)
{
    return expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PING);
}

int ossl_quic_wire_decode_frame_handshake_done(CBS *pkt)
{
    return expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE);
}

int ossl_quic_wire_peek_transport_param(CBS *pkt, uint64_t *id)
{
    return CBS_peek_quic_vlint(pkt, id);
}

const unsigned char *ossl_quic_wire_decode_transport_param_bytes(CBS *pkt,
    uint64_t *id,
    size_t *len)
{
    uint64_t len_;
    const unsigned char *b = NULL;
    uint64_t id_;
    CBS body_cbs;

    if (!CBS_get_quic_vlint(pkt, &id_)
        || !CBS_get_quic_vlint(pkt, &len_))
        return NULL;

    if (len_ > SIZE_MAX
        || !CBS_get_bytes(pkt, &body_cbs, (size_t)len_))
        return NULL;

    b = CBS_data(&body_cbs);
    *len = (size_t)len_;
    if (id != NULL)
        *id = id_;
    return b;
}

int ossl_quic_wire_decode_transport_param_int(CBS *pkt,
    uint64_t *id,
    uint64_t *value)
{
    CBS sub;
    const unsigned char *body;
    size_t len = 0;

    body = ossl_quic_wire_decode_transport_param_bytes(pkt, id, &len);
    if (body == NULL)
        return 0;
    CBS_init(&sub, body, len);
    if (!CBS_get_quic_vlint(&sub, value))
        return 0;

    if (CBS_len(&sub) > 0)
        return 0;

    return 1;
}

int ossl_quic_wire_decode_transport_param_cid(CBS *pkt,
    uint64_t *id,
    QUIC_CONN_ID *cid)
{
    const unsigned char *body;
    size_t len = 0;

    body = ossl_quic_wire_decode_transport_param_bytes(pkt, id, &len);
    if (body == NULL || len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    cid->id_len = (unsigned char)len;
    memcpy(cid->id, body, cid->id_len);
    return 1;
}

int ossl_quic_wire_decode_transport_param_preferred_addr(CBS *pkt,
    QUIC_PREFERRED_ADDR *p)
{
    const unsigned char *body;
    uint64_t id;
    size_t len = 0;
    CBS pkt2;
    uint16_t ipv4_port, ipv6_port;
    uint8_t cidl;

    body = ossl_quic_wire_decode_transport_param_bytes(pkt, &id, &len);
    if (body == NULL
        || len < QUIC_MIN_ENCODED_PREFERRED_ADDR_LEN
        || len > QUIC_MAX_ENCODED_PREFERRED_ADDR_LEN
        || id != QUIC_TPARAM_PREFERRED_ADDR)
        return 0;

    CBS_init(&pkt2, body, len);

    if (!CBS_copy_bytes(&pkt2, p->ipv4, sizeof(p->ipv4))
        || !CBS_get_u16(&pkt2, &ipv4_port)
        || !CBS_copy_bytes(&pkt2, p->ipv6, sizeof(p->ipv6))
        || !CBS_get_u16(&pkt2, &ipv6_port)
        || !CBS_get_u8(&pkt2, &cidl)
        || cidl > QUIC_MAX_CONN_ID_LEN
        || !CBS_copy_bytes(&pkt2, p->cid.id, cidl)
        || !CBS_copy_bytes(&pkt2, p->stateless_reset.token,
            sizeof(p->stateless_reset.token)))
        return 0;

    p->ipv4_port = (uint16_t)ipv4_port;
    p->ipv6_port = (uint16_t)ipv6_port;
    p->cid.id_len = (unsigned char)cidl;
    return 1;
}

const char *
ossl_quic_frame_type_to_string(uint64_t frame_type)
{
    switch (frame_type) {
#define X(name)                       \
    case OSSL_QUIC_FRAME_TYPE_##name: \
        return #name;
        X(PADDING)
        X(PING)
        X(ACK_WITHOUT_ECN)
        X(ACK_WITH_ECN)
        X(RESET_STREAM)
        X(STOP_SENDING)
        X(CRYPTO)
        X(NEW_TOKEN)
        X(MAX_DATA)
        X(MAX_STREAM_DATA)
        X(MAX_STREAMS_BIDI)
        X(MAX_STREAMS_UNI)
        X(DATA_BLOCKED)
        X(STREAM_DATA_BLOCKED)
        X(STREAMS_BLOCKED_BIDI)
        X(STREAMS_BLOCKED_UNI)
        X(NEW_CONN_ID)
        X(RETIRE_CONN_ID)
        X(PATH_CHALLENGE)
        X(PATH_RESPONSE)
        X(CONN_CLOSE_TRANSPORT)
        X(CONN_CLOSE_APP)
        X(HANDSHAKE_DONE)
        X(STREAM)
        X(STREAM_FIN)
        X(STREAM_LEN)
        X(STREAM_LEN_FIN)
        X(STREAM_OFF)
        X(STREAM_OFF_FIN)
        X(STREAM_OFF_LEN)
        X(STREAM_OFF_LEN_FIN)
#undef X
    default:
        return NULL;
    }
}

const char *ossl_quic_err_to_string(uint64_t error_code)
{
    switch (error_code) {
#define X(name)                \
    case OSSL_QUIC_ERR_##name: \
        return #name;
        X(NO_ERROR)
        X(INTERNAL_ERROR)
        X(CONNECTION_REFUSED)
        X(FLOW_CONTROL_ERROR)
        X(STREAM_LIMIT_ERROR)
        X(STREAM_STATE_ERROR)
        X(FINAL_SIZE_ERROR)
        X(FRAME_ENCODING_ERROR)
        X(TRANSPORT_PARAMETER_ERROR)
        X(CONNECTION_ID_LIMIT_ERROR)
        X(PROTOCOL_VIOLATION)
        X(INVALID_TOKEN)
        X(APPLICATION_ERROR)
        X(CRYPTO_BUFFER_EXCEEDED)
        X(KEY_UPDATE_ERROR)
        X(AEAD_LIMIT_REACHED)
        X(NO_VIABLE_PATH)
#undef X
    default:
        return NULL;
    }
}
