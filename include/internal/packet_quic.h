/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PACKET_QUIC_H
#define OSSL_INTERNAL_PACKET_QUIC_H
#pragma once

#include "internal/packet.h"
#include "internal/quic_vlint.h"

#ifndef OPENSSL_NO_QUIC

/*
 * Starts a QUIC sub-packet headed by a QUIC variable-length integer. A 4-byte
 * representation is used.
 */
__owur int WPACKET_start_quic_sub_packet(WPACKET *pkt);

/*
 * Starts a QUIC sub-packet headed by a QUIC variable-length integer. max_len
 * specifies the upper bound for the sub-packet size at the time the sub-packet
 * is closed, which determines the encoding size for the variable-length
 * integer header. max_len can be a precise figure or a worst-case bound
 * if a precise figure is not available.
 */
__owur int WPACKET_start_quic_sub_packet_bound(WPACKET *pkt, size_t max_len);

/*
 * Allocates a QUIC sub-packet with exactly len bytes of payload, headed by a
 * QUIC variable-length integer. The pointer to the payload buffer is output and
 * must be filled by the caller. This function assures optimal selection of
 * variable-length integer encoding length.
 */
__owur int WPACKET_quic_sub_allocate_bytes(WPACKET *pkt, size_t len,
    unsigned char **bytes);

/*
 * Write a QUIC variable-length integer to the packet.
 */
__owur int WPACKET_quic_write_vlint(WPACKET *pkt, uint64_t v);

#endif /* OPENSSL_NO_QUIC */
#endif /* OSSL_INTERNAL_PACKET_QUIC_H */
