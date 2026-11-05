# packet-to-cbs — PACKET → CBS feasibility experiment

## Goal

Replace all uses of the internal PACKET API with CBS calls, **as an
experiment**.  The deliverable is a feel for how hard the conversion is
(and a list of the friction points), not a PR.

## Base

This workspace sits on the tip of bob-beck's PR
[openssl/openssl#33377](https://github.com/openssl/openssl/pull/33377)
— branch `x509-view` on the `bob-beck` remote
(`x509-view@bob-beck`, tip `8e67f6be` "Parse the view of an X509's
DER" at setup time).  That PR imports the BoringSSL/LibreSSL CBS
reader:

- `include/internal/bytestring.h`, `crypto/bytestring.c`
- internal test `test/bytestring_internal_test.c`
  (`03-test_internal_bytestring.t`)

CBB (the builder half of bytestring.h) is **not** imported — Bob
explicitly left it out of this PR; expect it in his larger stack
([openssl/openssl#33376](https://github.com/openssl/openssl/pull/33376)).

## Landscape

- PACKET: `include/internal/packet.h`.  ~61 files under `ssl/`,
  `crypto/` and `include/` use `PACKET_` — mostly TLS/QUIC record and
  handshake parsing in `ssl/`.
- CBS reader surface (see bytestring.h for the full list): `CBS_init`,
  `CBS_len`, `CBS_data`, `CBS_offset`, `CBS_skip`, `CBS_get_u8/16/24/
  32/48/64`, `CBS_get_*_length_prefixed`, `CBS_get_bytes`,
  `CBS_peek_u8`, the `CBS_get_asn1*` family, `CBS_stow`, `CBS_dup`,
  `CBS_mem_equal`, `CBS_contains_zero_byte`.

## Method sketch

- Work file by file; every commit must build and pass tests on its
  own (usual commit discipline applies).
- PACKET and CBS are near-isomorphic (cursor + remaining length), so
  most call sites should be mechanical.  The interesting output is the
  **gap list**: PACKET helpers or idioms with no CBS equivalent (peek
  patterns, sub-packet handling, `PACKET_buf_init`, ...).  Record each
  gap as it appears — that list is part of the result.
- Write/build-side PACKET use (no CBB available yet) stays PACKET
  unless importing CBB becomes part of the experiment — flag it before
  going there.

## Boundaries

- Local experiment only: do not push to any remote.
- Build and test per the tree-level `AGENTS.md` chain (fresh build
  tree at `.cache/build-Pi` — this workspace has none yet).
