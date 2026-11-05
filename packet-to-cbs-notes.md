# PACKET → CBS experiment notes

Goal: replace read-side PACKET uses with CBS (from bob-beck's x509-view PR
base, 8e67f6be), file by file, one commit per file, recording friction.

Out of scope: WPACKET (write side; no CBB in this base), packet.h/packet.c
themselves until all users are gone, packettest.c / wpackettest.c until the
endgame.

## Translation table

| PACKET | CBS | Notes |
|---|---|---|
| `PACKET pkt` | `CBS cbs` | |
| `PACKET_buf_init(&p, buf, len)` | `CBS_init(&c, buf, len)` | |
| `PACKET_null_init(&p)` | `CBS_init(&c, NULL, 0)` | |
| `PACKET_remaining(&p)` | `CBS_len(&c)` | |
| `PACKET_data(&p)` | `CBS_data(&c)` | both return current position |
| `PACKET_end(&p)` | `CBS_data(&c) + CBS_len(&c)` | idiom, no helper |
| `PACKET_msg_start(&p)` | `CBS_data(&c) - CBS_offset(&c)` | idiom, top-level CBS only — sub-CBS trees lose it, see monster findings |
| `PACKET_forward(&p, n)` | `CBS_skip(&c, n)` | |
| `PACKET_get_1(&p, &u)` | `CBS_get_u8(&c, &u)` | u: unsigned int → uint8_t |
| `PACKET_peek_1(&p, &u)` | `CBS_peek_u8(&c, &u)` | |
| `PACKET_get_net_2(&p, &u)` | `CBS_get_u16(&c, &u)` | u: unsigned int → uint16_t |
| `PACKET_peek_net_2/3/4/6/8` | *(none)* | **GAP**: only `CBS_peek_u8` among numeric peeks; use `CBS_dup` + get |
| `PACKET_get_net_3(&p, &u)` | `CBS_get_u24(&c, &u)` | u: unsigned long → uint32_t |
| `PACKET_get_net_4(&p, &u)` | `CBS_get_u32(&c, &u)` | u: unsigned long → uint32_t |
| `PACKET_get_net_6/8(&p, &u)` | `CBS_get_u48/64(&c, &u)` | |
| `PACKET_get_net_{2,3,4}_len(&p, &s)` | `CBS_get_u{16,24,32}` into fixed type, assign | size_t targets widen fine |
| `PACKET_get_bytes(&p, &sub, n)` | `CBS_get_bytes(&c, &sub, n)` | |
| `PACKET_peek_bytes(&p, &ptr, n)` | *(none)* | **GAP**: peek-into-pointer; use `CBS_dup` + `CBS_get_bytes` + `CBS_data` |
| `PACKET_copy_bytes(&p, buf, n)` | `CBS_copy_bytes(&c, buf, n)` | imported from BoringSSL by this experiment |
| `PACKET_peek_copy_bytes` | *(none)* | **GAP**: same, on a dup |
| `PACKET_copy_all` | *(none)* | **GAP**: same |
| `PACKET_memdup(&p, &d, &l)` | `CBS_stow(&c, &d, &l)` | exact match; both allocate |
| `PACKET_strndup` | `CBS_strdup` | imported from BoringSSL by this experiment |
| `PACKET_equal(&p, d, n)` | `CBS_mem_equal(&c, d, n)` | |
| `PACKET_contains_zero_byte` | `CBS_contains_zero_byte` | |
| `PACKET_get_sub_packet/peek_sub_packet` | `CBS_get_bytes` (+dup for peek) | |
| `PACKET_get_length_prefixed_1/2/3` | `CBS_get_u8/16/24_length_prefixed` | exact match |
| `PACKET_as_length_prefixed_1/2` | *(none)* | **GAP**: get_length_prefixed on a dup, then require `CBS_len == 0` |
| `PACKET_get_4/peek_4` (LE!) | *(none)* | **GAP**: no little-endian getters in CBS. No production users — only packettest. |

## Systematic frictions

- **Type widths.** PACKET reads into `unsigned int` / `unsigned long`;
  CBS into `uint8_t` / `uint16_t` / `uint32_t` / `uint64_t`. Receiving
  variables must be retyped (or bounce through a temp), which ripples
  into format strings and comparisons.
- **Peek patterns.** CBS has only `CBS_peek_u8`. Every other peek is
  `CBS_dup` + get + use `CBS_data`/`CBS_len` of the dup.
- **Copy-to-buffer.** PACKET has a copy_bytes family; Bob's CBS import
  didn't (zero-copy ethos; BoringSSL has `CBS_copy_bytes()`, imported
  by this experiment).  Where only a look is needed, memcpy from a
  sub-CBS's `CBS_data`.
- **`PACKET_end` / `PACKET_msg_start`**: pointer arithmetic idioms, no
  helpers. Used with d2i_ calls (`PACKET_end` for "did d2i consume
  exactly the packet").

## Progress

- [x] build tree configured + baseline build
- [x] crypto/ warm-ups (LMS, ML-DSA, SLH-DSA, DER helpers)
- [x] bytestring: `CBS_copy_bytes()` imported from BoringSSL
- [x] ssl/record (record/alert header parsing)
- [x] ssl/quic (+ new `internal/bytestring_quic.h`)
- [x] ssl/statem + ssl/ech + ssl top level (one forced monster commit)
- [x] test files + QUIC fuzz harnesses
- [x] endgame: packet.h read-side removal, packettest.c deleted

Per-phase findings follow; the full test suite passes at the tip of
the stack.

## Gap list (final)

True gaps (no CBS equivalent, needed a workaround or an import):

- `PACKET_msg_start()` — top-buffer identity; carried explicitly in
  `CLIENTHELLO_MSG.msg_start`.
- `PACKET_memdup()` — exact match for this import's `CBS_stow()`
  (frees dest, empty->NULL, memdup).  No gap.
- `PACKET_strndup()` — resolved by importing BoringSSL's
  `CBS_strdup()`.
- `PACKET_copy_all()` — file-local `cbs_copy_all()` in statem_srvr.c.
- `PACKET_copy_bytes()` — resolved by importing BoringSSL's
  `CBS_copy_bytes()`.
- Peeks other than u8 — `CBS_dup` + get idiom.
- `PACKET_as_length_prefixed_*` — `CBS_get_u*_length_prefixed` +
  explicit `CBS_len() == 0` check.
- Little-endian `PACKET_get_4/peek_4` — no CBS equivalent; no
  production users, dropped with packettest.c.
- QUIC vlint readers — new `internal/bytestring_quic.h`.

## Findings so far (crypto/ warm-up)

Done: LMS (3 files), ML-DSA decode (1 file), SLH-DSA family (6 files),
DER helpers (asn1_dsa.c + header).

- `PACKET_get_bytes(&pkt, &ptr, n)` → `CBS_get_bytes(&cbs, &sub, n)` +
  `CBS_data(&sub)`.  Where the pointer feeds straight into the next call,
  inlining `CBS_data(&sub)` at the call site reads *better* than the old
  throwaway pointer variable (slh_fors.c, slh_wots.c, slh_xmss.c).
- `CBS_init()` returning void keeps biting: every `PACKET_buf_init()`
  inside an `&&`/`||` chain needs the chain restructured (statement +
  shortened chain).  The checks were dead anyway (len > SIZE_MAX/2
  paranoia only).
- Typed getters are narrower: `PACKET_get_1/2/3/4` wrote into
  `unsigned int`/`unsigned long`; `CBS_get_u8/16/32/64` want the exact
  fixed-width type.  Locals must narrow (asn1_dsa.c).
- `PACKET_copy_bytes()` had no CBS equivalent in this import: wrote a
  6-line file-local helper `cbs_copy_bytes()` in ml_dsa_encoders.c,
  replaced by the verbatim import of BoringSSL's `CBS_copy_bytes()`
  when the record layer needed the same primitive.
- Struct copy for peeking (`tmppkt = contpkt`) works unchanged for CBS.

## QUIC family (done)

- QUIC vlint helpers (packet_quic.h) are PACKET-specific inline
  functions poking `pkt->curr` directly; no CBS counterpart exists
  anywhere.  Introduced `internal/bytestring_quic.h` with CBS
  analogs (get/peek/skip vlint, quic length-prefixed).  Write-side
  WPACKET quic helpers stay in packet_quic.h.
- `PACKET_end()` has no `CBS_end()`; two users switched to
  `CBS_data(p) + CBS_len(p)`.
- `PACKET_as_length_prefixed_2()` (quictestlib.c): equivalent is
  `CBS_get_u16_length_prefixed()` + explicit `CBS_len() == 0`
  trailing check.
- Tests wrapped `PACKET_buf_init()` in TEST_true()/TEST_int_eq();
  with infallible `CBS_init()` those assertions simply vanish.
- Lesson learned (jj): `jj describe` does not start a new change —
  run `jj new` before starting the next unit's edits, or split
  afterwards.

## Record layer (done)

- Build plumbing: internal CBS_* symbols are not exported from
  libcrypto.so (PACKET never had this problem — it was ~all static
  inline in packet.h), so ssl/build.info gains ../crypto/bytestring.c
  in SHARED_SOURCE[../libssl], same trick packet.c already used.
- Otherwise mechanical: header-field reads become CBS_get_u8/16/24
  with narrowed temporaries.

## TLS state machine + ECH monster (done, full suite passes)

One commit was forced: PACKET sits in struct members
(RAW_EXTENSION.data, CLIENTHELLO_MSG fields) and ~60 function
signatures across ssl_local.h/statem_local.h.

- **CBS wins**: CBS_offset() replaces PACKET_data()-minus-buffer-start
  arithmetic (ech_helper.c); CBS_peek_u8() replaced a
  get-bytes-then-index idiom; skip-only get_bytes calls became
  CBS_skip(); the sub-CBS + inline CBS_data() pattern reads better
  than PACKET's throwaway pointers (ech_reconstitute_inner).
- **True semantic gap**: PACKET_msg_start() tracks the top-of-tree
  buffer; CBS sub-buffers don't.  First fix attempt
  (s->init_buf->data) was WRONG for ECH's reconstituted inner CH
  (found by test_ech binder verification).  Final: new
  CLIENTHELLO_MSG.msg_start field, set from
  CBS_data(pkt) - CBS_offset(pkt) at process entry.
- **Gotcha worth a warning**: narrowing getter targets bit me once —
  `context` in tls_process_server_hello is an SSL_EXT_* bitmask,
  not a u8 target; truncating it broke all ServerHello validation.
  The compiler can't catch a correctly-typed but semantically-wrong
  narrowing.
- PACKET_memdup/PACKET_strndup free destination first: this import's
  CBS_stow() turns out to be an EXACT match for PACKET_memdup (frees
  dest, empty->NULL, memdup) — initially misread, so a redundant
  ossl_cbs_memdup gap filler was added and later removed again.
  PACKET_strndup matched BoringSSL's CBS_strdup(), which Bob had not
  imported; imported verbatim by this experiment (see verdict 5).
- PACKET_copy_all(): file-local cbs_copy_all() in statem_srvr.c.
- PACKET_as_length_prefixed_*: sed-able transform to
  get_*_length_prefixed + CBS_len()==0 check.
- tls13secretstest compiles ../ssl/d1_transcript.c directly:
  needed ../crypto/bytestring.c added in test/build.info.

## Final phase (done, full suite passes)

- Test files converted mechanically (same idioms as statem).  Two
  structural findings:
  - PACKET was ~all static inline in packet.h; CBS functions are real
    symbols and internal ones aren't exported from libcrypto.so, so
    test binaries linking the shared libs compile ../crypto/bytestring.c
    in directly.  (Same trick the record-layer commit used for
    libssl's SHARED_SOURCE.)
  - The "read a length, then skip that many bytes" idiom
    (PACKET_get_net_2 + PACKET_forward) appears all over the test
    corpus; with CBS it needs a typed temporary plus CBS_skip().
- Fuzz harnesses (quic-lcidm/rcidm/srtm) converted the same way.
- Final removal: packet.h is now WPACKET-only, packet_quic.h is
  write-side only, test/packettest.c + recipe deleted.  Full test
  suite passes.

## Verdict sketch

Mechanical for ~90% of sites; the interesting 10%:

1. PACKET_msg_start() has no CBS analog — top-buffer identity must be
   carried explicitly (CLIENTHELLO_MSG.msg_start).
2. PACKET_memdup/strndup semantics initially looked like gaps; in
   fact PACKET_memdup ≡ this import's CBS_stow() (exact match), and
   PACKET_strndup ≡ BoringSSL's CBS_strdup() (see 5).
3. PACKET_as_length_prefixed_* → get_*_length_prefixed + explicit
   CBS_len()==0 check: fine, arguably more explicit.
4. Getter type narrowing (unsigned int/long → uint8_t/uint16_t/
   uint32_t) is the bulk of the diff and the main review risk —
   caught once by tests, not by the compiler, when a variable was
   also used as a bitmask.
5. Bob's import omitted BoringSSL's CBS_strdup() (frees dest,
   NUL-terminated, OPENSSL_strndup semantics — exactly PACKET_strndup);
   imported verbatim, with a "" fallback for empty input because
   OpenSSL's CRYPTO_strndup() rejects NULL data where BoringSSL's does
   not.
6. Same story for BoringSSL's CBS_copy_bytes(), imported verbatim.
   First needed by the ML-DSA decoders (initially papered over with a
   file-local CBS_get_bytes()+memcpy wrapper) and by the DTLS
   record-header sequence-number parsing; thereafter the 1:1
   replacement for every PACKET_copy_bytes() site.
7. CBS_offset() and CBS_skip() are genuine wins over the PACKET
   pointer-arithmetic idioms.
