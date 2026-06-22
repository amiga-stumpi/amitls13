# AmiTLS13 Optimization Plan

This plan tracks the work to reduce `amitls13.library` size, stack pressure and HTTPS latency while keeping the current working API stable.

## Goals

- Keep AmigaOS 1.3 and `-mcrt=nix13` compatibility.
- Keep the public `amitls13.library` API stable for current consumers.
- Preserve the working HTTPS path before removing or trimming code.
- Reduce release binary size and remove diagnostic overhead from non-debug builds.
- Reduce per-request latency for clients such as ISSTracker.
- Lower practical stack pressure where possible, without hiding the documented large-stack requirement for TLS handshakes.

## Phase 1: Release Hygiene

- Ensure release builds compile out local debug and trace callsites completely.
- Keep `TRACE=1` and `DEBUG=1` builds available for Amiga-side diagnosis.
- Verify release, trace and debug builds still compile.
- Measure `amitls13.library`, `libamitls13.a` and tool sizes after each change.

## Phase 2: BearSSL Source Trim

- Replace the broad BearSSL source import list with an explicit allow-list of modules required by the enabled client suites.
- Keep only client-side TLS, X.509 parser support, SHA-256, HMAC, AES-128/GCM, RSA verification and P-256 ECDHE support that is actually used.
- Exclude server code, unused symmetric algorithms, unused hash functions and unused integer backends.
- Validate with `https://example.com` and `https://api.wheretheiss.at`.

## Phase 3: Cipher Suite Policy

- Prefer the smallest suite set that still works with target APIs.
- Keep ECDHE-RSA AES128 suites for modern HTTPS endpoints.
- Retain RSA fallback only if target APIs still require it.
- Document the exact enabled TLS 1.2 suites.

## Phase 4: Runtime Memory and Stack Audit

- Audit BearSSL callback and HTTP helper paths for avoidable stack arrays.
- Keep context ownership simple: one connection context owns TLS engine, I/O buffer and X.509 state.
- Add notes for caller programs that need a larger stack before using HTTPS.

## Phase 5: Memory Layout and Stack Pressure

- Keep the large TLS connection context, BearSSL engine, X.509 state and TLS I/O buffer in one `AllocMem()` owned context.
- Allocate HTTP URL parse state, request buffer, receive buffer and TLS SNI host copy with `AllocMem()` instead of keeping them on the caller stack.
- Use `MEMF_PUBLIC` by default for OS1.3-safe allocations. Optional memory preferences can be selected at build time through `AMITLS13_MEM_FLAGS` and `AMITLS13_MEM_CLEAR_FLAGS`, but the default must not require Fast RAM.
- Rebuild and validate the HTTPS smoke tests after this layout change.

## Phase 6: Latency Optimization

- Avoid extra HTTPS calls in applications; batch data when possible.
- Reuse DNS results only if this can be done without breaking stack compatibility.
- Tune socket read/write waiting loops conservatively for TheWire13 and other bsdsocket stacks.
- Keep optional HTTPS features in consumers so HTTP fallback remains fast.

Current latency tuning stage:

- TLS socket read/write wait quantum reduced from 250 ms to 50 ms.
- TLS socket read/write retry budget changed from 80 attempts to 200 attempts.
- The total worst-case I/O wait window is therefore about 10 seconds instead of about 20 seconds, while allowing faster wake-up when data arrives.
- HTTP receive buffer remains at the validated 1024-byte size for the stable 1.0 baseline.
- These values are compile-time defaults: `AMITLS13_TLS_WAIT_US`, `AMITLS13_TLS_IO_TRIES`, `AMITLS13_HTTP_REQ_BUF`, `AMITLS13_HTTP_RECV_BUF`.

## Phase 7: HTTPGet Simplification

Status: postponed. The grouped HTTP state/body-only experiment regressed the Amiga-side HTTPS smoke test, so the stable 1.0 baseline intentionally keeps the older proven HTTPGet path.

Future work, if revisited:

- Keep `AmiTLS13_HTTPGet()` as the small high-level convenience path for current applications.
- Only change one behaviour at a time and validate on the Amiga after each change.
- Avoid changing returned byte-count semantics unless all consumers are updated together.
- Keep the current full-response output path as the reference behaviour for 1.0.

## Phase 8: Verification

For every optimization step:

- Build release with `make clean && make`.
- Build trace/debug when diagnostic code changes.
- Run Amiga-side smoke tests with `stack 65000` and again with `stack 131072` when changing TLS internals:
  - `amitls13_get_lib https://example.com`
  - `amitls13_repeat_get_lib https://example.com 3`
  - `amitls13_pin_print_lib https://example.com`
- Re-test an application integration path, currently ISSTracker.

## Current Work Item

Phase 1 is complete for local AmiTLS13 diagnostics: release builds compile out local debug and trace callsites.

Phase 2 has started: `br_ssl_client_init_full()` was replaced with a minimal TLS 1.2 client setup and the Makefile now uses an explicit BearSSL source allow-list. Initial release build results:

- `amitls13.library`: about 246 KB before trimming, about 85 KB after trimming.
- `libamitls13.a`: about 299 KB before trimming, about 97 KB after trimming.
- `amitls13_get`: about 112 KB before minimal TLS init, about 87 KB after.

The first Amiga validation succeeded at `stack 65000` for:

- `amitls13_get_lib https://example.com`
- `amitls13_repeat_get_lib https://example.com 3`
- `amitls13_pin_print_lib https://example.com`

A second trim stage is now active: CBC and static RSA suites were removed, leaving `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` as the only enabled suite. CBC record code and AES-CBC support were removed from the BearSSL source allow-list. Current release build results:

- `amitls13.library`: about 79 KB.
- `libamitls13.a`: about 90 KB.
- `amitls13_get`: about 82 KB.

The GCM-only stage was validated on the Amiga at `stack 65000`.

The P-256/SHA256-only stage was validated on the Amiga at `stack 65000` and is the current optimized baseline. TLS is limited to `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; SHA384, P-384, P-521 and Curve25519 support were removed from the release build allow-list. Current release build results:

- `amitls13.library`: about 58 KB.
- `libamitls13.a`: about 66 KB.
- `amitls13_get`: about 60 KB.

Next optimization work should be driven by target API compatibility and real application timing, not by blind size reduction.

Latency tuning is validated on the Amiga at `stack 65000` with:

- `amitls13_get_lib https://example.com`
- `amitls13_repeat_get_lib https://example.com 3`
- `amitls13_pin_print_lib https://example.com`

Observed result: all tests pass and HTTPS GET appears faster. The active latency baseline keeps the same TLS profile and changes only socket wait granularity plus HTTP receive buffer sizing.

Phase 5 memory layout work is implemented and Amiga-side validated at `stack 65000`. The TLS connection context and I/O buffer remain allocated off the caller stack. The stable 1.0 baseline keeps the proven HTTPGet request/receive buffer layout.

Phase 7 HTTPGet simplification was tested and reverted after Amiga-side validation failed with `GET failed: -7`. It should remain postponed until there is a narrower, separately validated change.
