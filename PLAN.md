# AmiTLS13 Implementation Plan

## Objective

Build a compact AmigaOS 1.3 TLS/HTTPS wrapper library named `amitls13.library`. It should let new OS1.3 programs use HTTPS without depending on AmiSSL v5/v6, OpenSSL 3.x/4.x, clib2, or AmigaOS 3 APIs.

AmiTLS13 is not a full AmiSSL replacement. It exposes a small stable client API for HTTPS and TLS streams.

## Fixed Direction

- Functionality over API breadth.
- OS1.3 compatibility first.
- 68020+ target for TLS builds.
- Use `bsdsocket.library` for network access.
- Use BearSSL as TLS backend.
- Keep stack requirements explicit: minimum 65000 bytes, recommended 131072 bytes.

## Phase 1: Static HTTPS Proof of Concept

Status: working PoC.

Completed:

1. BearSSL source imported under `third_party/bearssl/`.
2. Static `libamitls13.a` build works with bebbo/amiga-gcc and `-mcrt=nix13`.
3. `tools/amitls13_get` exists as reference test program.
4. HTTP and HTTPS URL parsing implemented for the PoC scope.
5. `bsdsocket.library` transport adapter implemented.
6. bsdsocket calls routed through 68k assembly stubs to preserve registers around library calls.
7. Insecure X.509 acceptor implemented for first transport validation.
8. `https://example.com` can be fetched on the Amiga test system with sufficient stack.
9. Request and receive buffers in `AmiTLS13_HTTPGet()` are allocated with `AllocMem()` to reduce stack pressure.
10. Trace and debug builds are optional through `make TRACE=1` and `make TRACE=1 DEBUG=1`.

Reference test:

```text
stack 131072
amitls13_get https://example.com
```

Expected result:

- TCP connect succeeds.
- TLS handshake succeeds.
- HTTP response is received.
- Output file is written.
- Program exits without crash when started with sufficient stack.

## Phase 2: Public Wrapper API

Status: initial API exists and builds both statically and through `amitls13.library` vectors.

Initial API:

```c
struct AmiTLS13Context;

LONG AmiTLS13_Init(void);
void AmiTLS13_Exit(void);
void AmiTLS13_SetDebugOutput(BPTR fh);

struct AmiTLS13Context *AmiTLS13_Connect(const char *host, UWORD port, ULONG flags);
LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len);
LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen);
void AmiTLS13_Close(struct AmiTLS13Context *ctx);
LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx);
LONG AmiTLS13_SocketErrno(void);

LONG AmiTLS13_HTTPGet(const char *url, const char *outfile, ULONG flags);
```

Required cleanup before declaring the API stable:

- Per-context TLS callback state is implemented.
- `AmiTLS13_Init()`/`AmiTLS13_Exit()` now reference-count the shared `bsdsocket.library` handle.
- Stable public error codes are defined in `include/amitls13.h`.
- Caller lifecycle rules are documented in `sdk/README.md` and `README.md`.

## Phase 3: `amitls13.library`

Status: initial library file builds and has passed the first Amiga-side HTTPS smoke test.

Completed:

1. `build/amitls13.library` is generated.
2. Classic Resident/AutoInit structure added.
3. Library metadata is set during init: name, version, revision and id string.
4. Library jump table contains standard vectors plus AmiTLS13 API vectors.
5. Assembly entry stubs translate Amiga register arguments to C stack arguments.
6. `tools/amitls13_get_lib` opens `amitls13.library` through `OpenLibrary()` and calls the API through client stubs.
7. `dos.library` is opened during library init so TLS/HTTP file and entropy paths have a valid DOSBase.
8. `tools/amitls13_openclose` provides repeated library open/close testing without network access.
9. `tools/amitls13_repeat_get_lib` validates repeated HTTPS calls through the shared library.
10. `sdk/` contains public headers, client stubs and a minimal consumer example.

Reference library test:

```text
copy amitls13.library LIBS:
stack 131072
amitls13_get_lib https://example.com
```

Next Phase 3 checks:

- Verify `version LIBS:amitls13.library` on OS1.3.
- Run `amitls13_example_get https://example.com` to validate the exported SDK example.
- Confirm no crash after `CloseLibrary()` and DOS `Exit()`.

## Phase 4: Certificates

Status: public-key pinning implemented and builds. Amiga-side validation is next.

Implemented:

1. `AMITLS13F_PIN_PUBKEY_SHA256` request flag.
2. `AmiTLS13_SetPublicKeyPinSHA256(pin, 32)` to set a process-global pin.
3. `AmiTLS13_SetPublicKeyPinSHA256(0, 0)` to clear the pin.
4. `AmiTLS13_GetLastPeerPublicKeySHA256(out, 32)` to retrieve the last successful TLS peer key hash.
5. `amitls13_pin_print_lib` to print the endpoint hash on the Amiga.
6. `amitls13_pin_fail_lib` to verify that a deliberately wrong pin is rejected.

Add certificate handling after transport stability:

- Keep `AMITLS13F_INSECURE` for development and retro systems.
- Add optional certificate pinning first, because it is small and deterministic.
- Add CA bundle support later if memory and file handling remain acceptable.
- Candidate locations:
  - `AmiTLS13:certs/`
  - `PROGDIR:certs/`

Verification flags:

- `AMITLS13F_INSECURE`
- `AMITLS13F_VERIFY_CERT`
- `AMITLS13F_VERIFY_HOSTNAME`

Reference pinning tests:

```text
copy amitls13.library LIBS:
stack 131072
amitls13_pin_print_lib https://example.com
amitls13_pin_fail_lib https://example.com
```

## Phase 5: Integration Targets

After the command-line and library PoCs are repeatably stable:

1. Weather13 HTTPS access
2. ISSTracker HTTPS fallback APIs
3. AMusicBrainz HTTPS support
4. MajaRadio HTTPS support

## Design Constraints

- Prefer stability and small memory footprint over OpenSSL API breadth.
- Keep OS1.3 compatibility visible in every module.
- Avoid heavy stdio in final library code.
- Prefer Fast/Slow RAM where practical; avoid unnecessary Chip RAM use.
- TLS 1.2 first. TLS 1.3 can follow when the TLS backend is ready.
