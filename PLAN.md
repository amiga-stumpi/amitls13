# AmiTLS13 Proof-of-Concept Plan

## Objective

Build a compact AmigaOS 1.3 TLS/HTTPS wrapper library named `amitls13.library`. It should let new OS1.3 programs use HTTPS without depending on AmiSSL v5/v6, OpenSSL 3.x/4.x, clib2, or AmigaOS 3 APIs.

## Scope

AmiTLS13 is not intended to be a full AmiSSL replacement. It will expose a small stable client API for HTTPS and TLS streams.

## Phase 1: Static HTTPS Proof of Concept

1. Import BearSSL source into `third_party/bearssl/`.
2. Build only the needed BearSSL client pieces. Current PoC still builds a broad BearSSL subset; object pruning is a follow-up.
3. Implement a bsdsocket-backed transport adapter.
4. Implement minimal URL parsing for `https://host[:port]/path`.
5. Build `tools/amitls13_get` as a static test program.
6. First test mode uses BearSSLs full client profile with an insecure X.509 acceptor to validate handshake and data flow.
7. Then enable CA/hostname verification.

Expected test:

```text
amitls13_get https://example.com/
```

Expected output milestones:

- DNS ok
- TCP connected
- TLS handshake ok
- HTTP status received
- bytes received

## Phase 2: Public Wrapper API

Initial API draft:

```c
struct AmiTLS13Context;

LONG AmiTLS13_Init(void);
void AmiTLS13_Exit(void);

struct AmiTLS13Context *AmiTLS13_Connect(const char *host, UWORD port, ULONG flags);
LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len);
LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen);
void AmiTLS13_Close(struct AmiTLS13Context *ctx);
LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx);

LONG AmiTLS13_HTTPGet(const char *url, const char *outfile, ULONG flags);
```

## Phase 3: `amitls13.library`

Convert the proven static implementation into a classic Amiga shared library:

- library file: `amitls13.library`
- install target: `LIBS:`
- no OS2+/OS3-only APIs
- use `AllocMem`/`FreeMem`, not `AllocVec`
- no `ReadArgs`
- no `CreateNewProc`
- per-connection contexts
- usable by multiple applications

## Phase 4: Certificates

Add CA handling:

- `AmiTLS13:certs/`
- optionally `PROGDIR:certs/` fallback for local application bundles
- verification flags:
  - `AMITLS13F_INSECURE`
  - `AMITLS13F_VERIFY_CERT`
  - `AMITLS13F_VERIFY_HOSTNAME`

## Phase 5: Integration Targets

After the command-line PoC works:

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
