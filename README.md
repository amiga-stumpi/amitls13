# AmiTLS13

AmiTLS13 is a compact TLS/HTTPS wrapper for AmigaOS 1.3 programs.

The goal is not to port the full AmiSSL/OpenSSL API. AmiTLS13 provides a small client-side API that new Kickstart 1.3 applications can use to access HTTPS resources through a bsdsocket-compatible stack.

## Current Status

Phase 1 is a working BearSSL-backed HTTPS proof of concept. The static reference tool `amitls13_get` can fetch `https://example.com` on the Amiga test system with a sufficiently large stack.

Phase 2/3 are now at an initial library-validation stage: the same implementation builds as a classic Amiga shared library file named `amitls13.library`. `amitls13_get_lib` opens `amitls13.library` with `OpenLibrary()` and calls the API through library-vector stubs instead of linking the TLS implementation directly.

The current TLS mode is intentionally insecure: it accepts the server certificate chain without CA or hostname validation. This validates transport, TLS handshake, encrypted I/O and HTTP data flow first. Certificate verification and hostname validation are later phases.

## Requirements

- AmigaOS 1.3 compatible runtime (`-mcrt=nix13`).
- 68020+ CPU target for the current build.
- A working `bsdsocket.library` compatible stack.
- Sufficient process stack for TLS.

Recommended stack:

```text
minimum:     65000 bytes
recommended: 131072 bytes
```

TLS/BearSSL uses deep call chains during handshake, X.509 parsing and RSA verification. Large persistent buffers are allocated with `AllocMem()`, but stack size still matters.

## Build

Release-style build without trace output:

```sh
make clean
make
```

Generated artifacts:

```text
build/libamitls13.a       static PoC library
build/amitls13.library    Amiga shared library for LIBS:
build/amitls13_get        statically linked reference tool
build/amitls13_get_lib    OpenLibrary-based HTTPS reference tool
build/amitls13_openclose  repeated OpenLibrary/CloseLibrary test tool
build/amitls13_repeat_get_lib repeated HTTPS test through amitls13.library
build/amitls13_example_get    SDK example using only sdk/ files
```

Trace build for Amiga-side diagnosis:

```sh
make clean
make TRACE=1
```

Trace plus debug logging:

```sh
make clean
make TRACE=1 DEBUG=1
```

## Static Test Tool

Usage:

```text
amitls13_get [LOG=FILE] URL [OUTFILE]
```

Examples:

```text
amitls13_get http://example.com
amitls13_get https://example.com
amitls13_get LOG=RAM:tls.log https://example.com RAM:example.out
```

The static tool uses direct DOS `Exit()` after completion on OS1.3 to avoid returning through fragile runtime cleanup paths after large TLS workloads.

## Library Test Tool

Install the library file first:

```text
copy amitls13.library LIBS:
```

Then run the OpenLibrary-based test tool with a large stack:

```text
stack 131072
amitls13_get_lib https://example.com
```

Expected result:

```text
AmiTLS13 library GET: https://example.com
Received bytes: 829
Saved to: RAM:amitls13_get.out
Program end ok
```

## Library Open/Close Test

After installing `amitls13.library` into `LIBS:`, the lightweight loader test can run repeated open/close cycles without network access:

```text
amitls13_openclose 50
```

Expected result:

```text
AmiTLS13 open/close test: 50 cycles
Open/close test ok
```

## Repeat HTTPS Test

After the basic library test succeeds, run repeated HTTPS calls through the shared library:

```text
stack 131072
amitls13_repeat_get_lib https://example.com 3
```

Expected result:

```text
AmiTLS13 repeat GET: https://example.com cycles=3
Cycle 1... ok bytes=829
Cycle 2... ok bytes=829
Cycle 3... ok bytes=829
Repeat GET test ok
```

`build/amitls13_example_get` is compiled from the exported SDK files, not from the internal `src/` stubs.

## Public API Draft

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

## SDK Layout

Consumer projects should use the files under `sdk/` instead of including internal source files:

```text
sdk/include/amitls13.h
sdk/include/amitls13_libbase.h
sdk/amitls13_client_stubs.S
sdk/examples/amitls13_example_get.c
```

The example builds as `build/amitls13_example_get` and is intentionally small enough to copy into applications such as Weather13, ISSTracker, AMusicBrainz or MajaRadio.

Lifecycle rules for applications:

1. Define `struct Library *AmiTLS13Base = 0;` in one C file.
2. Open `amitls13.library` with `OpenLibrary(AMITLS13NAME, AMITLS13VERSION)`.
3. Call `AmiTLS13_Init()` before using network/TLS functions.
4. Close every stream context with `AmiTLS13_Close()` if using the stream API.
5. Call `AmiTLS13_Exit()` once for every successful `AmiTLS13_Init()`.
6. Close the library with `CloseLibrary(AmiTLS13Base)`.


## Implementation Notes

- BearSSL is linked into `amitls13.library` and into the static PoC library.
- Network I/O goes through `bsdsocket.library`.
- bsdsocket calls are routed through 68k assembly stubs that preserve registers around library calls.
- `amitls13.library` uses a classic Resident/AutoInit structure and a negative-offset function table.
- Library entry stubs translate Amiga register arguments into normal C stack arguments.
- Client stubs in `sdk/amitls13_client_stubs.S` let consumer programs call the library vectors from C.
- `AmiTLS13_HTTPGet()` allocates request and receive buffers with `AllocMem()` to reduce application stack pressure.
- TLS socket callbacks use BearSSL opaque pointers and keep callback state per `AmiTLS13Context`.
- `AmiTLS13_Init()`/`AmiTLS13_Exit()` reference-count the shared `bsdsocket.library` handle so multiple library users do not close it out from under each other.

## Next Milestones

1. Add certificate handling, initially with insecure mode plus optional pinning or a small CA bundle.
2. Integrate HTTPS into Weather13, ISSTracker, AMusicBrainz or MajaRadio as first real consumers.
