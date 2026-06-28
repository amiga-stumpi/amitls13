# AmiTLS13

AmiTLS13 is a compact TLS/HTTPS wrapper for AmigaOS 1.3 programs.

The goal is not to port the full AmiSSL/OpenSSL API. AmiTLS13 provides a small client-side API that new Kickstart 1.3 applications can use to access HTTPS resources through a bsdsocket-compatible stack.

## Current Status

AmiTLS13 now builds as a compact classic Amiga shared library named `amitls13.library`, plus static and OpenLibrary-based test tools. The current optimized release baseline has passed the Amiga-side smoke tests with `stack 65000`.

The current TLS profile is intentionally small: TLS 1.2 client mode with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, P-256 ECDHE and SHA-256 PRF/hash support. CBC, static RSA key exchange, SHA384, P-384, P-521, Curve25519, ChaCha20, CCM, DES and server-side TLS code are not linked into the release build. This keeps the library small and focused on the HTTPS endpoints currently targeted by OS1.3 applications.

The current certificate mode is intentionally insecure by default: it accepts the server certificate chain without CA or hostname validation. Public-key pinning is available as a deterministic interim protection for known HTTPS endpoints. Full CA/hostname validation is a later phase.

## Requirements

- AmigaOS 1.3 compatible runtime (`-mcrt=nix13`).
- 68020+ CPU target for the current build.
- A working `bsdsocket.library` compatible stack.
- Sufficient process stack for TLS.

Recommended stack:

```text
minimum validated: 65000 bytes
recommended:      131072 bytes
```

TLS/BearSSL still uses deep call chains during handshake, X.509 parsing and RSA verification. Large persistent buffers and the HTTP/TLS transient buffers are allocated with `AllocMem()`, and the optimized release profile has passed the current smoke tests at `stack 65000`, but applications that do additional work around TLS should still prefer a larger stack.

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
build/amitls13_pin_print_lib  prints the leaf public-key material SHA256 hash
build/amitls13_pin_fail_lib   negative test: rejects a deliberately wrong pin
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

Then run the OpenLibrary-based test tool with a suitable stack:

```text
stack 65000
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

## Public-Key Pinning Test

After installing `amitls13.library`, obtain the current leaf public-key material hash for an endpoint:

```text
stack 65000
amitls13_pin_print_lib https://example.com
```

Expected result includes a 64-character hex value:

```text
Peer public key material SHA256: ...
Program end ok
```

A negative test is also built. It installs an all-zero pin and expects the TLS handshake to fail:

```text
stack 131072
amitls13_pin_fail_lib https://example.com
```

Expected result:

```text
Pin mismatch rejected as expected: -7
```

This first pinning mode hashes the BearSSL-decoded leaf public key material, not the DER SPKI wrapper used by OpenSSL `pin-sha256` examples. Use `amitls13_pin_print_lib` to derive the value to store in OS1.3 programs.

## Repeat HTTPS Test

After the basic library test succeeds, run repeated HTTPS calls through the shared library:

```text
stack 65000
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
LONG AmiTLS13_StartTLS(struct AmiTLS13Context *ctx, const char *host);
LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len);
LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen);
void AmiTLS13_Close(struct AmiTLS13Context *ctx);
LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx);
LONG AmiTLS13_SocketErrno(void);

LONG AmiTLS13_SetPublicKeyPinSHA256(const UBYTE *sha256, ULONG len);
LONG AmiTLS13_GetLastPeerPublicKeySHA256(UBYTE *out_sha256, ULONG len);
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
- The connection context owns the BearSSL client engine, X.509 state and TLS I/O buffer and is allocated with `AllocMem()`.
- `AmiTLS13_StartTLS(ctx, host)` upgrades a connected context to TLS, using `host` as the SNI/handshake hostname. Call it after `AmiTLS13_Connect()` and before the first `AmiTLS13_Write()`/`AmiTLS13_Read()`. The handshake itself completes lazily on the first read/write.
- `AmiTLS13_HTTPGet()` keeps the stable high-level HTTP path with small `AllocMem()` request and receive buffers. The current validated receive buffer is 1024 bytes.
- `AmiTLS13_HTTPGet()` writes the full HTTP/1.0 response to the output file. Full status/header parsing is intentionally left to caller applications for now.
- Allocation defaults use `MEMF_PUBLIC` for OS1.3 compatibility. Builds may override `AMITLS13_MEM_FLAGS` and `AMITLS13_MEM_CLEAR_FLAGS` if a target system should prefer a specific memory class, but the default does not require Fast RAM.
- TLS socket callbacks use BearSSL opaque pointers and keep callback state per `AmiTLS13Context`. The current default socket wait quantum is 50 ms with a 200-try budget, giving faster wake-up than the earlier 250 ms loop while keeping a conservative total wait window.
- `AmiTLS13_Init()`/`AmiTLS13_Exit()` reference-count the shared `bsdsocket.library` handle so multiple library users do not close it out from under each other.
- `AmiTLS13_SetPublicKeyPinSHA256(pin, 32)` stores a process-global pin. Passing `0, 0` clears it. The pin is enforced when `AMITLS13F_PIN_PUBKEY_SHA256` is used on a TLS request.
- `AmiTLS13_GetLastPeerPublicKeySHA256(out, 32)` returns the leaf public-key material hash from the last successful TLS `AmiTLS13_HTTPGet()`.

## Next Milestones

1. Test the optimized library in real consumers such as ISSTracker and Weather13.
2. Add CA bundle support if memory and file handling remain acceptable.
3. Add optional compatibility profiles only when a target HTTPS endpoint needs another TLS suite or curve.
