# AmiTLS13 SDK

This folder contains the files needed by AmigaOS 1.3 programs that want to use `amitls13.library`.

## Files

```text
include/amitls13.h              public API and error codes
include/amitls13_libbase.h      library name/version and AmiTLS13Base declaration
amitls13_client_stubs.S         C-callable library-vector stubs
examples/amitls13_example_get.c minimal HTTPS GET example
```

## Build Requirements

- Target AmigaOS 1.3 with bebbo/amiga-gcc and `-mcrt=nix13`.
- Link the application with `amitls13_client_stubs.S`.
- Define `struct Library *AmiTLS13Base = 0;` in exactly one C file of the application.
- Install `amitls13.library` in `LIBS:` on the target system.
- Use a large process stack for TLS. Recommended: `stack 131072`.

## Lifecycle

1. Open the library with `OpenLibrary(AMITLS13NAME, AMITLS13VERSION)`.
2. Call `AmiTLS13_Init()` before network/TLS operations.
3. Use either the stream API (`AmiTLS13_Connect`, `AmiTLS13_Write`, `AmiTLS13_Read`, `AmiTLS13_Close`) or the convenience helper `AmiTLS13_HTTPGet()`.
4. Close every `AmiTLS13Context` with `AmiTLS13_Close()`.
5. Call `AmiTLS13_Exit()` once for every successful `AmiTLS13_Init()`.
6. Close the library with `CloseLibrary(AmiTLS13Base)`.

`AmiTLS13_Init()` and `AmiTLS13_Exit()` reference-count the shared `bsdsocket.library` handle. This lets multiple consumers use AmiTLS13 in the same system without one program closing the socket library while another one still needs it.

## Current Security Status

TLS transport works, but certificate verification is not implemented yet. Use `AMITLS13F_INSECURE` for the current proof-of-concept phase. This encrypts the connection but does not protect against man-in-the-middle attacks.

Future flags are already reserved:

```c
AMITLS13F_VERIFY_CERT
AMITLS13F_VERIFY_HOSTNAME
```

## Example

Compile the example together with the client stubs, then run on the Amiga:

```text
stack 131072
amitls13_example_get https://example.com RAM:example.out
```
