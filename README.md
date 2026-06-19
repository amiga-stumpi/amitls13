# AmiTLS13

AmiTLS13 is a small TLS/HTTPS wrapper for AmigaOS 1.3 programs.

The goal is not to port the full AmiSSL/OpenSSL API. Instead, AmiTLS13 provides a compact client-side API that new Kickstart 1.3 applications can use to access HTTPS resources through a bsdsocket-compatible stack.

## Goals

- AmigaOS 1.3 compatible implementation style.
- Installable library name: `amitls13.library` in `LIBS:`.
- Initial target CPU: 68020+.
- Network backend: `bsdsocket.library`.
- TLS backend: BearSSL.
- Phase 1 target: static command-line HTTPS GET proof of concept.
- Later target: shared `amitls13.library` usable by multiple programs.

## Current Status

Phase 1 has started. The repository contains the OS1.3-safe project scaffold, public API draft, URL parser, bsdsocket adapter, and a test client skeleton. BearSSL has been imported into `third_party/bearssl/`. The next Phase 1 step is wiring the BearSSL client engine into `AmiTLS13_Connect()` and enabling an insecure handshake test before certificate validation.
