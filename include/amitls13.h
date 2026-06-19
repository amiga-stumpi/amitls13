#ifndef AMITLS13_H
#define AMITLS13_H

#include <exec/types.h>

#define AMITLS13_VERSION 0
#define AMITLS13_REVISION 1

#define AMITLS13F_INSECURE        0x00000001UL
#define AMITLS13F_VERIFY_CERT     0x00000002UL
#define AMITLS13F_VERIFY_HOSTNAME 0x00000004UL

#define AMITLS13_OK                 0L
#define AMITLS13_ERR_NO_SOCKETLIB  -1L
#define AMITLS13_ERR_DNS           -2L
#define AMITLS13_ERR_SOCKET        -3L
#define AMITLS13_ERR_CONNECT       -4L
#define AMITLS13_ERR_URL           -5L
#define AMITLS13_ERR_TLS_DISABLED  -6L
#define AMITLS13_ERR_IO            -7L

struct AmiTLS13Context;

LONG AmiTLS13_Init(void);
void AmiTLS13_Exit(void);

struct AmiTLS13Context *AmiTLS13_Connect(const char *host, UWORD port, ULONG flags);
LONG AmiTLS13_Write(struct AmiTLS13Context *ctx, const UBYTE *buf, ULONG len);
LONG AmiTLS13_Read(struct AmiTLS13Context *ctx, UBYTE *buf, ULONG maxlen);
void AmiTLS13_Close(struct AmiTLS13Context *ctx);
LONG AmiTLS13_GetLastError(struct AmiTLS13Context *ctx);

LONG AmiTLS13_HTTPGet(const char *url, const char *outfile, ULONG flags);

#endif
