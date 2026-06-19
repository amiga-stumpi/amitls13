/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#ifdef AMITLS13_DEBUG
#include <libraries/dos.h>
#include <proto/dos.h>
#include <string.h>
static void hmac_dbg(const char *s)
{
	if (s) {
		Write(Output(), (APTR)s, strlen(s));
	}
}
static void hmac_dbg_num(long n)
{
	char b[16];
	char t[14];
	int i = 0;
	int p = 0;
	if (n < 0) {
		hmac_dbg("-");
		n = -n;
	}
	do {
		t[i++] = (char)('0' + (n % 10));
		n /= 10;
	} while (n && i < 13);
	while (i > 0) {
		b[p++] = t[--i];
	}
	b[p] = 0;
	hmac_dbg(b);
}
#else
#define hmac_dbg(x) ((void)0)
#define hmac_dbg_num(x) ((void)0)
#endif

static void
hmac_copy(void *dst, const void *src, size_t len)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	while (len -- > 0) {
		*d ++ = *s ++;
	}
}

static void
hmac_fill(void *dst, unsigned char c, size_t len)
{
	unsigned char *d = dst;
	while (len -- > 0) {
		*d ++ = c;
	}
}

static inline size_t
block_size(const br_hash_class *dig)
{
	unsigned ls;
	
	ls = (unsigned)(dig->desc >> BR_HASHDESC_LBLEN_OFF)
		& BR_HASHDESC_LBLEN_MASK;
	return (size_t)1 << ls;
}

static void
process_key(const br_hash_class **hc, void *ks,
	const void *key, size_t key_len, unsigned bb)
{
	union {
		uint32_t align;
		unsigned char b[256];
	} tmp_u;
	unsigned char *tmp = tmp_u.b;
	size_t blen, u;

	blen = block_size(*hc);
	hmac_copy(tmp, key, key_len);
	for (u = 0; u < key_len; u ++) {
		tmp[u] ^= (unsigned char)bb;
	}
	hmac_fill(tmp + key_len, (unsigned char)bb, blen - key_len);
	(*hc)->init(hc);
	(*hc)->update(hc, tmp, blen);
	(*hc)->state(hc, ks);
}

/* see bearssl.h */
void
br_hmac_key_init(br_hmac_key_context *kc,
	const br_hash_class *dig, const void *key, size_t key_len)
{
	union {
		uint32_t align;
		br_hash_compat_context ctx;
	} hc_u;
	union {
		uint32_t align;
		unsigned char b[64];
	} kbuf_u;
	br_hash_compat_context *hc = &hc_u.ctx;
	unsigned char *kbuf = kbuf_u.b;

#ifdef AMITLS13_DEBUG
	hmac_dbg("HMAC keyinit enter kc=");
	hmac_dbg_num((long)kc);
	hmac_dbg(" key=");
	hmac_dbg_num((long)key);
	hmac_dbg(" len=");
	hmac_dbg_num((long)key_len);
	hmac_dbg(" hc=");
	hmac_dbg_num((long)hc);
	hmac_dbg("\n");
#endif
	kc->dig_vtable = dig;
	hc->vtable = dig;
	if (key_len > block_size(dig)) {
		dig->init(&hc->vtable);
		dig->update(&hc->vtable, key, key_len);
		dig->out(&hc->vtable, kbuf);
		key = kbuf;
		key_len = br_digest_size(dig);
	}
#ifdef AMITLS13_DEBUG
	hmac_dbg("HMAC process ipad\n");
#endif
	process_key(&hc->vtable, kc->ksi, key, key_len, 0x36);
#ifdef AMITLS13_DEBUG
	hmac_dbg("HMAC process opad\n");
#endif
	process_key(&hc->vtable, kc->kso, key, key_len, 0x5C);
#ifdef AMITLS13_DEBUG
	hmac_dbg("HMAC keyinit done\n");
#endif
}

/* see bearssl.h */
void
br_hmac_init(br_hmac_context *ctx,
	const br_hmac_key_context *kc, size_t out_len)
{
	const br_hash_class *dig;
	size_t blen, hlen;

	dig = kc->dig_vtable;
	blen = block_size(dig);
	dig->init(&ctx->dig.vtable);
	dig->set_state(&ctx->dig.vtable, kc->ksi, (uint64_t)blen);
	hmac_copy(ctx->kso, kc->kso, sizeof kc->kso);
	hlen = br_digest_size(dig);
	if (out_len > 0 && out_len < hlen) {
		hlen = out_len;
	}
	ctx->out_len = hlen;
}

/* see bearssl.h */
void
br_hmac_update(br_hmac_context *ctx, const void *data, size_t len)
{
	ctx->dig.vtable->update(&ctx->dig.vtable, data, len);
}

/* see bearssl.h */
size_t
br_hmac_out(const br_hmac_context *ctx, void *out)
{
	const br_hash_class *dig;
	union {
		uint32_t align;
		br_hash_compat_context ctx;
	} hc_u;
	union {
		uint32_t align;
		unsigned char b[64];
	} tmp_u;
	br_hash_compat_context *hc = &hc_u.ctx;
	unsigned char *tmp = tmp_u.b;
	size_t blen, hlen;

	dig = ctx->dig.vtable;
	dig->out(&ctx->dig.vtable, tmp);
	blen = block_size(dig);
	dig->init(&hc->vtable);
	dig->set_state(&hc->vtable, ctx->kso, (uint64_t)blen);
	hlen = br_digest_size(dig);
	dig->update(&hc->vtable, tmp, hlen);
	dig->out(&hc->vtable, tmp);
	hmac_copy(out, tmp, ctx->out_len);
	return ctx->out_len;
}
