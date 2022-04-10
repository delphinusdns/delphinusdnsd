/*
 * Copyright (c) 2022 Peter J. Philipp <pjp@delphinusdns.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>

#include "ddd-crypto.h"

DDD_EVP_MD_CTX *
delphinusdns_EVP_MD_CTX_new(void)
{
	static DDD_EVP_MD_CTX *ctx;

#ifdef USE_OPENSSL
	if ((ctx = calloc(1, sizeof(DDD_EVP_MD_CTX))) == NULL)
		return NULL;
	
	ctx->ctx = NULL;

	if ((ctx->ctx = EVP_MD_CTX_new()) == NULL) {
		free(ctx);
		return NULL;
	}

#endif
	
	return (ctx);
}

void
delphinusdns_EVP_MD_CTX_free(DDD_EVP_MD_CTX *ctx)
{

#ifdef USE_OPENSSL
	EVP_MD_CTX_free(ctx->ctx);
#endif
	free(ctx);
}


void
delphinusdns_HMAC_CTX_free(DDD_HMAC_CTX *ctx)
{
#ifdef USE_OPENSSL
	HMAC_CTX_free(ctx->ctx);
#endif
	free(ctx);
}


int
delphinusdns_EVP_DigestInit_ex(DDD_EVP_MD_CTX *ctx, const DDD_EVP_MD *type,
	DDD_ENGINE *impl)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = EVP_DigestInit_ex(ctx->ctx, (const EVP_MD *)type->md, (impl == NULL) ? NULL : (ENGINE *)impl->e);
#endif
	return (ret);
}

int
delphinusdns_EVP_DigestUpdate(DDD_EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = EVP_DigestUpdate(ctx->ctx, d, cnt);
#endif

	return (ret);
}

int
delphinusdns_EVP_DigestFinal_ex(DDD_EVP_MD_CTX *ctx, u_char *md, u_int *s)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = EVP_DigestFinal_ex(ctx->ctx, md, s);
#endif
	return (ret);
}


DDD_HMAC_CTX *
delphinusdns_HMAC_CTX_new(void)
{
	static DDD_HMAC_CTX *ctx;

#ifdef USE_OPENSSL
	if ((ctx = calloc(1, sizeof(DDD_HMAC_CTX))) == NULL)
		return NULL;

	ctx->ctx = NULL;

	if ((ctx->ctx = HMAC_CTX_new()) == NULL) {
		free(ctx);
		return NULL;
	}
#endif
	return (ctx);
}

int
delphinusdns_HMAC_Init_ex(DDD_HMAC_CTX *ctx, const void *key, int key_len,
	const DDD_EVP_MD *md, DDD_ENGINE *impl)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = HMAC_Init_ex(ctx->ctx, key, key_len, md->md, (impl == NULL) ? NULL : (ENGINE *)impl->e);
#endif

	return (ret);
}

int
delphinusdns_HMAC_Update(DDD_HMAC_CTX *ctx, const unsigned char *data, 
	size_t len)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = HMAC_Update(ctx->ctx, (const unsigned char *)data, len);
#endif

	return (ret);
}

int
delphinusdns_HMAC_Final(DDD_HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = HMAC_Final(ctx->ctx, (unsigned char *)md, (unsigned int *)len);
#endif

	return (ret);
}

unsigned char *
delphinusdns_HMAC(const DDD_EVP_MD *evp_md, const void *key, int key_len,
	const unsigned char *d, size_t n, unsigned char *md,
	unsigned int *md_len)
{
	static unsigned char *ret;

#ifdef USE_OPENSSL
	ret = HMAC(evp_md->md, (const void *)key, key_len, (const unsigned char *)d, n, (unsigned char *)md, (unsigned int *)md_len);
#endif

	return (ret);
}

const DDD_EVP_MD *
delphinusdns_EVP_get_digestbyname(const char *name)
{
	static DDD_EVP_MD *ret;

#ifdef USE_OPENSSL
	if ((ret = calloc(1, sizeof(DDD_EVP_MD))) == NULL) {
		return NULL;
	}
	
	ret->md = EVP_get_digestbyname(name);
	if (ret->md == NULL) {
		free(ret);
		return NULL;
	}
#endif

	return (ret);
}

int
delphinusdns_SHA384_Update(DDD_SHA512_CTX *c, const void *data, size_t len)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = SHA384_Update((SHA512_CTX *)c, (const void *)data, len);
#endif

	return (ret);
}

int
delphinusdns_HMAC_CTX_reset(DDD_HMAC_CTX *ctx)
{
	static int ret;

#ifdef USE_OPENSSL
	ret = HMAC_CTX_reset(ctx->ctx);	
#endif

	return (ret);
}
