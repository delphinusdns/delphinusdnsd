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


DDD_BIGNUM *
delphinusdns_BN_new(void)
{
	DDD_BIGNUM *bn;

#ifdef USE_OPENSSL
	bn = BN_new();
#endif
	return (bn);
}

void
delphinusdns_BN_free(DDD_BIGNUM *bn)
{
#ifdef USE_OPENSSL
	BN_free((BIGNUM *)bn);
#endif
}

void
delphinusdns_BN_clear_free(DDD_BIGNUM *a)
{
#ifdef USE_OPENSSL
	BN_clear_free((BIGNUM *)a);
#endif
}

int
delphinusdns_BN_bn2bin(const DDD_BIGNUM *a, unsigned char *to)
{
#ifdef USE_OPENSSL
	return (BN_bn2bin((const BIGNUM *)a, to));
#endif
}

DDD_BIGNUM *
delphinusdns_BN_bin2bn(const unsigned char *s, int len, DDD_BIGNUM *ret)
{
	DDD_BIGNUM *ret0;
#ifdef USE_OPENSSL
	ret0 = BN_bin2bn(s, len, (BIGNUM *)ret);
#endif

	return (ret0);
}

DDD_BIGNUM *
delphinusdns_BN_dup(const DDD_BIGNUM *from)
{
	DDD_BIGNUM *ret;
#ifdef USE_OPENSSL
	ret = BN_dup((const BIGNUM *)from);
#endif

	return (ret);
}

DDD_BN_GENCB *
delphinusdns_BN_GENCB_new(void)
{
	DDD_BN_GENCB *ret;
#ifdef USE_OPENSSL
	ret = BN_GENCB_new();
#endif

	return (ret);
}

int
delphinusdns_BN_set_bit(DDD_BIGNUM *a, int n)
{
	int ret;

#ifdef USE_OPENSSL
	ret = BN_set_bit((BIGNUM *)a, n);	
#endif

	return (ret);
}

void
delphinusdns_BN_GENCB_free(DDD_BN_GENCB *cb)
{
#ifdef USE_OPENSSL
	BN_GENCB_free((BN_GENCB *)cb);
#endif
}


DDD_RSA *
delphinusdns_RSA_new(void)
{
	DDD_RSA *rsa;
#ifdef USE_OPENSSL
	rsa = RSA_new();
#endif

	return (rsa);
}

void
delphinusdns_RSA_free(DDD_RSA *rsa)
{
#ifdef USE_OPENSSL
	RSA_free(rsa);
#endif
}

int
delphinusdns_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
         unsigned char *sigret, unsigned int *siglen, DDD_RSA *rsa)
{
	int ret;
#ifdef USE_OPENSSL
	ret = RSA_sign(type, m, m_len, sigret, siglen, (RSA *)rsa);
#endif

	return (ret);
}

int
delphinusdns_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
         unsigned char *sigbuf, unsigned int siglen, DDD_RSA *rsa)
{
	int ret;
#ifdef USE_OPENSSL
	ret = RSA_verify(type, m, m_len, sigbuf, siglen, (RSA *)rsa);
#endif
	return (ret);
}

void
delphinusdns_RSA_get0_key(const DDD_RSA *r, const DDD_BIGNUM **n, 
	const DDD_BIGNUM **e, const DDD_BIGNUM **d)
{
#ifdef USE_OPENSSL
	RSA_get0_key((const RSA *)r, (const BIGNUM **)n, (const BIGNUM **)e,
		(const BIGNUM **)d);
#endif
}

void
delphinusdns_RSA_get0_factors(const DDD_RSA *r, const DDD_BIGNUM **p, 
		const DDD_BIGNUM **q)
{
#ifdef USE_OPENSSL
	RSA_get0_factors((const RSA *)r, (const BIGNUM **)p, (const BIGNUM **)q);
#endif
}

void
delphinusdns_RSA_get0_crt_params(const DDD_RSA *r, const DDD_BIGNUM **dmp1,
	const DDD_BIGNUM **dmq1, const DDD_BIGNUM **iqmp)
{
#ifdef USE_OPENSSL
	RSA_get0_crt_params((const RSA *)r, (const BIGNUM **)dmp1, (const BIGNUM **)dmq1, (const BIGNUM **)iqmp);
#endif

}

int
delphinusdns_RSA_generate_key_ex(DDD_RSA *rsa, int bits, DDD_BIGNUM *e,
	DDD_BN_GENCB *cb)
{
	int ret;

#ifdef USE_OPENSSL
	ret = RSA_generate_key_ex((RSA *)rsa, bits, (BIGNUM *)e, (BN_GENCB *)cb);
#endif

	return (ret);
}

int
delphinusdns_RSA_set0_key(DDD_RSA *r, DDD_BIGNUM *n, DDD_BIGNUM *e, DDD_BIGNUM *d)
{
	int ret;
#ifdef USE_OPENSSL
	ret = RSA_set0_key((RSA *)r, (BIGNUM *)n, (BIGNUM *)e, (BIGNUM *)d);
#endif

	return (ret);
}

int
delphinusdns_RSA_set0_factors(DDD_RSA *r, DDD_BIGNUM *p, DDD_BIGNUM *q)
{
	int ret;
#ifdef USE_OPENSSL
	ret = RSA_set0_factors((RSA *)r, (BIGNUM *)p, (BIGNUM *)q);
#endif

	return (ret);
}

int
delphinusdns_RSA_set0_crt_params(DDD_RSA *r, DDD_BIGNUM *dmp1, 
	DDD_BIGNUM *dmq1, DDD_BIGNUM *iqmp)
{
	int ret;
#ifdef USE_OPENSSL
	ret = RSA_set0_crt_params((RSA *)r, (BIGNUM *)dmp1, (BIGNUM *)dmq1,
		(BIGNUM *)iqmp);
#endif

	return (ret);
}
