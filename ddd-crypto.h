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

#ifndef DDD_CRYPTO_H
#define DDD_CRYPTO_H

#if USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

typedef SHA512_CTX DDD_SHA512_CTX;

#endif

typedef struct {
#if USE_OPENSSL
	EVP_MD_CTX *ctx;
#endif	
} DDD_EVP_MD_CTX;

typedef struct {
#if USE_OPENSSL
	HMAC_CTX *ctx;
#endif
} DDD_HMAC_CTX;

typedef struct {
#if USE_OPENSSL
	const EVP_MD *md;
#endif
} DDD_EVP_MD;

typedef struct {
#if USE_OPENSSL
	ENGINE *e;
#endif
} DDD_ENGINE;

DDD_EVP_MD_CTX * delphinusdns_EVP_MD_CTX_new(void);
void delphinusdns_EVP_MD_CTX_free(DDD_EVP_MD_CTX *);
int delphinusdns_EVP_DigestInit_ex(DDD_EVP_MD_CTX *, const DDD_EVP_MD *, DDD_ENGINE *);
int delphinusdns_EVP_DigestUpdate(DDD_EVP_MD_CTX *, const void *, size_t);
int delphinusdns_EVP_DigestFinal_ex(DDD_EVP_MD_CTX *, u_char *, u_int *);
DDD_HMAC_CTX * delphinusdns_HMAC_CTX_new(void);
int delphinusdns_HMAC_Init_ex(DDD_HMAC_CTX *, const void *, int, const DDD_EVP_MD *, DDD_ENGINE *);
int delphinusdns_HMAC_Update(DDD_HMAC_CTX *, const unsigned char *, size_t);
int delphinusdns_HMAC_Final(DDD_HMAC_CTX *, unsigned char *, unsigned int *);
unsigned char * delphinusdns_HMAC(const DDD_EVP_MD *, const void *, int, const unsigned char *, size_t, unsigned char *, unsigned int *);
const DDD_EVP_MD * delphinusdns_EVP_get_digestbyname(const char *);
int delphinusdns_SHA384_Update(DDD_SHA512_CTX *, const void *, size_t);
void delphinusdns_HMAC_CTX_free(DDD_HMAC_CTX *);
int delphinusdns_HMAC_CTX_reset(DDD_HMAC_CTX *);


#endif /* DDD_CRYPTO_H */
