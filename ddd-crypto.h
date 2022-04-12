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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

typedef SHA512_CTX 	DDD_SHA512_CTX;
typedef BIGNUM 		DDD_BIGNUM;
typedef BN_GENCB 	DDD_BN_GENCB;
typedef RSA		DDD_RSA;

#define DDD_RSA_F4	RSA_F4
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

DDD_BIGNUM * delphinusdns_BN_new(void);
void delphinusdns_BN_free(DDD_BIGNUM *);
int delphinusdns_BN_bn2bin(const DDD_BIGNUM *, unsigned char *);
DDD_BIGNUM * delphinusdns_BN_bin2bn(const unsigned char *, int, DDD_BIGNUM *);
DDD_BIGNUM * delphinusdns_BN_dup(const DDD_BIGNUM *);
DDD_BN_GENCB * delphinusdns_BN_GENCB_new(void);
int delphinusdns_BN_set_bit(DDD_BIGNUM *, int);
void delphinusdns_BN_GENCB_free(DDD_BN_GENCB *);
void delphinusdns_BN_clear_free(DDD_BIGNUM *);



DDD_RSA * delphinusdns_RSA_new(void);
void delphinusdns_RSA_free(DDD_RSA *rsa);
int delphinusdns_RSA_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, DDD_RSA *);
int delphinusdns_RSA_verify(int, const unsigned char *, unsigned int, unsigned char *, unsigned int, DDD_RSA *);
void delphinusdns_RSA_get0_key(const DDD_RSA *, const DDD_BIGNUM **, const DDD_BIGNUM **, const DDD_BIGNUM **);
void delphinusdns_RSA_get0_factors(const DDD_RSA *, const DDD_BIGNUM **, const DDD_BIGNUM **);
void delphinusdns_RSA_get0_crt_params(const DDD_RSA *, const DDD_BIGNUM **, const DDD_BIGNUM **, const DDD_BIGNUM **);

int delphinusdns_RSA_generate_key_ex(DDD_RSA *, int, DDD_BIGNUM *, DDD_BN_GENCB *);
int delphinusdns_RSA_set0_key(DDD_RSA *, DDD_BIGNUM *, DDD_BIGNUM *, DDD_BIGNUM *);
int delphinusdns_RSA_set0_factors(DDD_RSA *, DDD_BIGNUM *, DDD_BIGNUM *);
int delphinusdns_RSA_set0_crt_params(DDD_RSA *, DDD_BIGNUM *,  DDD_BIGNUM *, DDD_BIGNUM *);
 



#endif /* DDD_CRYPTO_H */
