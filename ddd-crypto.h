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
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

typedef SHA512_CTX 	DDD_SHA512_CTX;
typedef SHA256_CTX	DDD_SHA256_CTX;
typedef SHA_CTX		DDD_SHA_CTX;

typedef BIGNUM 		DDD_BIGNUM;
typedef BN_CTX		DDD_BN_CTX;
typedef BN_GENCB 	DDD_BN_GENCB;
typedef RSA		DDD_RSA;

#define DDD_RSA_F4	RSA_F4

typedef EC_KEY		DDD_EC_KEY;
typedef EC_GROUP	DDD_EC_GROUP;
typedef EC_POINT	DDD_EC_POINT;

typedef ECDSA_SIG	DDD_ECDSA_SIG;


#endif

#ifdef USE_WOLFSSL

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/md5.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/rsa.h>

#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdsa.h>
#include <wolfssl/openssl/bn.h>

#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/hmac.h>

typedef void  	DDD_SHA512_CTX;
typedef SHA256_CTX	DDD_SHA256_CTX;
typedef SHA_CTX		DDD_SHA_CTX;

typedef BIGNUM 		DDD_BIGNUM;
typedef BN_CTX		DDD_BN_CTX;
typedef RSA		DDD_RSA;

#define DDD_RSA_F4	RSA_F4

typedef EC_KEY		DDD_EC_KEY;
typedef EC_GROUP	DDD_EC_GROUP;
typedef EC_POINT	DDD_EC_POINT;

typedef ECDSA_SIG	DDD_ECDSA_SIG;

typedef void		DDD_BN_GENCB;
typedef uint32_t	point_conversion_form_t;

#ifndef SHA384_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH	48
#endif

#endif

typedef struct {
#if USE_OPENSSL
	EVP_MD_CTX *ctx;
#endif	
#if USE_WOLFSSL
	EVP_MD_CTX *ctx;
#endif
} DDD_EVP_MD_CTX;

typedef struct {
#if USE_OPENSSL
	HMAC_CTX *ctx;
#endif
#if USE_WOLFSSL
	Hmac *ctx;
#endif
} DDD_HMAC_CTX;

typedef struct {
#if USE_OPENSSL
	const EVP_MD *md;
#endif
#if USE_WOLFSSL
	const EVP_MD *md;
#endif
} DDD_EVP_MD;

typedef struct {
#if USE_OPENSSL
	ENGINE *e;
#endif
#if USE_WOLFSSL
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
 
DDD_EC_KEY * delphinusdns_EC_KEY_new(void);
void delphinusdns_EC_KEY_free(DDD_EC_KEY *);
DDD_ECDSA_SIG * delphinusdns_ECDSA_SIG_new(void);
void delphinusdns_ECDSA_SIG_free(DDD_ECDSA_SIG *);

void delphinusdns_ECDSA_SIG_get0(const DDD_ECDSA_SIG *, const DDD_BIGNUM **, const DDD_BIGNUM **);

int delphinusdns_ECDSA_do_verify(const unsigned char *, int, const DDD_ECDSA_SIG *, DDD_EC_KEY *);

DDD_ECDSA_SIG * delphinusdns_ECDSA_do_sign(const unsigned char *, int, DDD_EC_KEY *);

void delphinusdns_EC_GROUP_free(DDD_EC_GROUP *);

int delphinusdns_EC_KEY_set_public_key(DDD_EC_KEY *, const DDD_EC_POINT *);

int delphinusdns_EC_POINT_mul(const DDD_EC_GROUP *, DDD_EC_POINT *, const DDD_BIGNUM *, const DDD_EC_POINT *, const DDD_BIGNUM *, DDD_BN_CTX *);

DDD_EC_POINT * delphinusdns_EC_POINT_new(const DDD_EC_GROUP *);
int delphinusdns_EC_KEY_set_private_key(DDD_EC_KEY *, const DDD_BIGNUM *);

int delphinusdns_EC_KEY_set_group(DDD_EC_KEY *, const DDD_EC_GROUP *);

DDD_EC_KEY * delphinusdns_EC_KEY_new_by_curve_name(int);
DDD_EC_GROUP * delphinusdns_EC_GROUP_new_by_curve_name(int);

size_t delphinusdns_EC_POINT_point2oct(const DDD_EC_GROUP *, const DDD_EC_POINT *, point_conversion_form_t, unsigned char *, size_t, DDD_BN_CTX *);

const DDD_EC_POINT * delphinusdns_EC_KEY_get0_public_key(const DDD_EC_KEY *);

const DDD_BIGNUM * delphinusdns_EC_KEY_get0_private_key(const DDD_EC_KEY *);

int delphinusdns_EC_KEY_generate_key(DDD_EC_KEY *);


#endif /* DDD_CRYPTO_H */
