/* 
 * Copyright (c) 2020 Peter J. Philipp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

/*
 * $Id: sign.c,v 1.9 2020/07/23 10:48:45 pjp Exp $
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#include "imsg.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include "imsg.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#ifndef NTOHS
#include "endian.h"
#endif

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-config.h"


SLIST_HEAD(, keysentry) keyshead;

static struct keysentry {
        char *keyname;
	uint32_t pid;
	int sign;
	int type;

	/* key material in this struct */
        char *key;
        char *zone;
        uint32_t ttl;
        uint16_t flags;
        uint8_t protocol;
        uint8_t algorithm;
        int keyid;

	/* private key RSA */
	BIGNUM *rsan;
	BIGNUM *rsae;
	BIGNUM *rsad;
	BIGNUM *rsap;
	BIGNUM *rsaq;
	BIGNUM *rsadmp1;
	BIGNUM *rsadmq1;
	BIGNUM *rsaiqmp;

	/* private key Elliptic Curve */

	BIGNUM *ecprivate;

        SLIST_ENTRY(keysentry) keys_entry;
} *kn, *knp;

u_int64_t expiredon, signedon;

/* prototypes */

int	add_dnskey(ddDB *);
char * 	parse_keyfile(int, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  key2zone(char *, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  get_key(struct keysentry *,uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int, int *);

char *	create_key(char *, int, int, int, int, uint32_t *);
char *	create_key_rsa(char *, int, int, int, int, uint32_t *);
char *	create_key_ec(char *, int, int, int, int, uint32_t *);
int	create_key_ec_getpid(EC_KEY *, EC_GROUP *, EC_POINT *, int, int);

char * 	alg_to_name(int);
int 	alg_to_rsa(int);

int 	construct_nsec3(ddDB *, char *, int, char *);
int 	calculate_rrsigs(ddDB *, char *, int, int);

static int	sign_hinfo(ddDB *, char *, int, struct rbtree *, int);
static int	sign_rp(ddDB *, char *, int, struct rbtree *, int);
static int	sign_caa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_dnskey(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_a(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_mx(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_ns(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_srv(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_cname(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_soa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_txt(ddDB *, char *, int, struct rbtree *, int);
static int	sign_aaaa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_ptr(ddDB *, char *, int, struct rbtree *, int);
static int	sign_nsec3(ddDB *, char *, int, struct rbtree *, int);
static int	sign_nsec3param(ddDB *, char *, int, struct rbtree *, int);
static int	sign_naptr(ddDB *, char *, int, struct rbtree *, int);
static int	sign_sshfp(ddDB *, char *, int, struct rbtree *, int);
static int	sign_tlsa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_ds(ddDB *, char *, int, struct rbtree *, int);

int 		sign(int, char *, int, struct keysentry *, char *, int *);
int 		create_ds(ddDB *, char *, struct keysentry *);
u_int 		keytag(u_char *key, u_int keysize);
u_int 		dnskey_keytag(struct dnskey *dnskey);
void		free_private_key(struct keysentry *);
RSA * 		get_private_key_rsa(struct keysentry *);
EC_KEY *	get_private_key_ec(struct keysentry *);
int		store_private_key(struct keysentry *, char *, int, int);
int 		print_rbt(FILE *, struct rbtree *);
int 		print_rbt_bind(FILE *, struct rbtree *);
int		signmain(int argc, char *argv[]);
void 		init_keys(void);
uint32_t 	getkeypid(char *);
void		update_soa_serial(ddDB *, char *, time_t);
void		debug_bindump(const char *, int);
int 		dump_db(ddDB *, FILE *, char *);
int		notglue(ddDB *, struct rbtree *, char *);
char * 		dnskey_wire_rdata(struct rr *, int *);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

BN_GENCB * BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *);

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp);
#endif

extern int debug;
extern int verbose;
extern int bytes_received;
extern int notify;
extern int passlist;
extern int bcount;
extern char *bind_list[255];
extern char *interface_list[255];
extern int bflag;
extern int ratelimit_packets_per_second;
extern int ratelimit;
extern int nflag;
extern int iflag;
extern int lflag;
extern int icount;
extern int vslen;
extern char *versionstring;

/* externs */

extern void	dolog(int pri, char *fmt, ...);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern int fill_dnskey(ddDB *,char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);
extern int fill_rrsig(ddDB *,char *, char *, u_int32_t, char *, u_int8_t, u_int8_t, u_int32_t, u_int64_t, u_int64_t, u_int16_t, char *, char *);
extern int fill_nsec3param(ddDB *, char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *);
extern int fill_nsec3(ddDB *, char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *, char *, char *);
extern char * convert_name(char *name, int namelen);

extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);
extern struct rbtree *         Lookup_zone(ddDB *, char *, int, int, int);
extern struct question         *build_fake_question(char *, int, u_int16_t, char *, int);
extern char * dns_label(char *, int *);
extern int label_count(char *);
extern char *get_dns_type(int, int);
extern char * hash_name(char *, int, struct nsec3param *);
extern char * base32hex_encode(u_char *input, int len);
extern int  	init_entlist(ddDB *);
extern int	check_ent(char *, int);
extern struct question          *build_question(char *, int, int, char *);
struct rrtab    *rrlookup(char *);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
extern char * 	bin2hex(char *, int);
extern u_int64_t timethuman(time_t);
extern char * 	bitmap2human(char *, int);
extern int                      memcasecmp(u_char *, u_char *, int);

extern int insert_axfr(char *, char *);
extern int insert_filter(char *, char *);
extern int insert_passlist(char *, char *);
extern int insert_notifyddd(char *, char *);

extern int dnssec;
extern int tsig;

/* Aliases */

#define ROLLOVER_METHOD_PRE_PUBLICATION		0
#define ROLLOVER_METHOD_DOUBLE_SIGNATURE	1

#define KEYTYPE_NONE	0
#define KEYTYPE_KSK 	1
#define KEYTYPE_ZSK	2

#define SCHEME_OFF	0
#define SCHEME_YYYY	1
#define SCHEME_TSTAMP	2

#define ALGORITHM_RSASHA1_NSEC3_SHA1 	7 	/* rfc 5155 */
#define ALGORITHM_RSASHA256		8	/* rfc 5702 */
#define ALGORITHM_RSASHA512		10	/* rfc 5702 */
#define ALGORITHM_ECDSAP256SHA256	13	/* rfc 6605 */

#define RSA_F5			0x100000001

#define PROVIDED_SIGNTIME			0
#define	SIGNEDON				20161230073133
#define EXPIREDON 				20170228073133

#define SIGNEDON_DRIFT				(14 * 86400)
#define DEFAULT_EXPIRYTIME			(60 * 86400)

#define DEFAULT_TTL				3600
#define DEFAULT_BITS				3072

/* define masks */

#define MASK_PARSE_BINDFILE		0x1
#define MASK_PARSE_FILE			0x2
#define MASK_ADD_DNSKEY			0x4
#define MASK_CONSTRUCT_NSEC3		0x8
#define MASK_CALCULATE_RRSIGS		0x10
#define MASK_CREATE_DS			0x20
#define MASK_DUMP_DB			0x40
#define MASK_DUMP_BIND			0x80


/*
 * SIGNMAIN - the heart of dddctl sign ...
 */

int
signmain(int argc, char *argv[])
{
	FILE *of = stdout;
	struct stat sb;

	int ch;
	int bits = DEFAULT_BITS;
	int ttl = DEFAULT_TTL;
	int create_zsk = 0;
	int create_ksk = 0;
	int rollmethod = ROLLOVER_METHOD_PRE_PUBLICATION;
	int algorithm = ALGORITHM_ECDSAP256SHA256;
	int expiry = DEFAULT_EXPIRYTIME;
	int iterations = 10;
	u_int32_t mask = (MASK_PARSE_FILE | MASK_ADD_DNSKEY | MASK_CONSTRUCT_NSEC3 | MASK_CALCULATE_RRSIGS | MASK_CREATE_DS | MASK_DUMP_DB);

	char *salt = "-";
	char *zonefile = NULL;
	char *zonename = NULL;
	char *ep;
	
	int ksk_key = 0, zsk_key = 0;
	int numkeys = 0, search = 0;

	int numksk = 0, numzsk = 0;

	uint32_t pid = -1, newpid;

	char key_key[4096];
	char buf[512];
       	char *key_zone;
        uint32_t key_ttl;
        uint16_t key_flags;
        uint8_t key_protocol;
        uint8_t key_algorithm;
        int key_keyid;
	
	ddDB *db;

	time_t now, serial = 0;
	struct tm *tm;
	uint32_t parseflags = PARSEFILE_FLAG_NOSOCKET;

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif


	while ((ch = getopt(argc, argv, "a:B:e:hI:i:Kk:m:n:o:R:S:s:t:vXx:Zz:")) != -1) {
		switch (ch) {
		case 'a':
			/* algorithm */
			algorithm = atoi(optarg);
			break;
	
		case 'B':
			/* bits */

			bits = atoi(optarg);
			break;
		case 'e':
			/* expiry */
		
			expiry = atoi(optarg);
			break;

		case 'I':
			/* NSEC3 iterations */
			iterations = atoi(optarg);	
			break;

		case 'i':
			/* inputfile */
			zonefile = optarg;

			break;

		case 'K':
			/* create KSK key */
			create_ksk = 1;

			break;

		case 'k':
			/* use KSK key */
			kn = malloc(sizeof(struct keysentry));
			if (kn == NULL) {
				perror("malloc");
				exit(1);
			}
			kn->keyname = strdup(optarg);
			if (kn->keyname == NULL) {
				perror("strdup");
				exit(1);
			}
			kn->type = KEYTYPE_KSK;
			kn->pid = getkeypid(kn->keyname);
#if DEBUG
			printf("opened %s with pid %u\n", kn->keyname, kn->pid);
#endif
			kn->sign = 0;
			ksk_key = 1;

			if ((key_zone = key2zone(kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
				perror("key2zone");
				exit(1);
			}

			kn->zone = strdup(key_zone);
			if (kn->zone == NULL) {
				perror("strdup");
				exit(1);
			}
			kn->ttl = key_ttl;
			kn->flags = key_flags;
			kn->protocol = key_protocol;
			kn->algorithm = key_algorithm;
			kn->key = strdup(key_key);
			if (kn->key == NULL) {
				perror("strdup kn->key");
				exit(1);
			}
			kn->keyid = key_keyid;

			if (store_private_key(kn, kn->zone, kn->keyid, kn->algorithm) < 0) {
				perror("store_private_key");
				exit(1);
			}

			SLIST_INSERT_HEAD(&keyshead, kn, keys_entry);
			numkeys++;
			numksk++;

			break;

		case 'm':
			/* mask */
			mask = strtoull(optarg, &ep, 16); 
			break;

		case 'n':

			/* zone name */
			zonename = optarg;

			break;

		case 'o':
			/* output file */
			if (optarg[0] == '-')
				break;
 
			errno = 0;
			if (lstat(optarg, &sb) < 0 && errno != ENOENT) {
				perror("lstat");
				exit(1);
			}
			if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
				fprintf(stderr, "%s is not a file!\n", optarg);
				exit(1);
			}
			if ((of = fopen(optarg, "w")) == NULL) {
				perror("fopen");
				exit(1);
			}

			break;
		case 'R':
			/* rollover method see RFC 7583 section 2.1 */
			if (strcmp(optarg, "prep") == 0) {
				rollmethod = ROLLOVER_METHOD_PRE_PUBLICATION;
			} else if (strcmp(optarg, "double") == 0) {
				rollmethod = ROLLOVER_METHOD_DOUBLE_SIGNATURE;
			}
			
			break;

		case 'S':
			pid = atoi(optarg);

			break;

		case 's':
			/* salt */
			salt = optarg;
			break;

		case 't':

			/* ttl of the zone */
			ttl = atoi(optarg);

			break;

		case 'v':
			/* version */

			printf("%s\n", DD_CONVERT_VERSION);
			exit(0);

		case 'X':
			/* update serial */
			now = time(NULL);
			tm = localtime(&now);
			strftime(buf, sizeof(buf), "%Y%m%d01", tm);
			serial = atoll(buf);
			break;	

		case 'x':
			serial = atoll(optarg);
			break;

		case 'Z':
			/* create ZSK */
			create_zsk = 1;
			break;

		case 'z':
			/* use ZSK */
			kn = malloc(sizeof(struct keysentry));
			if (kn == NULL) {
				perror("malloc");
				exit(1);
			}
			kn->keyname = strdup(optarg);
			if (kn->keyname == NULL) {
				perror("strdup");
				exit(1);
			}
			kn->type = KEYTYPE_ZSK;
			kn->pid = getkeypid(kn->keyname);
#if DEBUG
			printf("opened %s with pid %u\n", kn->keyname, kn->pid);
#endif
			kn->sign = 0;
			zsk_key = 1;

			if ((key_zone = key2zone(kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
				perror("key2zone");
				exit(1);
			}

			kn->zone = strdup(key_zone);
			if (kn->zone == NULL) {
				perror("strdup");
				exit(1);
			}
			kn->ttl = key_ttl;
			kn->flags = key_flags;
			kn->protocol = key_protocol;
			kn->algorithm = key_algorithm;
			kn->key = strdup(key_key);
			if (kn->key == NULL) {
				perror("strdup kn->key");
				exit(1);
			}
			kn->keyid = key_keyid;

			if (store_private_key(kn, kn->zone, kn->keyid, kn->algorithm) < 0) {
				perror("store_private_key");
				exit(1);
			}


			SLIST_INSERT_HEAD(&keyshead, kn, keys_entry);
			numkeys++;
			numzsk++;

			break;
		}
	
	}


	if (zonename == NULL) {
		fprintf(stderr, "must provide a zonename with the -n flag\n");
		exit(1);
	}

	if (create_ksk) {
		kn = malloc(sizeof(struct keysentry));
		if (kn == NULL) {
			perror("malloc");
			exit(1);
		}

		dolog(LOG_INFO, "creating new KSK (257) algorithm: %s with %d bits, pid ", alg_to_name(algorithm), bits);
		kn->keyname = create_key(zonename, ttl, 257, algorithm, bits, &newpid);
		if (kn->keyname == NULL) {
			dolog(LOG_ERR, "failed.\n");
			exit(1);
		}

		kn->type = KEYTYPE_KSK;
		kn->pid = newpid;
		kn->sign = 0;
		ksk_key = 1;

		dolog(LOG_INFO, "%d.\n", newpid);
		
		if ((key_zone = key2zone(kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
			perror("key2zone");
			exit(1);
		}

		kn->zone = strdup(key_zone);
		if (kn->zone == NULL) {
			perror("strdup");
			exit(1);
		}
		kn->ttl = key_ttl;
		kn->flags = key_flags;
		kn->protocol = key_protocol;
		kn->algorithm = key_algorithm;
		kn->key = strdup(key_key);
		if (kn->key == NULL) {
			perror("strdup kn->key");
			exit(1);
		}
		kn->keyid = key_keyid;


		if (store_private_key(kn, kn->zone, kn->keyid, kn->algorithm) < 0) {
			perror("store_private_key");
			exit(1);
		}

		SLIST_INSERT_HEAD(&keyshead, kn, keys_entry);
		numkeys++;
		numksk++;
	}
	if (create_zsk) {
		kn = malloc(sizeof(struct keysentry));
		if (kn == NULL) {
			perror("malloc");
			exit(1);
		}
		dolog(LOG_INFO, "creating new ZSK (256) algorithm: %s with %d bits, pid ", alg_to_name(algorithm), bits);
		kn->keyname = create_key(zonename, ttl, 256, algorithm, bits, &newpid);
		if (kn->keyname == NULL) {
			dolog(LOG_ERR, "failed.\n");
			exit(1);
		}
			
		kn->type = KEYTYPE_ZSK;
		kn->pid = newpid;
		kn->sign = 0;
		zsk_key = 1;

		dolog(LOG_INFO, "%d.\n", newpid);
	
		if ((key_zone = key2zone(kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
			perror("key2zone");
			exit(1);
		}

		kn->zone = strdup(key_zone);
		if (kn->zone == NULL) {
			perror("strdup");
			exit(1);
		}
		kn->ttl = key_ttl;
		kn->flags = key_flags;
		kn->protocol = key_protocol;
		kn->algorithm = key_algorithm;
		kn->key = strdup(key_key);
		if (kn->key == NULL) {
			perror("strdup kn->key");
			exit(1);
		}
		kn->keyid = key_keyid;
				
		if (store_private_key(kn, kn->zone, kn->keyid, kn->algorithm) < 0) {
			perror("store_private_key");
			exit(1);
		}


		SLIST_INSERT_HEAD(&keyshead, kn, keys_entry);
		numkeys++;
		numzsk++;
	}

	if (zonefile == NULL || zonename == NULL) {
		if (create_zsk || create_ksk) {
			fprintf(stderr, "key(s) created\n");
			exit(0);
		}

		fprintf(stderr, "must provide a zonefile and a zonename!\n");
		exit(1);
	} 

	if (ksk_key == 0 || zsk_key == 0) {
		dolog(LOG_INFO, "must specify both a ksk and a zsk key! or -z -k\n");
		exit(1);
	}


	/* check what keys we sign or not */
	if ((rollmethod == ROLLOVER_METHOD_PRE_PUBLICATION && numkeys > 3) ||
		(rollmethod == ROLLOVER_METHOD_DOUBLE_SIGNATURE && numkeys > 4)) {
		switch (rollmethod) {
		case ROLLOVER_METHOD_PRE_PUBLICATION:
			dolog(LOG_INFO, "rollover pre-publication method: can't roll-over more than 1 key at a time! numkeys > 3\n");
			break;
		case ROLLOVER_METHOD_DOUBLE_SIGNATURE:
			dolog(LOG_INFO, "rollover double-signature method: can't roll-over more than 2 keys at a time!  numkeys > 4\n");
			break;
		}

		exit(1);
	} else if ((numkeys > 2 && rollmethod == ROLLOVER_METHOD_DOUBLE_SIGNATURE) || numkeys == 2) {
#if 0
	} else if (numkeys == 2) {
#endif
		/* sign them all */
		SLIST_FOREACH(knp, &keyshead, keys_entry) {
			knp->sign = 1;
		}
	} else {
		/* we can only be pre-publication method and have 3 keys now */
		if (pid == -1) {
			fprintf(stderr, "pre-publication rollover: you specified three keys, please select one for signing (with -S pid)!\n");
			exit(1);
		}

		search = KEYTYPE_NONE;
		SLIST_FOREACH(knp, &keyshead, keys_entry) {
			if (knp->pid == pid) {
				knp->sign = 1;
				search = (knp->type == KEYTYPE_KSK) ? KEYTYPE_ZSK : KEYTYPE_KSK;
				break;
			}
		}

		SLIST_FOREACH(knp, &keyshead, keys_entry) {
			if (search == knp->type && knp->sign == 0)
				knp->sign = 1;
		} /* SLIST_FOREACH */
	} /* numkeys == 3 */

#if DEBUG
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		printf("%s pid: %u %s\n", knp->keyname, knp->pid, knp->sign ? "<--" : "" );
	}
#endif
#if DEBUG
	printf("zonefile is %s\n", zonefile);
#endif

	/* open the database(s) */
	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		exit(1);
	}

	/* now we start reading our configfile */
		
	if ((mask & MASK_PARSE_FILE) && parse_file(db, zonefile, parseflags) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		exit(1);
	}

	/* create ENT list */
	if (init_entlist(db) < 0) {
		dolog(LOG_INFO, "creating entlist failed\n");
		exit(1);
	}

	/* update any serial updates here */
	if (serial)
		update_soa_serial(db, zonename, serial);

	/* three passes to "sign" our zones */
	/* first pass, add dnskey records, on apex */

	if ((mask & MASK_ADD_DNSKEY) && add_dnskey(db) < 0) {
		dolog(LOG_INFO, "add_dnskey failed\n");
		exit(1);
	}

	/* second pass construct NSEC3 records, including ENT's */	

	if ((mask & MASK_CONSTRUCT_NSEC3) && construct_nsec3(db, zonename, iterations, salt) < 0) {
		dolog(LOG_INFO, "construct nsec3 failed\n");
		exit(1);
	}

	/* third  pass calculate RRSIG's for every RR set */

	if ((mask & MASK_CALCULATE_RRSIGS) && calculate_rrsigs(db, zonename, expiry, rollmethod) < 0) {
		dolog(LOG_INFO, "calculate rrsigs failed\n");
		exit(1);
	}

	/* calculate ds */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((mask & MASK_CREATE_DS) && create_ds(db, zonename, knp) < 0) {
			dolog(LOG_INFO, "create_ds failed\n");
			exit(1);
		}
	}

	/* free private keys */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		free_private_key(knp);	
	}

	/* write new zone file */
	if ((mask & MASK_DUMP_DB) && dump_db(db, of, zonename) < 0)
		exit (1);


	exit(0);
}


int	
add_dnskey(ddDB *db)
{
	char key[4096];
	char *zone;
	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	int keyid;

	/* first the zsk */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->type == KEYTYPE_ZSK) {
			if ((zone = get_key(knp, &ttl, &flags, &protocol, &algorithm, (char *)&key, sizeof(key), &keyid)) == NULL) {
				dolog(LOG_INFO, "get_key: %s\n", knp->keyname);
				return -1;
			}
			if (fill_dnskey(db, zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
				return -1;
			}
		} /* if ZSK */
	} /* SLIST_FOREACH */

	/* now the ksk */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->type == KEYTYPE_KSK) {
			if ((zone = get_key(knp, &ttl, &flags, &protocol, &algorithm, (char *)&key, sizeof(key), &keyid)) == NULL) {
				dolog(LOG_INFO, "get_key %s\n", knp->keyname);
				return -1;
			}
			if (fill_dnskey(db, zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
				return -1;
			}
		} /* if KSK */
	} /* SLIST_FOREACH */

	return 0;
}

char *
parse_keyfile(int fd, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int *keyid)
{
	static char retbuf[256];
	char buf[8192];
	char *p, *q;
	FILE *f;

	if ((f = fdopen(fd, "r")) == NULL)
		return NULL;
	
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (buf[0] == ';') {
			if ((p = strstr(buf, "keyid ")) != NULL) {
				p += 6;
				q = strchr(p, ' ');
				if (q == NULL) 
					return NULL;
				*q = '\0';
				pack32((char *)keyid, atoi(p));
			}

			continue;
		}
	}

	/* name */
	p = &buf[0];
	q = strchr(p, ' ');
	if (q == NULL) {
		return NULL;
	}
	
	*q++ = '\0';
	
	strlcpy(retbuf, p, sizeof(retbuf));
	/* ttl */
	p = q;
	
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;

	*q++ = '\0';
	*ttl = atoi(p);
	/* IN/DNSKEY/ flags */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	q++;
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	q++;
	p = q;
	q = strchr(p, ' ');
	if (q == NULL) 
		return NULL;
	*q++ = '\0';
	*flags = atoi(p);
	/* protocol */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	*q++ = '\0';
	*protocol = atoi(p);
	/* algorithm */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	*q++ = '\0';
	*algorithm = atoi(p);
	/* key */
	p = q;

	q = key;
	while (*p) {
		if (*p == ' ' || *p == '\n' || *p == '\r') {
			p++;
			continue;
		}

		*q++ = *p++;
	}
	*q = '\0';
			
	return (&retbuf[0]);	
}

int
dump_db(ddDB *db, FILE *of, char *zonename)
{
	int j, rs;

        ddDBT key, data;
	
	struct node *n, *nx;
	struct rbtree *rbt0, *rbt;
	
	char *dnsname;
	int labellen;

	fprintf(of, "; this file is automatically generated, do NOT edit\n");
	fprintf(of, "; it was generated by dddctl.c\n");

	fprintf(of, "zone \"%s\" {\n", zonename);

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt0 = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
		return -1;
	}

	if (print_rbt(of, rbt0) < 0) {
		fprintf(stderr, "print_rbt error\n");
		return -1;
	}
	
	memset(&key, 0, sizeof(key));   
	memset(&data, 0, sizeof(data));

	j = 0;
	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		if (rbt->zonelen == rbt0->zonelen && 
			memcasecmp(rbt->zone, rbt0->zone, rbt->zonelen) == 0) {
			continue;
		}

		if (print_rbt(of, rbt) < 0) {
			fprintf(stderr, "print_rbt error\n");
			return -1;
		}

		j++;
	} 

	fprintf(of, "}\n");

#if DEBUG
	printf("%d records\n", j);
#endif
	return (0);
}

char *	
create_key(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
	case ALGORITHM_RSASHA256:
	case ALGORITHM_RSASHA512:
		return (create_key_rsa(zonename, ttl, flags, algorithm, bits, pid));
		break;
	case ALGORITHM_ECDSAP256SHA256:
		return (create_key_ec(zonename, ttl, flags, algorithm, bits, pid));
		break;
	default:
		dolog(LOG_INFO, "invalid algorithm in key\n");
		break;
	}

	return NULL;
}

char *	
create_key_ec(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	FILE *f;
	EC_KEY *eckey;
	EC_GROUP *ecgroup;
	const BIGNUM *ecprivatekey;
	const EC_POINT *ecpublickey;

	struct stat sb;

	char bin[4096];
	char b64[4096];
	char tmp[4096];
	char buf[512];
	char *retval;
	char *p;

	int binlen;
	int len;

	mode_t savemask;
	time_t now;
	struct tm *tm;

	if (algorithm != ALGORITHM_ECDSAP256SHA256) {
		return NULL;	
	}

	eckey = EC_KEY_new();
	if (eckey == NULL) {
		dolog(LOG_ERR, "EC_KEY_new(): %s\n", strerror(errno));
		return NULL;
	}

	ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecgroup == NULL) {
		dolog(LOG_ERR, "EC_GROUP_new_by_curve_name(): %s\n", strerror(errno));
		EC_KEY_free(eckey);
		return NULL;
	}

	if (EC_KEY_set_group(eckey, ecgroup) != 1) {
		dolog(LOG_ERR, "EC_KEY_set_group(): %s\n", strerror(errno));	
		goto out;
	}

	/* XXX create EC key here */
	if (EC_KEY_generate_key(eckey) == 0) {
		dolog(LOG_ERR, "EC_KEY_generate_key(): %s\n", strerror(errno));	
		goto out;
	}

	ecprivatekey = EC_KEY_get0_private_key(eckey);
	if (ecprivatekey == NULL) {
		dolog(LOG_INFO, "EC_KEY_get0_private_key(): %s\n", strerror(errno));
		goto out;
	}

	ecpublickey = EC_KEY_get0_public_key(eckey);
	if (ecpublickey == NULL) {
		dolog(LOG_ERR, "EC_KEY_get0_public_key(): %s\n", strerror(errno));
		goto out;
	}
		
	*pid = create_key_ec_getpid(eckey, ecgroup, (EC_POINT *)ecpublickey, algorithm, flags);
	if (*pid == -1) {
		dolog(LOG_ERR, "create_key_ec_getpid(): %s\n", strerror(errno));
		goto out;
	}

	/* check for collisions, XXX should be rare */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->pid == *pid)
			break;
	}
	
	if (knp != NULL) {
		dolog(LOG_INFO, "create_key: collision with existing pid %d\n", *pid);
		EC_GROUP_free(ecgroup);
		EC_KEY_free(eckey);
		return (create_key_ec(zonename, ttl, flags, algorithm, bits, pid));
	}

	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, *pid);

	retval = strdup(buf);
	if (retval == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		goto out;
	}
		
	snprintf(buf, sizeof(buf), "%s.private", retval);

	savemask = umask(077);

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		goto out;
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		goto out;
	}
	
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		goto out;
	}

	fprintf(f, "Private-key-format: v1.3\n");
	fprintf(f, "Algorithm: %d (%s)\n", algorithm, alg_to_name(algorithm));
	/* PrivateKey */
	binlen = BN_bn2bin(ecprivatekey, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "PrivateKey: %s\n", b64);

	now = time(NULL);
	tm = gmtime(&now);
	
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	fprintf(f, "Created: %s\n", buf);
	fprintf(f, "Publish: %s\n", buf);
	fprintf(f, "Activate: %s\n", buf);
	fclose(f);

	/* now for the EC public .key */

	snprintf(buf, sizeof(buf), "%s.key", retval);
	umask(savemask);

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		goto out;
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		goto out;
	}

	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		goto out;
	}
	
	fprintf(f, "; This is a %s key, keyid %u, for %s%s\n", (flags == 257) ? "key-signing" : "zone-signing", *pid, zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".");

	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	strftime(bin, sizeof(bin), "%c", tm);
	fprintf(f, "; Created: %s (%s)\n", buf, bin);
	fprintf(f, "; Publish: %s (%s)\n", buf, bin);
	fprintf(f, "; Activate: %s (%s)\n", buf, bin);

	if ((binlen = EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, tmp, sizeof(tmp), NULL)) == 0) {
		dolog(LOG_ERR, "EC_POINT_point2oct(): %s\n", strerror(errno));
		fclose(f);
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		goto out;
	}
	
	/*
	 * taken from PowerDNS's opensslsigners.cc, apparently to get to the
	 * real public key one has to take out a byte and reduce the length
	 */

	p = tmp;
	p++;
	binlen--;

	len = mybase64_encode(p, binlen, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);

	EC_GROUP_free(ecgroup);
	EC_KEY_free(eckey);
	
	return (retval);

out:
	EC_GROUP_free(ecgroup);
	EC_KEY_free(eckey);
	
	return NULL;
}

int
create_key_ec_getpid(EC_KEY *eckey, EC_GROUP *ecgroup, EC_POINT *ecpublickey, int algorithm, int flags)
{
	int binlen;
	char *tmp, *p, *q;
	char bin[4096];

	p = &bin[0];
	pack16(p, htons(flags));
	p += 2;
	pack8(p, 3);	/* protocol always 3 */
	p++;
 	pack8(p, algorithm);
	p++;

	binlen = EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);

	if (binlen == 0) {
		dolog(LOG_ERR, "EC_POINT_point2oct(): %s\n", strerror(errno));
		return -1;
	} 

	tmp = malloc(binlen);
	if (tmp == NULL) {
		dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
		return (-1);
	}

	if (EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, tmp, binlen, NULL) == 0) {
		dolog(LOG_ERR, "EC_POINT_point2oct(): %s\n", strerror(errno));
		return -1; 
	}

	q = tmp;
	q++;
	binlen--;
	
	pack(p, q, binlen);
	p += binlen;

	free(tmp);
	binlen = (p - &bin[0]);

	return (keytag(bin, binlen));
}

char *	
create_key_rsa(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	FILE *f;
        RSA *rsa;
        BIGNUM *e;
	BIGNUM *rsan, *rsae, *rsad, *rsap, *rsaq;
	BIGNUM *rsadmp1, *rsadmq1, *rsaiqmp;
        BN_GENCB *cb;
	char buf[512];
	char bin[4096];
	char b64[4096];
	char tmp[4096];
	int i, binlen, len;
	char *retval;
	char *p;
	time_t now;
	struct tm *tm;
	struct stat sb;
	mode_t savemask;
	int rlen;

	if ((rsa = RSA_new()) == NULL) {
		dolog(LOG_INFO, "RSA_new: %s\n", strerror(errno));
		return NULL;
	}

	if ((e = BN_new()) == NULL) {
		dolog(LOG_INFO, "BN_new: %s\n", strerror(errno));
		RSA_free(rsa);
		return NULL;
	}
	if ((rsan = BN_new()) == NULL ||
		(rsae = BN_new()) == NULL ||
		(rsad = BN_new()) == NULL ||
		(rsap = BN_new()) == NULL ||
		(rsaq = BN_new()) == NULL ||
		(rsadmp1 = BN_new()) == NULL ||
		(rsadmq1 = BN_new()) == NULL ||
		(rsaiqmp = BN_new()) == NULL) {
		dolog(LOG_INFO, "BN_new: %s\n", strerror(errno));
		RSA_free(rsa);
		return NULL;
	}
	
	if ((cb = BN_GENCB_new()) == NULL) {
		dolog(LOG_INFO, "BN_GENCB_new: %s\n", strerror(errno));
		RSA_free(rsa);
		return NULL;
	}

	for (i = 0; i < 32; i++) {
		if (RSA_F4 & (1 << i)) {
			BN_set_bit(e, i);
		}
	}

	BN_GENCB_set_old(cb, NULL, NULL);
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		break;
	case ALGORITHM_RSASHA256:
		break;
	case ALGORITHM_RSASHA512:
		break;
	default:
		dolog(LOG_INFO, "invalid algorithm in key\n");
		return NULL;
	}

	if (RSA_generate_key_ex(rsa, bits, e, cb) == 0) {
		dolog(LOG_INFO, "RSA_generate_key_ex: %s\n", strerror(errno));
		BN_free(e);
		RSA_free(rsa);
		BN_GENCB_free(cb);
		return NULL;
	}

	/* cb is not used again */
	BN_GENCB_free(cb);

	/* get the bignums for now hidden struct */
	RSA_get0_key(rsa, (const BIGNUM **)&rsan, (const BIGNUM **)&rsae, (const BIGNUM **)&rsad);

	/* get the keytag, this is a bit of a hard process */
	p = (char *)&bin[0];
	pack16(p, htons(flags));
	p+=2;
	pack8(p, 3);	/* protocol always 3 */
	p++;
 	pack8(p, algorithm);
	p++;
	binlen = BN_bn2bin(rsae, (char *)tmp); 
	/* RFC 3110 */
	if (binlen < 256) {
		*p = binlen;
		p++;
	} else {
		*p = 0;
		p++;
		pack16(p, htons(binlen));
		p += 2;
	}
	
	pack(p, tmp, binlen);
	p += binlen;
	binlen = BN_bn2bin(rsan, (char *)tmp);
	pack(p, tmp, binlen);
	p += binlen;
	rlen = (p - &bin[0]);
	*pid = keytag(bin, rlen);

	/* check for collisions, XXX should be rare */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->pid == *pid)
			break;
	}
	
	if (knp != NULL) {
		dolog(LOG_INFO, "create_key: collision with existing pid %d\n", *pid);
		RSA_free(rsa);
		BN_free(e);
		return (create_key_rsa(zonename, ttl, flags, algorithm, bits, pid));
	}
	
	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, *pid);

	retval = strdup(buf);
	if (retval == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
		
	snprintf(buf, sizeof(buf), "%s.private", retval);

	savemask = umask(077);

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
	
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}

	fprintf(f, "Private-key-format: v1.3\n");
	fprintf(f, "Algorithm: %d (%s)\n", algorithm, alg_to_name(algorithm));
	/* modulus */
	binlen = BN_bn2bin(rsan, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Modulus: %s\n", b64);
	/* public exponent */
	binlen = BN_bn2bin(rsae, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "PublicExponent: %s\n", b64);
	/* private exponent */
	binlen = BN_bn2bin(rsad, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "PrivateExponent: %s\n", b64);
	/* get the RSA factors */
	RSA_get0_factors(rsa, (const BIGNUM **)&rsap, (const BIGNUM **)&rsaq);
	/* prime1 */
	binlen = BN_bn2bin(rsap, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime1: %s\n", b64);
	/* prime2 */
	binlen = BN_bn2bin(rsaq, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime2: %s\n", b64);
	/* get the RSA crt params */
	RSA_get0_crt_params(rsa, (const BIGNUM **)&rsadmp1, (const BIGNUM **)&rsadmq1, (const BIGNUM **)&rsaiqmp);
	/* exponent1 */
	binlen = BN_bn2bin(rsadmp1, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent1: %s\n", b64);
	/* exponent2 */
	binlen = BN_bn2bin(rsadmq1, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent2: %s\n", b64);
	/* coefficient */
	binlen = BN_bn2bin(rsaiqmp, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Coefficient: %s\n", b64);

	now = time(NULL);
	tm = gmtime(&now);
	
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	fprintf(f, "Created: %s\n", buf);
	fprintf(f, "Publish: %s\n", buf);
	fprintf(f, "Activate: %s\n", buf);
	
	fclose(f);
	BN_free(e);

	/* now for the .key */

	
	snprintf(buf, sizeof(buf), "%s.key", retval);
	umask(savemask);

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		RSA_free(rsa);
		return NULL;
	}
	
	fprintf(f, "; This is a %s key, keyid %u, for %s%s\n", (flags == 257) ? "key-signing" : "zone-signing", *pid, zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".");

	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	strftime(bin, sizeof(bin), "%c", tm);
	fprintf(f, "; Created: %s (%s)\n", buf, bin);
	fprintf(f, "; Publish: %s (%s)\n", buf, bin);
	fprintf(f, "; Activate: %s (%s)\n", buf, bin);

	/* RFC 3110, section 2 */
	p = &bin[0];
	binlen = BN_bn2bin(rsae, (char *)tmp);
	if (binlen < 256) {
		*p = binlen;
		p++;
	} else {
		*p = 0;
		p++;
		pack16(p, htons(binlen));
		p += 2;
	}
	pack(p, tmp, binlen);
	p += binlen;
	binlen = BN_bn2bin(rsan, (char *)tmp);
	pack(p, tmp, binlen);
	p += binlen; 
	binlen = (p - &bin[0]);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);
	RSA_free(rsa);
	
	return (retval);
}

char *
alg_to_name(int algorithm)
{
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1: 
		return ("RSASHA1_NSEC3_SHA1");
		break;
	case ALGORITHM_RSASHA256:
		return ("RSASHA256");
		break;
	case ALGORITHM_RSASHA512:
		return ("RSASHA512");
		break;
	case ALGORITHM_ECDSAP256SHA256:
		return ("ECDSAP256SHA256");
		break;
	}

	return (NULL);
}

int
alg_to_rsa(int algorithm)
{
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		return (NID_sha1);
		break;
	case ALGORITHM_RSASHA256:
		return (NID_sha256);
		break;
	case ALGORITHM_RSASHA512:
		return (NID_sha512);
		break;
	}

	return (-1);
}

int
calculate_rrsigs(ddDB *db, char *zonename, int expiry, int rollmethod)
{
	struct node *n, *nx;
	struct rbtree *rbt;
	struct rrset *rrset = NULL;
	int j, rs;

	time_t now, twoweeksago; 
	char timebuf[32];
	struct tm *tm;

	/* set expiredon and signedon */

	now = time(NULL);
	twoweeksago = now - SIGNEDON_DRIFT;
	tm = gmtime(&twoweeksago);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	signedon = atoll(timebuf);
	now += expiry;
	tm = gmtime(&now);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	expiredon = atoll(timebuf);

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif

	j = 0;

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);
		
		if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
			if (sign_dnskey(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_dnskey error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
			if (notglue(db, rbt, zonename) && 
				sign_a(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_a error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
			if (sign_mx(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_mx error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
			if (sign_ns(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_ns error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
			if (sign_soa(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_soa error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
			if (sign_txt(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_txt error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
			/* find out if we're glue, if not sign */
			if (notglue(db, rbt, zonename) && 
				sign_aaaa(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_aaaa error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
			if (sign_nsec3(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_nsec3 error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
			if (sign_nsec3param(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_nsec3param error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
			if (sign_cname(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_cname error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
			if (sign_ptr(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_ptr error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
			if (sign_naptr(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_naptr error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
			if (sign_srv(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_srv error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
			if (sign_sshfp(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_sshfp error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
			if (sign_tlsa(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_tlsa error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
			if (sign_ds(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_ds error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
			if (sign_caa(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_caa error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
			if (sign_rp(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_rp error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
			if (sign_hinfo(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_hinfo error\n");
				return -1;
			}
		}

		j++;
	}
	
		
	return 0;
}

/*
 * create a RRSIG for an SOA record
 */

static int
sign_soa(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no SOA records but have rrset entry!\n");
				return -1;
			}
		} else  {
			dolog(LOG_INFO, "no SOA records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_SOA));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		pack(p, rbt->zone, rbt->zonelen);
		p += rbt->zonelen;
		pack16(p, htons(DNS_TYPE_SOA));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(((struct soa *)rrp->rdata)->nsserver_len + ((struct soa *)rrp->rdata)->rp_len + 4 + 4 + 4 + 4 + 4));
		p += 2;
		pack(p, ((struct soa *)rrp->rdata)->nsserver, ((struct soa *)rrp->rdata)->nsserver_len);
		p += ((struct soa *)rrp->rdata)->nsserver_len;
		pack(p, ((struct soa *)rrp->rdata)->responsible_person, ((struct soa *)rrp->rdata)->rp_len);
		p += ((struct soa *)rrp->rdata)->rp_len;
		pack32(p, htonl(((struct soa *)rrp->rdata)->serial));
		p += sizeof(u_int32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->refresh));
		p += sizeof(u_int32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->retry));
		p += sizeof(u_int32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->expire));
		p += sizeof(u_int32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->minttl));
		p += sizeof(u_int32_t);

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
		
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SOA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}

	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a TXT record
 */

static int
sign_txt(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL, *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey = NULL;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	TAILQ_HEAD(listhead, canonical) head;

 	struct canonical {
  		char *data;
  		int len;
  		TAILQ_ENTRY(canonical) entries;
 	} *c1, *c2, *cp;


 	TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no TXT records but have rrset entry!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no TXT records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_TXT));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += sizeof(u_int32_t);
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
  			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_TXT));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			/* the below uses rrp! because we can't have an rrsig differ */
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(((struct txt *)rrp2->rdata)->txtlen));
			q += 2;
			pack(q, (char *)((struct txt *)rrp2->rdata)->txt, ((struct txt *)rrp2->rdata)->txtlen);
			q += ((struct txt *)rrp2->rdata)->txtlen;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						 memcmp(c1->data, c2->data, c1->len) < 0)
						break;
			}

			if (c2 != NULL)
				TAILQ_INSERT_BEFORE(c2, c1, entries);
			else
				TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "TXT", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an AAAA record
 */
static int
sign_aaaa(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
	TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no AAAA records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no AAAA records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_AAAA));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_AAAA));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			/* the below uses rrp! because we can't have an rrsig differ */
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(sizeof(struct in6_addr)));
			q += 2;
			pack(q, (char *)&((struct aaaa *)rrp2->rdata)->aaaa, sizeof(struct in6_addr));
			q += sizeof(struct in6_addr);

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "AAAA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}

	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an NSEC3 record
 */

static int
sign_nsec3(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do { 
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no NSEC3 records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no NSEC3 records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_NSEC3));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		pack(p, rbt->zone, rbt->zonelen);
		p += rbt->zonelen;

		pack16(p, htons(DNS_TYPE_NSEC3));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(1 + 1 + 2 + 1 + ((struct nsec3 *)rrp->rdata)->saltlen + 1 + ((struct nsec3 *)rrp->rdata)->nextlen + ((struct nsec3 *)rrp->rdata)->bitmap_len));
		p += 2;
		pack8(p, ((struct nsec3 *)rrp->rdata)->algorithm);
		p++;
		pack8(p, ((struct nsec3 *)rrp->rdata)->flags);
		p++;
		pack16(p, htons(((struct nsec3 *)rrp->rdata)->iterations));
		p += 2;
		
		pack8(p, ((struct nsec3 *)rrp->rdata)->saltlen);
		p++;
			
		if (((struct nsec3 *)rrp->rdata)->saltlen) {
			pack(p, ((struct nsec3 *)rrp->rdata)->salt, ((struct nsec3 *)rrp->rdata)->saltlen);
			p += ((struct nsec3 *)rrp->rdata)->saltlen;
		} 
		
		pack8(p, ((struct nsec3 *)rrp->rdata)->nextlen);
		p++;
		pack(p, ((struct nsec3 *)rrp->rdata)->next, ((struct nsec3 *)rrp->rdata)->nextlen);
		p += ((struct nsec3 *)rrp->rdata)->nextlen;
		if (((struct nsec3 *)rrp->rdata)->bitmap_len) {
			pack(p, ((struct nsec3 *)rrp->rdata)->bitmap, ((struct nsec3 *)rrp->rdata)->bitmap_len);
			p += ((struct nsec3 *)rrp->rdata)->bitmap_len;
		}
		
		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NSEC3", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}


/*
 * create a RRSIG for an NSEC3PARAM record
 */

static int
sign_nsec3param(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no NSEC3PARAM records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no NSEC3PARAM records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_NSEC3PARAM));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		pack(p, rbt->zone, rbt->zonelen);
		p += rbt->zonelen;
		pack16(p, htons(DNS_TYPE_NSEC3PARAM));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(1 + 1 + 2 + 1 + ((struct nsec3param *)rrp->rdata)->saltlen));
		p += 2;
		pack8(p, ((struct nsec3param *)rrp->rdata)->algorithm);
		p++;
		pack8(p, ((struct nsec3param *)rrp->rdata)->flags);
		p++;
		pack16(p, htons(((struct nsec3param *)rrp->rdata)->iterations));
		p += 2;

		pack8(p, ((struct nsec3param *)rrp->rdata)->saltlen);
		p++;
			
		if (((struct nsec3param *)rrp->rdata)->saltlen) {
			pack(p, ((struct nsec3param *)rrp->rdata)->salt, ((struct nsec3param *)rrp->rdata)->saltlen);
			p += ((struct nsec3param *)rrp->rdata)->saltlen;
		} 

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", 0, "NSEC3PARAM", algorithm, labels, 0, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a CNAME record
 */

static int
sign_cname(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no CNAME records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no CNAME records\n");
			return -1;

		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_CNAME));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		pack(p, rbt->zone, rbt->zonelen);
		p += rbt->zonelen;
		pack16(p, htons(DNS_TYPE_CNAME));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(((struct cname *)rrp->rdata)->cnamelen));
		p += 2;
		pack(p, ((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen);
		p += ((struct cname *)rrp->rdata)->cnamelen;

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "CNAME", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an NS record
 */

static int
sign_ptr(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no PTR records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no PTR records\n");
			return -1;
		}
			
		
		p = key;

		pack16(p, htons(DNS_TYPE_PTR));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		pack(p, rbt->zone, rbt->zonelen);
		p += rbt->zonelen;
		pack16(p, htons(DNS_TYPE_PTR));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(((struct ptr *)rrp->rdata)->ptrlen));
		p += 2;
		pack(p, ((struct ptr *)rrp->rdata)->ptr, ((struct ptr *)rrp->rdata)->ptrlen);
		p += ((struct ptr *)rrp->rdata)->ptrlen;

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "PTR", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);

	return 0;
}

/*
 * create a RRSIG for a NAPTR record
 */

static int
sign_naptr(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no NAPTR records but have flags!\n");
				return -1;
			}
		} else {
				dolog(LOG_INFO, "no NAPTR records\n");
				return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_NAPTR));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_NAPTR));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + 2 + 1 + ((struct naptr *)rrp2->rdata)->flagslen + 1 + ((struct naptr *)rrp2->rdata)->serviceslen + 1 + ((struct naptr *)rrp2->rdata)->regexplen + ((struct naptr *)rrp2->rdata)->replacementlen));
			q += 2;
			pack16(q, htons(((struct naptr *)rrp2->rdata)->order));
			q += 2;
			pack16(q, htons(((struct naptr *)rrp2->rdata)->preference));
			q += 2;

			pack8(q, ((struct naptr *)rrp2->rdata)->flagslen);
			q++;
			pack(q, ((struct naptr *)rrp2->rdata)->flags, ((struct naptr *)rrp2->rdata)->flagslen);
			q += ((struct naptr *)rrp2->rdata)->flagslen;

			pack8(q, ((struct naptr *)rrp2->rdata)->serviceslen);
			q++;
			pack(q, ((struct naptr *)rrp2->rdata)->services, ((struct naptr *)rrp2->rdata)->serviceslen);
			q += ((struct naptr *)rrp2->rdata)->serviceslen;

			pack8(q, ((struct naptr *)rrp2->rdata)->regexplen);
			q++;
			pack(q, ((struct naptr *)rrp2->rdata)->regexp, ((struct naptr *)rrp2->rdata)->regexplen);
			q += ((struct naptr *)rrp2->rdata)->regexplen;

			pack(q, ((struct naptr *)rrp2->rdata)->replacement, ((struct naptr *)rrp2->rdata)->replacementlen);
			q += ((struct naptr *)rrp2->rdata)->replacementlen;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NAPTR", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a SRV record
 */

static int
sign_srv(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no SRV records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no SRV records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_SRV));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_SRV));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + 2 + 2 + ((struct srv *)rrp2->rdata)->targetlen));
			q += 2;
			pack16(q, htons(((struct srv *)rrp2->rdata)->priority));
			q += 2;
			pack16(q, htons(((struct srv *)rrp2->rdata)->weight));
			q += 2;
			pack16(q, htons(((struct srv *)rrp2->rdata)->port));
			q += 2;
			pack(q, ((struct srv *)rrp2->rdata)->target, ((struct srv *)rrp2->rdata)->targetlen);
			q += ((struct srv *)rrp2->rdata)->targetlen;
			
			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}

		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SRV", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}


/*
 * create a RRSIG for an SSHFP record
 */

static int
sign_sshfp(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no SSHFP records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no SSHFP records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_SSHFP));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_SSHFP));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(1 + 1 + ((struct sshfp *)rrp2->rdata)->fplen));
			q += 2;
			pack8(q, ((struct sshfp *)rrp2->rdata)->algorithm);
			q++;
			pack8(q, ((struct sshfp *)rrp2->rdata)->fptype);
			q++;
			pack(q, ((struct sshfp *)rrp2->rdata)->fingerprint, ((struct sshfp *)rrp2->rdata)->fplen);
			q += ((struct sshfp *)rrp2->rdata)->fplen;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len &&
						memcmp(c1->data, c2->data, c1->len) > 0)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SSHFP", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a TLSA record
 */

static int
sign_tlsa(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no TLSA records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no TLSA records\n");
			return -1;

		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_TLSA));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_TLSA));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(1 + 1 + 1 + ((struct tlsa *)rrp2->rdata)->datalen));
			q += 2;
			pack8(q, ((struct tlsa *)rrp2->rdata)->usage);
			q++;
			pack8(q, ((struct tlsa *)rrp2->rdata)->selector);
			q++;
			pack8(q, ((struct tlsa *)rrp2->rdata)->matchtype);
			q++;
			pack(q, ((struct tlsa *)rrp2->rdata)->data, ((struct tlsa *)rrp2->rdata)->datalen);
			q += ((struct tlsa *)rrp2->rdata)->datalen;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "TLSA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	
	} while ((*++zsk_key) != NULL);
	return 0;
}

static int
sign_rp(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no RP records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no RP records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_RP));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_RP));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(((struct rp *)rrp2->rdata)->mboxlen + ((struct rp *)rrp2->rdata)->txtlen));
			q += 2;

			pack(q, ((struct rp *)rrp2->rdata)->mbox, ((struct rp *)rrp2->rdata)->mboxlen);
			q += ((struct rp *)rrp2->rdata)->mboxlen;

			pack(q, ((struct rp *)rrp2->rdata)->txt, ((struct rp *)rrp2->rdata)->txtlen);
			q += ((struct rp *)rrp2->rdata)->txtlen;


		       c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif
	if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
		dolog(LOG_INFO, "signing failed\n");
		return -1;
	}

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "RP", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	} while ((*++zsk_key) != NULL);

	return 0;
}

static int
sign_hinfo(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no HINFO records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no HINFO records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_HINFO));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_HINFO));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + ((struct hinfo *)rrp2->rdata)->cpulen + ((struct hinfo *)rrp2->rdata)->oslen));
			q += 2;

			pack8(q, ((struct hinfo *)rrp2->rdata)->cpulen);
			q++;
			pack(q, ((struct hinfo *)rrp2->rdata)->cpu, ((struct hinfo *)rrp2->rdata)->cpulen);
			q += ((struct hinfo *)rrp2->rdata)->cpulen;

			pack8(q, ((struct hinfo *)rrp2->rdata)->oslen);
			q++;
			pack(q, ((struct hinfo *)rrp2->rdata)->os, ((struct hinfo *)rrp2->rdata)->oslen);
			q += ((struct hinfo *)rrp2->rdata)->oslen;


		       c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif
	if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
		dolog(LOG_INFO, "signing failed\n");
		return -1;
	}

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "HINFO", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	} while ((*++zsk_key) != NULL);

	return 0;
}

/*
 * create a RRSIG for an CAA record
 */

static int
sign_caa(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no CAA records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no CAA records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_CAA));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_CAA));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(1 + 1 + ((struct caa *)rrp2->rdata)->taglen + ((struct caa *)rrp2->rdata)->valuelen));
			q += 2;

			pack8(q, ((struct caa *)rrp2->rdata)->flags);
			q++;
			pack8(q, ((struct caa *)rrp2->rdata)->taglen);
			q++;
			pack(q, ((struct caa *)rrp2->rdata)->tag, ((struct caa *)rrp2->rdata)->taglen);
			q += ((struct caa *)rrp2->rdata)->taglen;

			pack(q, ((struct caa *)rrp2->rdata)->value, ((struct caa *)rrp2->rdata)->valuelen);
			q += ((struct caa *)rrp2->rdata)->valuelen;


		       c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif
	if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
		dolog(LOG_INFO, "signing failed\n");
		return -1;
	}

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "CAA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	} while ((*++zsk_key) != NULL);

	return 0;
}

/*
 * create a RRSIG for an DS record
 */

static int
sign_ds(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}
	
	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no DS records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no DS records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_DS));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_DS));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + 1 + 1 + ((struct ds *)rrp2->rdata)->digestlen));
			q += 2;
			pack16(q, htons(((struct ds *)rrp2->rdata)->key_tag));
			q += 2;
			pack8(q, ((struct ds *)rrp2->rdata)->algorithm);
			q++;
			pack8(q, ((struct ds *)rrp2->rdata)->digest_type);
			q++;
			pack(q, ((struct ds *)rrp2->rdata)->digest, ((struct ds *)rrp2->rdata)->digestlen);
			q += ((struct ds *)rrp2->rdata)->digestlen;

		       c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif
	if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
		dolog(LOG_INFO, "signing failed\n");
		return -1;
	}

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "DS", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	} while ((*++zsk_key) != NULL);

	return 0;
}


/*
 * create a RRSIG for an NS record
 */
static int
sign_ns(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no NS records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no NS records\n");
			return -1;

		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_NS));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_NS));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(((struct ns *)rrp2->rdata)->nslen));
			q += 2;
			memcpy(q, ((struct ns *)rrp2->rdata)->nsserver, ((struct ns *)rrp2->rdata)->nslen);
			q += ((struct ns *)rrp2->rdata)->nslen;

		       c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}
		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NS", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an MX record
 */

static int
sign_mx(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no MX records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no MX records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_MX));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_MX));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + ((struct smx *)rrp2->rdata)->exchangelen));
			q += 2;
			pack16(q, htons(((struct smx *)rrp2->rdata)->preference));
			q += 2;
			memcpy(q, ((struct smx *)rrp2->rdata)->exchange, ((struct smx *)rrp2->rdata)->exchangelen);
			q += ((struct smx *)rrp2->rdata)->exchangelen;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}
		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "MX", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}


/*
 * create a RRSIG for an A record
 */

static int
sign_a(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}

	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->type == KEYTYPE_ZSK && rollmethod == \
			ROLLOVER_METHOD_DOUBLE_SIGNATURE) || \
			(knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* get the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}

		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no A records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no A records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_A));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		/* XXX this should probably be done on a canonical sorted records */
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_A));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(sizeof(in_addr_t)));
			q += 2;
			pack32(q, ((struct a *)rrp2->rdata)->a);
			q += 4;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			memcpy(c1->data, tmpkey, c1->len);

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->len < c2->len)
						break;
					else if (c2->len == c1->len &&
						memcmp(c1->data, c2->data, c1->len) < 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			TAILQ_REMOVE(&head, c2, entries);
		}
		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);	
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "A", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

int
create_ds(ddDB *db, char *zonename, struct keysentry *ksk_key)
{
	FILE *f;

	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct stat sb;

	char *mytmp;
	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int keylen;
	int bufsize;
	int labels;
	static int pass = 0;

	/* silently ignore zsk's, no error here */
	if (knp->type != KEYTYPE_KSK)
		return 0;

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL) {
		dolog(LOG_INFO, "dnsname == NULL\n");
		return -1;
	}

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
		dolog(LOG_INFO, "rbt == NULL\n");
		return -1;
	}


	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}

	keylen = 0;

	/* get the KSK */
	if ((zone = get_key(ksk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", knp->keyname);
		return -1;
	}

	/* check the keytag supplied */
	p = key;
	pack16(p, htons(flags));
	p += 2;
	pack8(p, protocol);
	p++;
	pack8(p, algorithm);
	p++;
	keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
	pack(p, signature, keylen);
	p += keylen;
	keylen = (p - key);
	if (keyid != keytag(key, keylen)) {
		dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
		return -1;
	}
	
	labels = label_count(rbt->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == NULL) {
			dolog(LOG_INFO, "no ds!\n");
			return -1;
		}
	} 
	
	keylen = (p - key);	

	/* work out the digest */

	p = key;
	pack(p, rbt->zone, rbt->zonelen);
	p += rbt->zonelen;
	pack16(p, htons(flags));
	p += 2;
	pack8(p, protocol);
	p++;
	pack8(p, algorithm);
	p++;
	keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
	pack(p, signature, keylen);
	p += keylen;
	
	keylen = (p - key);

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, key, keylen);
	SHA1_Final((u_char *)shabuf, &sha1);
	bufsize = 20;

	mytmp = bin2hex(shabuf, bufsize);
	if (mytmp == NULL) {
		dolog(LOG_INFO, "bin2hex shabuf\n");
		return -1;
	}
		
	for (p = mytmp; *p; p++) {
		*p = toupper(*p);
	}
	
	snprintf(buf, sizeof(buf), "dsset-%s", convert_name(rbt->zone, rbt->zonelen));

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		return -1;
	}

	/* remove the file at first pass */
	if (pass++ == 0)
		unlink(buf);

	f = fopen(buf, "a");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen dsset\n");
		return -1;
	}

	fprintf(f, "%s\t\tIN DS %u %d 1 %s\n", convert_name(rbt->zone, rbt->zonelen), keyid, algorithm, mytmp);


	SHA256_Init(&sha256);
	SHA256_Update(&sha256, key, keylen);
	SHA256_Final((u_char *)shabuf, &sha256);
	bufsize = 32;

	mytmp = bin2hex(shabuf, bufsize);
	if (mytmp == NULL) {
		dolog(LOG_INFO, "bin2hex shabuf\n");
		return -1;
	}
	
	for (p = mytmp; *p; p++) {
		*p = toupper(*p);
	}

	fprintf(f, "%s\t\tIN DS %u %d 2 %s\n", convert_name(rbt->zone, rbt->zonelen), keyid, algorithm, mytmp);

	fclose(f);

	return 0;
}

/* 
 * From RFC 4034, appendix b 
 */

static int
sign_dnskey(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int nzk = 0;
	int labellen;
	int keyid;
	int len;
	int keylen, siglen = sizeof(signature);
	int labels;


	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	TAILQ_HEAD(listhead, canonical) head;

	struct canonical {
		char *data;
		int len;
		char *rdata;
		int rdatalen;
		int pid;
		TAILQ_ENTRY(canonical) entries;
	} *c1, *c2, *cp;
		

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}
		
	TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
		return -1;
	}

	/* get the KSK */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->type == KEYTYPE_KSK) {
			if ((zone = get_key(knp, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
				dolog(LOG_INFO, "get_key %s\n", knp->keyname);
				return -1;
			}

			/* check the keytag supplied */
			p = key;
			pack16(p, htons(flags));
			p += 2;
			pack8(p, protocol);
			p++;
			pack8(p, algorithm);
			p++;
			keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
			pack(p, signature, keylen);
			p += keylen;
			keylen = (p - key);
			if (keyid != keytag(key, keylen)) {
				dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
				return -1;
			}
			
			labels = label_count(rbt->zone);
			if (labels < 0) {
				dolog(LOG_INFO, "label_count");
				return -1;
			}

			dnsname = dns_label(zonename, &labellen);
			if (dnsname == NULL)
				return -1;

			if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
				rrp = TAILQ_FIRST(&rrset->rr_head);
				if (rrp == NULL) {
					dolog(LOG_INFO, "no dnskeys in apex!\n");
					return -1;
				}
			} else {
				dolog(LOG_INFO, "no dnskeys\n");
				return -1;
			}
			
			p = key;

			pack16(p, htons(DNS_TYPE_DNSKEY));
			p += 2;
			pack8(p, algorithm);
			p++;
			pack8(p, labels);
			p++;
			pack32(p, htonl(rrset->ttl));
			p += 4;
				
			snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);

			pack32(p, htonl(expiredon2));
			p += 4;
			pack32(p, htonl(signedon2));	
			p += 4;
			pack16(p, htons(keyid));
			p += 2;
			pack(p, dnsname, labellen);
			p += labellen;

			/* no signature here */	
			
			TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
				q = tmpkey;
				pack(q, dnsname, labellen);
				q += labellen;
				pack16(q, htons(DNS_TYPE_DNSKEY));
				q += 2;
				pack16(q, htons(DNS_CLASS_IN));
				q += 2;
				pack32(q, htonl(rrset->ttl));
				q += 4;
				pack16(q, htons(2 + 1 + 1 + ((struct dnskey *)rrp2->rdata)->publickey_len));
				q += 2;
				pack16(q, htons(((struct dnskey *)rrp2->rdata)->flags));
				q += 2;
				pack8(q, ((struct dnskey *)rrp2->rdata)->protocol);
				q++;
				pack8(q, ((struct dnskey *)rrp2->rdata)->algorithm);
				q++;
				pack(q, ((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len);
				q += ((struct dnskey *)rrp2->rdata)->publickey_len;

				c1 = malloc(sizeof(struct canonical));
				if (c1 == NULL) {
					dolog(LOG_INFO, "c1 out of memory\n");
					return -1;
				}

				c1->len = (q - tmpkey);
				c1->data = malloc(c1->len);
				if (c1->data == NULL) {
					dolog(LOG_INFO, "c1->data out of memory\n");
					return -1;
				}
			
				memcpy(c1->data, tmpkey, c1->len);

				c1->rdata = dnskey_wire_rdata(rrp2, &c1->rdatalen);
				if (c1->rdata == NULL) {
					dolog(LOG_INFO, "c1->rdata out of memory\n");
					return -1;
				}

				if (TAILQ_EMPTY(&head))
					TAILQ_INSERT_TAIL(&head, c1, entries);
				else {
					TAILQ_FOREACH(c2, &head, entries) {
						if (c1->rdatalen < c2->rdatalen && 	
							memcmp(c1->rdata, c2->rdata, c1->rdatalen) <= 0)
							break;
						else if (c1->rdatalen > c2->rdatalen &&
							memcmp(c1->rdata, c2->rdata, c2->rdatalen) <= 0)
							break;
						else if (c2->rdatalen == c1->rdatalen &&
							memcmp(c1->rdata, c2->rdata, c1->rdatalen) <= 0)
							break;
					}

					if (c2 != NULL) 
						TAILQ_INSERT_BEFORE(c2, c1, entries);
					else
						TAILQ_INSERT_TAIL(&head, c1, entries);
				}

			}

			TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
				pack(p, c2->data, c2->len);
				p += c2->len;

				free(c2->rdata);
				free(c2->data);

				TAILQ_REMOVE(&head, c2, entries);
			}
			keylen = (p - key);	

		#if 0
			debug_bindump(key, keylen);
		#endif

			if (sign(algorithm, key, keylen, knp, (char *)&signature, &siglen) < 0) {
				dolog(LOG_INFO, "signing failed\n");
				return -1;
			}

			len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
			tmp[len] = '\0';

			if (fill_rrsig(db, rbt->humanname, "RRSIG", ttl, "DNSKEY", algorithm, labels, 		ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
				dolog(LOG_INFO, "fill_rrsig\n");
				return -1;
			}

		} /* if KSK */
	} /* SLIST_FOREACH */


	nzk = 0;
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if ((knp->sign == 1 && knp->type == KEYTYPE_ZSK)) {
				zsk_key[nzk++] = knp;
		}
	}

	zsk_key[nzk] = NULL;

	/* now work out the ZSK */
	do {
		if ((zone = get_key(*zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
			dolog(LOG_INFO, "get_key %s\n", (*zsk_key)->keyname);
			return -1;
		}
		/* check the keytag supplied */
		p = key;
		pack16(p, htons(flags));
		p += 2;
		pack8(p, protocol);
		p++;
		pack8(p, algorithm);
		p++;
		keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (p - key);
		if (keyid != keytag(key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
			return -1;
		}
		
		labels = label_count(rbt->zone);
		if (labels < 0) {
			dolog(LOG_INFO, "label_count");
			return -1;
		}

		dnsname = dns_label(zonename, &labellen);
		if (dnsname == NULL)
			return -1;

		if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no dnskeys in apex!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no dnskeys\n");
			return -1;
		}
			
		
		p = key;

		pack16(p, htons(DNS_TYPE_DNSKEY));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
#if 0
			/* if we're a zone key (zsk) and the keytag doesn't match exlude it */
			if ((((struct dnskey *)rrp2->rdata)->flags == 256) && keyid != dnskey_keytag((struct dnskey *)rrp2->rdata)) {
					dolog(LOG_INFO, "skipping key %u\n", dnskey_keytag((struct dnskey *)rrp2->rdata));
					continue;
			}
#endif

			q = tmpkey;
			pack(q, dnsname, labellen);
			q += labellen;
			pack16(q, htons(DNS_TYPE_DNSKEY));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + 1 + 1 + ((struct dnskey *)rrp2->rdata)->publickey_len));
			q += 2;
			pack16(q, htons(((struct dnskey *)rrp2->rdata)->flags));
			q += 2;
			pack8(q, ((struct dnskey *)rrp2->rdata)->protocol);
			q++;
			pack8(q, ((struct dnskey *)rrp2->rdata)->algorithm);
			q++;
			pack(q, ((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len);
			q += ((struct dnskey *)rrp2->rdata)->publickey_len;

			c1 = malloc(sizeof(struct canonical));
			if (c1 == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			c1->len = (q - tmpkey);
			c1->data = malloc(c1->len);
			if (c1->data == NULL) {
				dolog(LOG_INFO, "c1->data out of memory\n");
				return -1;
			}

			c1->pid = dnskey_keytag((struct dnskey *)rrp2->rdata);

			memcpy(c1->data, tmpkey, c1->len);

			c1->rdata = dnskey_wire_rdata(rrp2, &c1->rdatalen);
			if (c1->rdata == NULL) {
				dolog(LOG_INFO, "c1->rdata out of memory\n");
				return -1;
			}

			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, c1, entries);
			else {
				TAILQ_FOREACH(c2, &head, entries) {
					if (c1->rdatalen < c2->rdatalen && 	
						memcmp(c1->rdata, c2->rdata, c1->rdatalen) <= 0)
						break;
					else if (c1->rdatalen > c2->rdatalen &&
						memcmp(c1->rdata, c2->rdata, c2->rdatalen) <= 0)
						break;
					else if (c2->rdatalen == c1->rdatalen &&
						memcmp(c1->rdata, c2->rdata, c1->rdatalen) <= 0)
						break;
				}

				if (c2 != NULL)
					TAILQ_INSERT_BEFORE(c2, c1, entries);
				else
					TAILQ_INSERT_TAIL(&head, c1, entries);
			}
		}

		TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
			pack(p, c2->data, c2->len);
			p += c2->len;

			free(c2->rdata);
			free(c2->data);

			TAILQ_REMOVE(&head, c2, entries);
		}

		keylen = (p - key);	

	#if 0
		debug_bindump(key, keylen);
	#endif

		siglen = sizeof(signature);
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", ttl, "DNSKEY", algorithm, labels, 			ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/* 
 * From RFC 4034, appendix b 
 */

u_int 
keytag(u_char *key, u_int keysize)
{
	u_long ac;
	int i;
	
	for (ac = 0, i = 0; i < keysize; ++i)
		ac += (i & 1) ? key[i] : key[i] << 8;
	ac += (ac >> 16) & 0xffff;
	
	return ac & 0xffff;
}


u_int
dnskey_keytag(struct dnskey *dnskey)
{
	char *key;
	int keylen;
	char *p;
	u_int ret;
	
	key = calloc(10 * 4096, 1);
	if (key == NULL)
		return 0;

	/* check the keytag supplied */
	p = key;
	pack16(p, htons(dnskey->flags));
	p += 2;
	pack8(p, dnskey->protocol);
	p++;
	pack8(p, dnskey->algorithm);
	p++;
	pack(p, dnskey->public_key, dnskey->publickey_len);
	p += dnskey->publickey_len;
	keylen = (p - key);

	ret = keytag(key, keylen);
	free(key);
	
	return (ret);
}


void
free_private_key(struct keysentry *kn)
{
	if (kn->algorithm < 13) {
		/* RSA */
		BN_clear_free(kn->rsan);
		BN_clear_free(kn->rsae);
		BN_clear_free(kn->rsad);
		BN_clear_free(kn->rsap);
		BN_clear_free(kn->rsaq);
		BN_clear_free(kn->rsadmp1);
		BN_clear_free(kn->rsadmq1);
		BN_clear_free(kn->rsaiqmp);
	} else {
		/* EC */
		BN_clear_free(kn->ecprivate);
	}

	return;
}

RSA *
get_private_key_rsa(struct keysentry *kn)
{
	RSA *rsa;

	BIGNUM *rsan;
	BIGNUM *rsae;
	BIGNUM *rsad;
	BIGNUM *rsap;
	BIGNUM *rsaq;
	BIGNUM *rsadmp1;
	BIGNUM *rsadmq1;
	BIGNUM *rsaiqmp;

	rsa = RSA_new();
	if (rsa == NULL) {
		dolog(LOG_INFO, "RSA creation\n");
		return NULL;
	}

	if ( 	(rsan = BN_dup(kn->rsan)) == NULL ||
		(rsae = BN_dup(kn->rsae)) == NULL ||
		(rsad = BN_dup(kn->rsad)) == NULL ||
		(rsap = BN_dup(kn->rsap)) == NULL ||
		(rsaq = BN_dup(kn->rsaq)) == NULL ||
		(rsadmp1 = BN_dup(kn->rsadmp1)) == NULL ||
		(rsadmq1 = BN_dup(kn->rsadmq1)) == NULL ||
		(rsaiqmp = BN_dup(kn->rsaiqmp)) == NULL) {
		dolog(LOG_INFO, "BN_dup\n");
		return NULL;
	}

	if (RSA_set0_key(rsa, rsan, rsae, rsad) == 0 ||
		RSA_set0_factors(rsa, rsap, rsaq) == 0 ||
		RSA_set0_crt_params(rsa, rsadmp1, rsadmq1, rsaiqmp) == 0) {
		dolog(LOG_INFO, "RSA_set0_* failed\n");
		return NULL;
	}

	return (rsa);
}

EC_KEY *
get_private_key_ec(struct keysentry *kn)
{
	EC_KEY *eckey;
	EC_GROUP *ecgroup;

	const EC_POINT *ecpoint = NULL;
	const BIGNUM *ecprivate;
	BN_CTX *bn_ctx = NULL;

	eckey = EC_KEY_new();
	if (eckey == NULL) {
		dolog(LOG_INFO, "EC creation\n");
		return NULL;
	}

	
	if ((ecprivate = BN_dup(kn->ecprivate)) == NULL) {
		dolog(LOG_INFO, "BN_dup\n");
		goto out;
	}


	ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecgroup == NULL) {
		dolog(LOG_ERR, "EC_GROUP_new_by_curve_name(): %s\n", strerror(errno));
		goto out;
	}

	if (EC_KEY_set_group(eckey, ecgroup) != 1) {
		dolog(LOG_ERR, "EC_KEY_set_group(): %s\n", strerror(errno));	
		EC_GROUP_free(ecgroup);
		goto out;
	}

	if (EC_KEY_set_private_key(eckey, ecprivate) != 1) {
		dolog(LOG_INFO, "EC_KEY_set_private_key failed\n");
		EC_GROUP_free(ecgroup);
		goto out;
	}

	ecpoint = EC_POINT_new(ecgroup);
	if (ecpoint == NULL) {
		dolog(LOG_ERR, "EC_POINT_new(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(ecgroup);
		goto out;
	}

	if (EC_POINT_mul(ecgroup, (EC_POINT *)ecpoint, ecprivate, NULL, NULL, bn_ctx) != 1) {
		dolog(LOG_ERR, "EC_POINT_mul(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(ecgroup);
		goto out;
	}

	if (EC_KEY_set_public_key(eckey, ecpoint) != 1) { 
		dolog(LOG_ERR, "EC_KEY_set_public_key(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(ecgroup);
		goto out;
	}

	return (eckey);	

out:
	EC_KEY_free(eckey);
	return NULL;
}

int
store_private_key(struct keysentry *kn, char *zonename, int keyid, int algorithm)
{
	FILE *f;

	char buf[4096];
	char key[4096];
	char *p, *q;

	int keylen;

	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d.private", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, keyid);

	f = fopen(buf, "r");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		return -1;
	}
		
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if ((p = strstr(buf, "Private-key-format: ")) != NULL) {
			p += 20;
			if (strncmp(p, "v1.3", 4) != 0) {
				dolog(LOG_INFO, "wrong private key version %s", p);
				return -1;
			}	
		} else if ((p = strstr(buf, "Algorithm: ")) != NULL) {
			p += 11;

			q = strchr(p, ' ');
			if (q == NULL) {
				dolog(LOG_INFO, "bad parse of private key 1\n");
				return -1;
			}
			*q = '\0';
	
			if (algorithm != atoi(p)) {
				dolog(LOG_INFO, "ZSK .key and .private file do not agree on algorithm %d\n", atoi(p));
				return -1;
			}
		} else if ((p = strstr(buf, "Modulus: ")) != NULL) {
			p += 9;
	
			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsan = BN_bin2bn(key, keylen, NULL)) == NULL)  {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PublicExponent: ")) != NULL) {
			p += 16;	

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsae = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PrivateExponent: ")) != NULL) {
			p += 17;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsad = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Prime1: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsap = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Prime2: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsaq = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Exponent1: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsadmp1 = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Exponent2: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsadmq1 = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Coefficient: ")) != NULL) {
			p += 13;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->rsaiqmp = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PrivateKey: ")) != NULL) {
			p += 12;

			if (algorithm != ALGORITHM_ECDSAP256SHA256) {
				dolog(LOG_INFO, "got PrivateKey in keyfile, but not on algorithm 13!\n");
				return -1;
			}

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((kn->ecprivate = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return -1;
			}
		}
	
	} /* fgets */

	fclose(f);


#if __OpenBSD__
	explicit_bzero(buf, sizeof(buf));
	explicit_bzero(key, sizeof(key));
#else
	memset(buf, 0, sizeof(buf));
	memset(key, 0, sizeof(key));
#endif

	return 0;
	
}


int
construct_nsec3(ddDB *db, char *zone, int iterations, char *salt)
{
	struct node *n, *nx;

	struct nsec3param n3p;

	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;

	char buf[4096];
	char bitmap[4096];
	char *dnsname;
	char *hashname = NULL;
	char *p;

	int labellen;
	u_int32_t ttl = 0;

	int j, rs, len, rootlen;

	TAILQ_HEAD(listhead, mynsec3) head;

	struct mynsec3 {
		char *hashname;
		char *bitmap;
		TAILQ_ENTRY(mynsec3) entries;
	} *n1, *n2, *np;
		
		
	TAILQ_INIT(&head);

	/* fill nsec3param */
	
	if (fill_nsec3param(db, zone, "nsec3param", 0, 1, 0, iterations, salt) < 0) {
		printf("fill_nsec3param failed\n");
		return -1;
	}

	dnsname = dns_label(zone, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_NSEC3PARAM, 0)) == NULL) {
		return -1;
	}

	/* get the rootzone's len */
	rootlen = rbt->zonelen;

	rrset = find_rr(rbt, DNS_TYPE_SOA);
	if (rrset == NULL)
		return -1;
	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		return -1;

	/* RFC 5155 page 3 */
	ttl = rrset->ttl;

	
	rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM);
	if (rrset == NULL)
		return -1;
	rrp2 = TAILQ_FIRST(&rrset->rr_head);
	if (rrp2 == NULL)
		return -1;

	memset((char *)&n3p, 0, sizeof(n3p));

	n3p.algorithm = 1;	/* still in conformance with above */
	n3p.flags = 0;
	n3p.iterations = ((struct nsec3param *)rrp2->rdata)->iterations;
	n3p.saltlen = ((struct nsec3param *)rrp2->rdata)->saltlen;
	memcpy((char *)&n3p.salt, ((struct nsec3param *)rrp2->rdata)->salt, 
			((struct nsec3param *)rrp2->rdata)->saltlen);

	j = 0;

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		hashname = hash_name(rbt->zone, rbt->zonelen, &n3p);
		if (hashname == NULL) {
			dolog(LOG_INFO, "hash_name return NULL");
			return -1;
		}
		
		/* if we're a glue record, skip */
		if (! notglue(db, rbt, zone))
			continue;

		bitmap[0] = '\0';
		if (find_rr(rbt, DNS_TYPE_A) != NULL)
			strlcat(bitmap, "A ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_NS) != NULL)
			strlcat(bitmap, "NS ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_CNAME) != NULL)
			strlcat(bitmap, "CNAME ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SOA) != NULL)
			strlcat(bitmap, "SOA ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_PTR) != NULL)
			strlcat(bitmap, "PTR ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_MX) != NULL)
			strlcat(bitmap, "MX ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_TXT) != NULL)
			strlcat(bitmap, "TXT ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_AAAA) != NULL)
			strlcat(bitmap, "AAAA ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SRV) != NULL)
			strlcat(bitmap, "SRV ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_NAPTR) != NULL)
			strlcat(bitmap, "NAPTR ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_DS) != NULL)
			strlcat(bitmap, "DS ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SSHFP) != NULL)
			strlcat(bitmap, "SSHFP ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_RP) != NULL)
			strlcat(bitmap, "RP ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_HINFO) != NULL)
			strlcat(bitmap, "HINFO ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_CAA) != NULL)
			strlcat(bitmap, "CAA ", sizeof(bitmap));	

		/* they all have RRSIG */
		strlcat(bitmap, "RRSIG ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_DNSKEY) != NULL)
			strlcat(bitmap, "DNSKEY ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NSEC3) != NULL)
			strlcat(bitmap, "NSEC3 ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM) != NULL)
			strlcat(bitmap, "NSEC3PARAM ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_TLSA) != NULL)
			strlcat(bitmap, "TLSA ", sizeof(bitmap));	

#if 0
		printf("%s %s\n", buf, bitmap);
#endif

		n1 = calloc(1, sizeof(struct mynsec3));
		if (n1 == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}
		
		n1->hashname = strdup(hashname);
		n1->bitmap = strdup(bitmap);	
		if (n1->hashname == NULL || n1->bitmap == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}
	
		if (TAILQ_EMPTY(&head))
			TAILQ_INSERT_TAIL(&head, n1, entries);
		else {
			TAILQ_FOREACH(n2, &head, entries) {
				if (strcmp(n1->hashname, n2->hashname) < 0)
					break;
			}

			if (n2 != NULL) 
				TAILQ_INSERT_BEFORE(n2, n1, entries);
			else
				TAILQ_INSERT_TAIL(&head, n1, entries);
		}

	}  /* RB_FOREACH_SAFE */

	/* check ENT's which we'll create */

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		len = rbt->zonelen;
		for (p = rbt->zone; *p && len > rootlen; p++, len--) {
			if (check_ent(p, len))
				break;
			
			len -= *p;
			p += *p;
		}

		if (len > rootlen) {
			/* we have an ENT */
			hashname = hash_name(p, len, &n3p);
			if (hashname == NULL) {
				dolog(LOG_INFO, "hash_name return NULL");
				return -1;
			}
			
			bitmap[0] = '\0';

			n1 = calloc(1, sizeof(struct mynsec3));
			if (n1 == NULL) {
				dolog(LOG_INFO, "out of memory");
				return -1;
			}
			
			n1->hashname = strdup(hashname);
			n1->bitmap = strdup(bitmap);	
			if (n1->hashname == NULL || n1->bitmap == NULL) {
				dolog(LOG_INFO, "out of memory");
				return -1;
			}
		
			if (TAILQ_EMPTY(&head))
				TAILQ_INSERT_TAIL(&head, n1, entries);
			else {
				TAILQ_FOREACH(n2, &head, entries) {
					if (strcmp(n1->hashname, n2->hashname) < 0)
						break;
				}

				if (n2 != NULL) 
					TAILQ_INSERT_BEFORE(n2, n1, entries);
				else
					TAILQ_INSERT_TAIL(&head, n1, entries);
			}

		} /* if len > rootlen */


	} /* RB_FOREACH_SAFE */


	TAILQ_FOREACH(n2, &head, entries) {
		np = TAILQ_NEXT(n2, entries);
		if (np == NULL)
			np = TAILQ_FIRST(&head);

		/*
		 * Below can happen for example when 2+ ENT's exist in the
		 * same zonefile ie. _465._tcp.mail.tld, _25._tcp.mail.tld..
		 * where they get sorted beside each other and thus have the
		 * same hash, just skip those.  Funny thing is that it did
		 * not get found when struct domain's were still used.. odd.
		 */
		if (strcmp(n2->hashname, np->hashname) == 0)
			continue;
#if 0
		printf("%s next: %s %s\n", n2->hashname, np->hashname, n2->bitmap);
#endif
		snprintf(buf, sizeof(buf), "%s.%s.", n2->hashname, zone);
		fill_nsec3(db, buf, "nsec3", ttl, n3p.algorithm, n3p.flags, n3p.iterations, salt, np->hashname, n2->bitmap);
	}

#if 0
	printf("%d records\n", j);
#endif
	
	return 0;
}


int
print_rbt(FILE *of, struct rbtree *rbt)
{
	int i, x, len;

	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;

	char buf[4096];

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no soa in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,soa,%d,%s,%s,%u,%d,%d,%d,%d\n", 
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl, 
			convert_name(((struct soa *)rrp->rdata)->nsserver, ((struct soa *)rrp->rdata)->nsserver_len),
			convert_name(((struct soa *)rrp->rdata)->responsible_person, ((struct soa *)rrp->rdata)->rp_len),
			((struct soa *)rrp->rdata)->serial, 
			((struct soa *)rrp->rdata)->refresh, 
			((struct soa *)rrp->rdata)->retry, 
			((struct soa *)rrp->rdata)->expire, 
			((struct soa *)rrp->rdata)->minttl);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ns in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,ns,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				convert_name(((struct ns *)rrp2->rdata)->nsserver, ((struct ns *)rrp2->rdata)->nslen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no mx in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,mx,%d,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct smx *)rrp2->rdata)->preference,
				convert_name(((struct smx *)rrp2->rdata)->exchange, ((struct smx *)rrp2->rdata)->exchangelen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ds in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,ds,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct ds *)rrp2->rdata)->key_tag,
				((struct ds *)rrp2->rdata)->algorithm,
				((struct ds *)rrp2->rdata)->digest_type,
				bin2hex(((struct ds *)rrp2->rdata)->digest, ((struct ds *)rrp2->rdata)->digestlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no cname in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,cname,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				convert_name(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,naptr,%d,%d,%d,\"", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct naptr *)rrp2->rdata)->order,
				((struct naptr *)rrp2->rdata)->preference);
			
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->flagslen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->flags[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->serviceslen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->services[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->regexplen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->regexp[x]);
			}
			fprintf(of, "\",%s\n", (((struct naptr *)rrp2->rdata)->replacement[0] == '\0') ? "." : convert_name(((struct naptr *)rrp2->rdata)->replacement, ((struct naptr *)rrp2->rdata)->replacementlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no txt in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,txt,%d,\"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl);

			for (i = 0; i < ((struct txt *)rrp2->rdata)->txtlen; i++) {
				if (i % 256 == 0)
					continue;

				fprintf(of, "%c", ((struct txt *)rrp2->rdata)->txt[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,ptr,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				convert_name(((struct ptr *)rrp->rdata)->ptr, ((struct ptr *)rrp->rdata)->ptrlen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,srv,%d,%d,%d,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct srv *)rrp2->rdata)->priority,
				((struct srv *)rrp2->rdata)->weight,
				((struct srv *)rrp2->rdata)->port,
				convert_name(((struct srv *)rrp2->rdata)->target,((struct srv *)rrp2->rdata)->targetlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,tlsa,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct tlsa *)rrp2->rdata)->usage,
				((struct tlsa *)rrp2->rdata)->selector,
				((struct tlsa *)rrp2->rdata)->matchtype,
				bin2hex(((struct tlsa *)rrp2->rdata)->data, ((struct tlsa *)rrp2->rdata)->datalen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,sshfp,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct sshfp *)rrp2->rdata)->algorithm,
				((struct sshfp *)rrp2->rdata)->fptype,
				bin2hex(((struct sshfp *)rrp2->rdata)->fingerprint, ((struct sshfp *)rrp2->rdata)->fplen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			inet_ntop(AF_INET, &((struct a *)rrp2->rdata)->a, buf, sizeof(buf));
			fprintf(of, "  %s,a,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no hinfo in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,rp,%d,%s,%s\n", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					convert_name(((struct rp *)rrp2->rdata)->mbox, ((struct rp *)rrp2->rdata)->mboxlen),
					convert_name(((struct rp *)rrp2->rdata)->txt, ((struct rp *)rrp2->rdata)->txtlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no hinfo in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,caa,%d,%d,", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					((struct caa *)rrp2->rdata)->flags);

			for (i = 0; i < ((struct caa *)rrp2->rdata)->taglen; i++) {
				fprintf(of, "%c", ((struct caa *)rrp2->rdata)->tag[i]);
			}
			fprintf(of, ",\"");
			for (i = 0; i < ((struct caa *)rrp2->rdata)->valuelen; i++) {
				fprintf(of, "%c", ((struct caa *)rrp2->rdata)->value[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no hinfo in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,hinfo,%d,\"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl);

			for (i = 0; i < ((struct hinfo *)rrp2->rdata)->cpulen; i++) {
				fprintf(of, "%c", ((struct hinfo *)rrp2->rdata)->cpu[i]);
			}
			fprintf(of, "\",\"");
			for (i = 0; i < ((struct hinfo *)rrp2->rdata)->oslen; i++) {
				fprintf(of, "%c", ((struct hinfo *)rrp2->rdata)->os[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no aaaa in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			inet_ntop(AF_INET6, &((struct aaaa *)rrp2->rdata)->aaaa, buf, sizeof(buf));
			fprintf(of, "  %s,aaaa,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode(((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "  %s,dnskey,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct dnskey *)rrp2->rdata)->flags,
				((struct dnskey *)rrp2->rdata)->protocol,
				((struct dnskey *)rrp2->rdata)->algorithm,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}

		fprintf(of, "  %s,nsec3param,0,%d,%d,%d,\"%s\"\n",
			convert_name(rbt->zone, rbt->zonelen),
			((struct nsec3param *)rrp->rdata)->algorithm,
			((struct nsec3param *)rrp->rdata)->flags,
			((struct nsec3param *)rrp->rdata)->iterations,
			(((struct nsec3param *)rrp->rdata)->saltlen == 0) ? "-" : bin2hex(((struct nsec3param *)rrp->rdata)->salt, ((struct nsec3param *)rrp->rdata)->saltlen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec3,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\"\n",
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl,
			((struct nsec3 *)rrp->rdata)->algorithm, 
			((struct nsec3 *)rrp->rdata)->flags,
			((struct nsec3 *)rrp->rdata)->iterations,
			(((struct nsec3 *)rrp->rdata)->saltlen == 0) ? "-" : bin2hex(((struct nsec3 *)rrp->rdata)->salt, ((struct nsec3 *)rrp->rdata)->saltlen),
			base32hex_encode(((struct nsec3 *)rrp->rdata)->next, ((struct nsec3 *)rrp->rdata)->nextlen),
			bitmap2human(((struct nsec3 *)rrp->rdata)->bitmap, ((struct nsec3 *)rrp->rdata)->bitmap_len));

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode(((struct rrsig *)rrp2->rdata)->signature, ((struct rrsig *)rrp2->rdata)->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				((struct rrsig *)rrp2->rdata)->ttl, 
				
				get_dns_type(((struct rrsig *)rrp2->rdata)->type_covered, 0), 
				((struct rrsig *)rrp2->rdata)->algorithm, 
				((struct rrsig *)rrp2->rdata)->labels,
				((struct rrsig *)rrp2->rdata)->original_ttl, 
				timethuman(((struct rrsig *)rrp2->rdata)->signature_expiration),
				timethuman(((struct rrsig *)rrp2->rdata)->signature_inception), 
				((struct rrsig *)rrp2->rdata)->key_tag,
				convert_name(((struct rrsig *)rrp2->rdata)->signers_name, ((struct rrsig *)rrp2->rdata)->signame_len),
				buf);	
		}
	}

	return 0;
}

/*
 * INIT_KEYS - initialize the dnskeys singly linked list
 */

void
init_keys(void)
{
        SLIST_INIT(&keyshead);
        return;
}

uint32_t
getkeypid(char *key)
{
	char tmp[4096];

	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	int keyid;

	if ((zone = key2zone(key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, &keyid)) == NULL) {
		dolog(LOG_INFO, "key2zone\n");
		return -1;
	}

	return (keyid);
}


char *
get_key(struct keysentry *kn, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int keylen, int *keyid)
{
	pack32((char *)ttl, kn->ttl);
	pack16((char *)flags, kn->flags);
	*protocol = kn->protocol;
	*algorithm = kn->algorithm;
	pack32((char *)keyid, kn->keyid);
	
	strlcpy(key, kn->key, keylen);
	
	return (kn->zone);
}

char *
key2zone(char *keyname, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int *keyid)
{
	int fd;
	char *zone;
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s.key", keyname);
	if ((fd = open(buf, O_RDONLY, 0)) < 0) {
		dolog(LOG_INFO, "open %s: %s\n", buf, strerror(errno));
		return NULL;
	}

	if ((zone = parse_keyfile(fd, ttl, flags, protocol, algorithm, key, keyid)) == NULL) {
		dolog(LOG_INFO, "parse %s\n", buf);
		close (fd);
		return NULL;
	}

	close(fd);

	return (zone);
}

void
debug_bindump(const char *key, int keylen)
{
	int fd, i;

	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (const void *)&key[i], 1);
	}
	close(fd);
	
	return;
}

/* carelessly copied from https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

int 
RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

int 
RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

int 
RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

void 
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void 
RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void 
RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

BN_GENCB *
BN_GENCB_new(void) 
{
	static BN_GENCB cb;

	return (&cb);
}

void
BN_GENCB_free(BN_GENCB *cb)
{
	return;
}


#endif


/*
 * sign() - sign an RR
 */

int
sign(int algorithm, char *key, int keylen, struct keysentry *key_entry, char *signature, int *siglen)
{
	RSA *rsa;
	EC_KEY *eckey;

	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char shabuf[64];
	int bufsize;
	int rsatype;

	ECDSA_SIG *tmpsig;
	const BIGNUM *r = NULL, *s = NULL;

	char buf[512];
	int buflen;
	
	/* digest */
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
	case ALGORITHM_ECDSAP256SHA256:
		/* FALLTHROUGH */
	case ALGORITHM_RSASHA256:	
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, key, keylen);
		SHA256_Final((u_char *)shabuf, &sha256);
		bufsize = 32;
		break;
	case ALGORITHM_RSASHA512:
		SHA512_Init(&sha512);
		SHA512_Update(&sha512, key, keylen);
		SHA512_Final((u_char *)shabuf, &sha512);
		bufsize = 64;
		break;
	default:
		dolog(LOG_INFO, "algorithm not supported\n");
		return -1;
	}

	/* sign */
	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
	case ALGORITHM_RSASHA256:	
	case ALGORITHM_RSASHA512:
		rsa = get_private_key_rsa(key_entry);
		if (rsa == NULL) {
			dolog(LOG_INFO, "reading private key failed\n");
			return -1;
		}
			
		rsatype = alg_to_rsa(algorithm);
		if (rsatype == -1) {
			dolog(LOG_INFO, "algorithm mismatch\n");
			RSA_free(rsa);
			return -1;
		}

		if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, siglen, rsa) != 1) {
			dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (RSA_verify(rsatype, (u_char*)shabuf, bufsize, (u_char*)signature, *siglen, rsa) != 1) {
			dolog(LOG_INFO, "unable to verify with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
			
		RSA_free(rsa);
		break;

	case ALGORITHM_ECDSAP256SHA256:
		eckey = get_private_key_ec(key_entry);
		if (eckey == NULL) {
			dolog(LOG_INFO, "reading EC private key failed\n");
			return -1;
		}

			
		if ((tmpsig = ECDSA_do_sign(shabuf, bufsize, eckey)) == NULL) {
			dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			EC_KEY_free(eckey);
			return -1;
		}

		if (ECDSA_do_verify(shabuf, bufsize, (const ECDSA_SIG *)tmpsig, eckey) != 1) {
			dolog(LOG_INFO, "unable to verify signature with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			EC_KEY_free(eckey);
			ECDSA_SIG_free(tmpsig);
			return -1;
		}

		ECDSA_SIG_get0(tmpsig, &r, &s);

		/*
		 * taken from PowerDNS's opensslsigners.cc, apparently a
		 * signature's r and s must be pre-padded with 0x0 if the
		 * size of r or s is less than full 32 bytes.
		 */

		memset(signature, 0, *siglen);

		buflen = BN_bn2bin(r, buf);
		memcpy((char *)&signature[32 - buflen], buf, buflen);

		buflen = BN_bn2bin(s, buf);
		memcpy((char *)&signature[64 - buflen], buf, buflen);
		*siglen = 64;

		ECDSA_SIG_free(tmpsig);
		EC_KEY_free(eckey);
		break;

	default:
		dolog(LOG_INFO, "algorithm not supported\n");
		return -1;
	}

	return 0;
}

int
notglue(ddDB *db, struct rbtree *rbt, char *zonename)
{
	struct rbtree *rbt0;
	char *zoneapex, *p;
	int apexlen, len;
	

	zoneapex = dns_label(zonename, &apexlen);
	if (zoneapex == NULL) {	
		dolog(LOG_INFO, "can't get dns_label() to work\n");
		return 0;
	}

	if (rbt->zonelen == apexlen && 
		memcasecmp(rbt->zone, zoneapex, rbt->zonelen) == 0) {
		free(zoneapex);
		/* we aren't glue */
		return 1;
	}

	p = rbt->zone;
	len = rbt->zonelen;	

	do {
		len -= (*p + 1);
		p += (*p + 1);
		
		if (*p == '\0')
			break;

		if ((rbt0 = Lookup_zone(db, p, len, DNS_TYPE_NS, 0)) == NULL) {
			continue;
		}

		if (len > apexlen && find_rr(rbt0, DNS_TYPE_NS) != NULL) {
			free(zoneapex);
			return 0;
		}
		

	} while (*p && len > 0 && ! (len == apexlen && memcasecmp(p, zoneapex, len) == 0));
		

	free(zoneapex);
	/* let's pretend we're not glue here */
	return 1;
}

/*
 * DNSKEY_WIRE_RDATA - create wire representation of the RDATA portion of an RR
 */

char *
dnskey_wire_rdata(struct rr *rr, int *outlen)
{
	char *tmp = NULL, *p;

	*outlen = sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) \
		+ ((struct dnskey *)rr->rdata)->publickey_len;

	tmp = malloc(*outlen);
	if (tmp == NULL)
		return NULL;
		
	p = tmp;
	pack16(p, htons(((struct dnskey *)rr->rdata)->flags));
	p += 2;
	
	pack8(p, ((struct dnskey *)rr->rdata)->protocol);
	p++;

	pack8(p, ((struct dnskey *)rr->rdata)->algorithm);
	p++;

	pack(p, ((struct dnskey *)rr->rdata)->public_key,
		((struct dnskey *)rr->rdata)->publickey_len);

	return (tmp);
}

void
update_soa_serial(ddDB *db, char *zonename, time_t serial)
{
	char *dnsname;
	int labellen;
	struct rbtree *rbt0 = NULL;

	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;


	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return;

	if ((rbt0 = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
		return;
	}

	if ((rrset = find_rr(rbt0, DNS_TYPE_SOA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			return;
		}

		((struct soa *)rrp->rdata)->serial = serial;
	}


}
