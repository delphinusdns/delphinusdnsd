/* 
 * Copyright (c) 2016-2019 Peter J. Philipp
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
 * $Id: dddctl.c,v 1.42 2019/02/08 15:00:10 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-config.h"

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>


int debug = 0;
int verbose = 0;
static struct timeval tv0;
static time_t current_time;
static int bytes_received, answers;

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

	/* private key */
	BIGNUM *rsan;
	BIGNUM *rsae;
	BIGNUM *rsad;
	BIGNUM *rsap;
	BIGNUM *rsaq;
	BIGNUM *rsadmp1;
	BIGNUM *rsadmq1;
	BIGNUM *rsaiqmp;

        SLIST_ENTRY(keysentry) keys_entry;
} *kn, *knp;


/* prototypes */

void	dolog(int pri, char *fmt, ...);
int	add_dnskey(ddDB *);
char * 	parse_keyfile(int, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  key2zone(char *, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  get_key(struct keysentry *,uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int, int *);
char *	create_key(char *, int, int, int, int, uint32_t *);
int 	dump_db(ddDB *, FILE *, char *);
int	dump_db_bind(ddDB*, FILE *, char *);
char * 	alg_to_name(int);
int 	alg_to_rsa(int);
int 	construct_nsec3(ddDB *, char *, int, char *);
int 	calculate_rrsigs(ddDB *, char *, int);
int	sign_dnskey(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_a(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_mx(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_ns(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_srv(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_cname(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	sign_soa(ddDB *, char *, struct keysentry  *, int, struct domain *);
int	sign_txt(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_aaaa(ddDB *, char *, struct keysentry  *, int, struct domain *);
int	sign_ptr(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_nsec3(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_nsec3param(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_naptr(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_sshfp(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_tlsa(ddDB *, char *, struct keysentry *, int, struct domain *);
int	sign_ds(ddDB *, char *, struct keysentry *, int, struct domain *);
int 	create_ds(ddDB *, char *, struct keysentry *);
u_int 	keytag(u_char *key, u_int keysize);
void 	pack(char *, char *, int);
void 	pack32(char *, u_int32_t);
void 	pack16(char *, u_int16_t);
void 	pack8(char *, u_int8_t);
void	free_private_key(struct keysentry *);
RSA * 	get_private_key(struct keysentry *);
int	store_private_key(struct keysentry *, char *, int, int);
u_int64_t timethuman(time_t);
char * 	bitmap2human(char *, int);
char * 	bin2hex(char *, int);
int 	print_sd(FILE *, struct domain *);
int 	print_sd_bind(FILE *, struct domain *);
int	usage(int argc, char *argv[]);
int	start(int argc, char *argv[]);
int	restart(int argc, char *argv[]);
int	stop(int argc, char *argv[]);
int	signmain(int argc, char *argv[]);
int	dig(int argc, char *argv[]);
int	configtest(int argc, char *argv[]);
int	bindfile(int argc, char *argv[]);
int	sshfp(int argc, char *argv[]);
void 	init_keys(void);
uint32_t getkeypid(char *);
pid_t 	getdaemonpid(void);
void	debug_bindump(const char *, int);
int	command_socket(char *);
int 	connect_server(char *, int, u_int32_t);
int 	lookup_name(FILE *, int, char *, u_int16_t, struct soa *, u_int32_t, char *, u_int16_t);
int	lookup_axfr(FILE *, int, char *, struct soa *, u_int32_t);

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


struct _mycmdtab {
	char *var;
	int (*cmd)(int, char **);
} mycmdtab[] = {
	{ "bindfile", bindfile },
	{ "configtest", configtest },
	{ "query", dig },
	{ "help", usage },
	{ "sign", signmain },
	{ "sshfp", sshfp },
	{ "start", start },
	{ "stop", stop},
	{ "restart", restart },
	{ NULL, NULL }
};


#define KEYTYPE_NONE	0
#define KEYTYPE_KSK 	1
#define KEYTYPE_ZSK	2

#define SCHEME_OFF	0
#define SCHEME_YYYY	1
#define SCHEME_TSTAMP	2

#define ALGORITHM_RSASHA1_NSEC3_SHA1 7 		/* rfc 5155 */
#define ALGORITHM_RSASHA256	8		/* rfc 5702 */
#define ALGORITHM_RSASHA512	10		/* rfc 5702 */

#define RSA_F5			0x100000001

#define PROVIDED_SIGNTIME			0
#define	SIGNEDON				20161230073133
#define EXPIREDON 				20170228073133

#define SIGNEDON_DRIFT				(14 * 86400)
#define DEFAULT_EXPIRYTIME			(60 * 86400)

#define DEFAULT_TTL				3600
#define DEFAULT_BITS				2048

/* define masks */

#define MASK_PARSE_BINDFILE		0x1
#define MASK_PARSE_FILE			0x2
#define MASK_ADD_DNSKEY			0x4
#define MASK_CONSTRUCT_NSEC3		0x8
#define MASK_CALCULATE_RRSIGS		0x10
#define MASK_CREATE_DS			0x20
#define MASK_DUMP_DB			0x40
#define MASK_DUMP_BIND			0x80

/* glue */
int insert_axfr(char *, char *);
int insert_region(char *, char *);
int insert_filter(char *, char *);
int insert_whitelist(char *, char *);
int insert_notifyslave(char *, char *);

int *ptr = NULL;
int notify = 0;
int whitelist = 0;
int bcount = 0;
char *bind_list[255];
char *interface_list[255];
int bflag = 0;
int ratelimit_packets_per_second = 0;
int ratelimit = 0;
u_int16_t port = 53;
int nflag = 0;
int iflag = 0;
int lflag = 0;
int icount = 0;
int vslen = 0;
char *versionstring = NULL;
u_int64_t expiredon, signedon;

/* externs */

extern int fill_dnskey(char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);
extern int fill_rrsig(char *, char *, u_int32_t, char *, u_int8_t, u_int8_t, u_int32_t, u_int64_t, u_int64_t, u_int16_t, char *, char *);
extern int fill_nsec3param(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *);
extern int fill_nsec3(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *, char *, char *);
extern char * convert_name(char *name, int namelen);

extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);
extern struct domain *         lookup_zone(ddDB *, struct question *, int *, int *, char *);
extern struct question         *build_fake_question(char *, int, u_int16_t);
extern char * dns_label(char *, int *);
extern void * find_substruct(struct domain *, u_int16_t);
extern int label_count(char *);
extern char *get_dns_type(int, int);
extern char * hash_name(char *, int, struct nsec3param *);
extern char * base32hex_encode(u_char *input, int len);
extern int  	init_entlist(ddDB *);
extern int	check_ent(char *, int);
extern struct question          *build_question(char *, int, int);
extern int                      free_question(struct question *);
struct rrtab    *rrlookup(char *);


extern int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
extern u_int16_t raxfr_skip(FILE *, u_char *, u_char *);
extern int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, u_int32_t);
extern int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, u_int16_t *, u_int32_t);

extern int dnssec;

extern int domaincmp(struct node *e1, struct node *e2);
RB_HEAD(domaintree, node) rbhead;
RB_GENERATE_STATIC(domaintree, node, rbentry, domaincmp)


static struct raxfr_logic {
	int rrtype;
	int dnssec;
	int (*raxfr)(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
} supported[] = {
	{ DNS_TYPE_A, 0, raxfr_a },
	{ DNS_TYPE_NS, 0, raxfr_ns },
	{ DNS_TYPE_MX, 0, raxfr_mx },
	{ DNS_TYPE_PTR, 0, raxfr_ptr },
	{ DNS_TYPE_AAAA, 0, raxfr_aaaa },
	{ DNS_TYPE_CNAME, 0, raxfr_cname },
	{ DNS_TYPE_TXT, 0, raxfr_txt },
	{ DNS_TYPE_DNSKEY, 1, raxfr_dnskey },
	{ DNS_TYPE_RRSIG, 1, raxfr_rrsig },
	{ DNS_TYPE_NSEC3PARAM, 1, raxfr_nsec3param },
	{ DNS_TYPE_NSEC3, 1, raxfr_nsec3 },
	{ DNS_TYPE_DS, 1, raxfr_ds },
	{ DNS_TYPE_SSHFP, 0, raxfr_sshfp },
	{ DNS_TYPE_TLSA, 0, raxfr_tlsa },
	{ DNS_TYPE_SRV, 0, raxfr_srv },
	{ DNS_TYPE_NAPTR, 0, raxfr_naptr },
	{ 0, 0, NULL }
};


int
main(int argc, char *argv[])
{
	struct _mycmdtab *pctab;

	if (argc == 1) {
		usage(argc, argv);
		exit(1);
	}
	
	for (pctab = &mycmdtab[0]; pctab->var; pctab++) {
		if (strcmp((char *)pctab->var, argv[1]) == 0) {
			argc--; argv++;
			dnssec = 1;
			exit(pctab->cmd(argc, argv));
		}
	}

	usage(argc, argv);
	exit(1);
}

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
	int algorithm = ALGORITHM_RSASHA256;
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
       	char *key_zone;
        uint32_t key_ttl;
        uint16_t key_flags;
        uint8_t key_protocol;
        uint8_t key_algorithm;
        int key_keyid;
	
	ddDB *db;

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif


	while ((ch = getopt(argc, argv, "a:B:e:hI:i:Kk:m:n:o:S:s:t:vZz:")) != -1) {
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

	if (zonefile == NULL || zonename == NULL) {
		fprintf(stderr, "must provide a zonefile and a zonename!\n");
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


	if (ksk_key == 0 || zsk_key == 0) {
		dolog(LOG_INFO, "must specify both a ksk and a zsk key! or -z -k\n");
		exit(1);
	}

	/* check what keys we sign or not */
	if (numkeys > 3) {
		dolog(LOG_INFO, "can't roll-over more than 1 key at a time! numkeys > 3\n");
		exit(1);
	} else if (numkeys == 2) {
		SLIST_FOREACH(knp, &keyshead, keys_entry) {
			knp->sign = 1;
		}
	} else {
		if (pid == -1) {
			fprintf(stderr, "you specified three keys, please select one for signing (with -S pid)!\n");
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
		
	if ((mask & MASK_PARSE_FILE) && parse_file(db, zonefile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		exit(1);
	}

	/* create ENT list */
	if (init_entlist(db) < 0) {
		dolog(LOG_INFO, "creating entlist failed\n");
		exit(1);
	}

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

	if ((mask & MASK_CALCULATE_RRSIGS) && calculate_rrsigs(db, zonename, expiry) < 0) {
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
insert_axfr(char *address, char *prefixlen)
{
	return 0;
}

int
insert_region(char *address, char *prefixlen)
{
	return 0;
}

int
insert_filter(char *address, char *prefixlen)
{
	return 0;
}

int
insert_whitelist(char *address, char *prefixlen)
{
	return 0;
}

int
insert_notifyslave(char *address, char *prefixlen)
{
	return 0;
}




/*
 * dolog() - is a wrapper to syslog and printf depending on debug flag
 *
 */

void 
dolog(int pri, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	/*
	 * if the message is a debug message and verbose (-v) is set
	 *  then print it, otherwise 
	 */

	if (pri <= LOG_INFO) {
		vprintf(fmt, ap);
	}	
	
	va_end(ap);

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
			if (fill_dnskey(zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
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
			if (fill_dnskey(zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
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
				*keyid = atoi(p);
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
	struct question *q;
	struct domain *sdomain;
	
	char replystring[512];
	char *dnsname;
	int labellen;
	int lzerrno, retval;

	fprintf(of, "; this file is automatically generated, do NOT edit\n");
	fprintf(of, "; it was generated by dddctl.c\n");

	fprintf(of, "zone \"%s\" {\n", zonename);

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_SOA);
	if (q == NULL) {
		return -1;
	}

	if ((sdomain = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	if (print_sd(of, sdomain) < 0) {
		fprintf(stderr, "print_sd error\n");
		return -1;
	}
	
	memset(&key, 0, sizeof(key));   
	memset(&data, 0, sizeof(data));

	j = 0;
	RB_FOREACH_SAFE(n, domaintree, &rbhead, nx) {
		rs = n->datalen;
		if ((sdomain = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sdomain, (char *)n->data, n->datalen);

		if (strcmp(sdomain->zonename, zonename) == 0)
			continue;

		if (print_sd(of, sdomain) < 0) {
			fprintf(stderr, "print_sd error\n");
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
		return (create_key(zonename, ttl, flags, algorithm, bits, pid));
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
	case ALGORITHM_RSASHA256:
		return ("RSASHA256");
		break;
	case ALGORITHM_RSASHA512:
		return ("RSASHA512");
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
calculate_rrsigs(ddDB *db, char *zonename, int expiry)
{
	struct keysentry *zsk_key = NULL;
	struct node *n, *nx;
	struct domain *sd;
	int j, rs;

	time_t now, twoweeksago; 
	char timebuf[32];
	struct tm *tm;

	/* set ZSK key, there can be only two set max */
	
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->sign == 1 && knp->type == KEYTYPE_ZSK)
			zsk_key = knp;
	}

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

	RB_FOREACH_SAFE(n, domaintree, &rbhead, nx) {
		rs = n->datalen;
		if ((sd = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sd, (char *)n->data, n->datalen);
		
		if (sd->flags & DOMAIN_HAVE_DNSKEY)
			if (sign_dnskey(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_dnskey error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_A)
			if (sign_a(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_a error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_MX)
			if (sign_mx(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_mx error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NS)
			if (sign_ns(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ns error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SOA)
			if (sign_soa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_soa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_TXT)
			if (sign_txt(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_txt error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_AAAA)
			if (sign_aaaa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_aaaa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NSEC3) 
			if (sign_nsec3(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_nsec3 error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM)
			if (sign_nsec3param(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_nsec3param error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_CNAME)
			if (sign_cname(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_cname error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_PTR)
			if (sign_ptr(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ptr error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NAPTR)
			if (sign_naptr(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_naptr error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SRV)
			if (sign_srv(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_srv error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SSHFP)
			if (sign_sshfp(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_sshfp error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_TLSA)
			if (sign_tlsa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_tlsa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_DS)
			if (sign_ds(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ds error\n");
				return -1;
			}

		j++;
	}
	
		
	return 0;
}

/*
 * create a RRSIG for an SOA record
 */

int
sign_soa(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_soa *sdsoa = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SOA) {
                if ((sdsoa = (struct domain_soa *)find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL) {
			dolog(LOG_INFO, "no SOA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SOA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SOA]));
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
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_SOA));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SOA]));
	p += 4;
	pack16(p, htons(sdsoa->soa.nsserver_len + sdsoa->soa.rp_len + 4 + 4 + 4 + 4 + 4));
	p += 2;
	pack(p, sdsoa->soa.nsserver, sdsoa->soa.nsserver_len);
	p += sdsoa->soa.nsserver_len;
	pack(p, sdsoa->soa.responsible_person, sdsoa->soa.rp_len);
	p += sdsoa->soa.rp_len;
	pack32(p, htonl(sdsoa->soa.serial));
	p += 4;
	pack32(p, htonl(sdsoa->soa.refresh));
	p += 4;
	pack32(p, htonl(sdsoa->soa.retry));
	p += 4;
	pack32(p, htonl(sdsoa->soa.expire));
	p += 4;
	pack32(p, htonl(sdsoa->soa.minttl));
	p += 4;

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
	
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SOA], "SOA", algorithm, labels, sd->ttl[INTERNAL_TYPE_SOA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a TXT record
 */

int
sign_txt(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_txt *sdtxt = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_TXT) {
                if ((sdtxt = (struct domain_txt *)find_substruct(sd, INTERNAL_TYPE_TXT)) == NULL) {
			dolog(LOG_INFO, "no TXT records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_TXT));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TXT]));
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

	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_TXT));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TXT]));
	p += 4;
	pack16(p, htons(sdtxt->txtlen + 1));
	p += 2;
	pack8(p, sdtxt->txtlen);
	p++;
	pack(p, sdtxt->txt, sdtxt->txtlen);
	p += sdtxt->txtlen;

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_TXT], "TXT", algorithm, labels, sd->ttl[INTERNAL_TYPE_TXT], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an AAAA record
 */

int
sign_aaaa(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_aaaa *sdaaaa = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_AAAA) {
                if ((sdaaaa = (struct domain_aaaa *)find_substruct(sd, INTERNAL_TYPE_AAAA)) == NULL) {
			dolog(LOG_INFO, "no AAAA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_AAAA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_AAAA]));
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
	
	for (i = 0; i < sdaaaa->aaaa_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_AAAA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_AAAA]));
		q += 4;
		pack16(q, htons(sizeof(struct in6_addr)));
		q += 2;
		pack(q, (char *)&sdaaaa->aaaa[i], sizeof(struct in6_addr));
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

#ifdef __linux__
	TAILQ_FOREACH(c2, &head, entries) {
#else
	TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_AAAA], "AAAA", algorithm, labels, sd->ttl[INTERNAL_TYPE_AAAA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an NSEC3 record
 */

int
sign_nsec3(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_nsec3 *sdnsec3 = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NSEC3) {
                if ((sdnsec3 = (struct domain_nsec3 *)find_substruct(sd, INTERNAL_TYPE_NSEC3)) == NULL) {
			dolog(LOG_INFO, "no NSEC3 records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NSEC3));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3]));
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
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;

	pack16(p, htons(DNS_TYPE_NSEC3));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3]));
	p += 4;
	pack16(p, htons(1 + 1 + 2 + 1 + sdnsec3->nsec3.saltlen + 1 + sdnsec3->nsec3.nextlen + sdnsec3->nsec3.bitmap_len));
	p += 2;
	pack8(p, sdnsec3->nsec3.algorithm);
	p++;
	pack8(p, sdnsec3->nsec3.flags);
	p++;
	pack16(p, htons(sdnsec3->nsec3.iterations));
	p += 2;
	
	pack8(p, sdnsec3->nsec3.saltlen);
	p++;
		
	if (sdnsec3->nsec3.saltlen) {
		pack(p, sdnsec3->nsec3.salt, sdnsec3->nsec3.saltlen);
		p += sdnsec3->nsec3.saltlen;
	} 
	
	pack8(p, sdnsec3->nsec3.nextlen);
	p++;
	pack(p, sdnsec3->nsec3.next, sdnsec3->nsec3.nextlen);
	p += sdnsec3->nsec3.nextlen;
	pack(p, sdnsec3->nsec3.bitmap, sdnsec3->nsec3.bitmap_len);
	p += sdnsec3->nsec3.bitmap_len;
	
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NSEC3], "NSEC3", algorithm, labels, sd->ttl[INTERNAL_TYPE_NSEC3], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an NSEC3PARAM record
 */

int
sign_nsec3param(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_nsec3param *sdnsec3 = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
                if ((sdnsec3 = (struct domain_nsec3param *)find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
			dolog(LOG_INFO, "no NSEC3PARAM records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NSEC3PARAM));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3PARAM]));
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
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_NSEC3PARAM));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3PARAM]));
	p += 4;
	pack16(p, htons(1 + 1 + 2 + 1 + sdnsec3->nsec3param.saltlen));
	p += 2;
	pack8(p, sdnsec3->nsec3param.algorithm);
	p++;
	pack8(p, sdnsec3->nsec3param.flags);
	p++;
	pack16(p, htons(sdnsec3->nsec3param.iterations));
	p += 2;

	pack8(p, sdnsec3->nsec3param.saltlen);
	p++;
		
	if (sdnsec3->nsec3param.saltlen) {
		pack(p, sdnsec3->nsec3param.salt, sdnsec3->nsec3param.saltlen);
		p += sdnsec3->nsec3param.saltlen;
	} 

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", 0, "NSEC3PARAM", algorithm, labels, 0, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a CNAME record
 */

int
sign_cname(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_cname *sdc = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_CNAME) {
                if ((sdc = (struct domain_cname *)find_substruct(sd, INTERNAL_TYPE_CNAME)) == NULL) {
			dolog(LOG_INFO, "no CNAME records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_CNAME));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_CNAME]));
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
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_CNAME));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_CNAME]));
	p += 4;
	pack16(p, htons(sdc->cnamelen));
	p += 2;
	pack(p, sdc->cname, sdc->cnamelen);
	p += sdc->cnamelen;

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_CNAME], "CNAME", algorithm, labels, sd->ttl[INTERNAL_TYPE_CNAME], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an NS record
 */

int
sign_ptr(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ptr *sdptr = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

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
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_PTR) {
                if ((sdptr = (struct domain_ptr *)find_substruct(sd, INTERNAL_TYPE_PTR)) == NULL) {
			dolog(LOG_INFO, "no PTR records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_PTR));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_PTR]));
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
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_PTR));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_PTR]));
	p += 4;
	pack16(p, htons(sdptr->ptrlen));
	p += 2;
	pack(p, sdptr->ptr, sdptr->ptrlen);
	p += sdptr->ptrlen;

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_PTR], "PTR", algorithm, labels, sd->ttl[INTERNAL_TYPE_PTR], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a NAPTR record
 */

int
sign_naptr(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_naptr *sdnaptr = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NAPTR) {
                if ((sdnaptr = (struct domain_naptr *)find_substruct(sd, INTERNAL_TYPE_NAPTR)) == NULL) {
			dolog(LOG_INFO, "no NAPTR records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NAPTR));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NAPTR]));
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
	
	for (i = 0; i < sdnaptr->naptr_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_NAPTR));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_NAPTR]));
		q += 4;
		pack16(q, htons(2 + 2 + 1 + sdnaptr->naptr[i].flagslen + 1 + sdnaptr->naptr[i].serviceslen + 1 + sdnaptr->naptr[i].regexplen + sdnaptr->naptr[i].replacementlen));
		q += 2;
		pack16(q, htons(sdnaptr->naptr[i].order));
		q += 2;
		pack16(q, htons(sdnaptr->naptr[i].preference));
		q += 2;

		pack8(q, sdnaptr->naptr[i].flagslen);
		q++;
		pack(q, sdnaptr->naptr[i].flags, sdnaptr->naptr[i].flagslen);
		q += sdnaptr->naptr[i].flagslen;

		pack8(q, sdnaptr->naptr[i].serviceslen);
		q++;
		pack(q, sdnaptr->naptr[i].services, sdnaptr->naptr[i].serviceslen);
		q += sdnaptr->naptr[i].serviceslen;

		pack8(q, sdnaptr->naptr[i].regexplen);
		q++;
		pack(q, sdnaptr->naptr[i].regexp, sdnaptr->naptr[i].regexplen);
		q += sdnaptr->naptr[i].regexplen;

		pack(q, sdnaptr->naptr[i].replacement, sdnaptr->naptr[i].replacementlen);
		q += sdnaptr->naptr[i].replacementlen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NAPTR], "NAPTR", algorithm, labels, sd->ttl[INTERNAL_TYPE_NAPTR], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a SRV record
 */

int
sign_srv(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_srv *sdsrv = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SRV) {
                if ((sdsrv = (struct domain_srv *)find_substruct(sd, INTERNAL_TYPE_SRV)) == NULL) {
			dolog(LOG_INFO, "no SRV records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SRV));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SRV]));
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
	
	for (i = 0; i < sdsrv->srv_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_SRV));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_SRV]));
		q += 4;
		pack16(q, htons(2 + 2 + 2 + sdsrv->srv[i].targetlen));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].priority));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].weight));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].port));
		q += 2;
		pack(q, sdsrv->srv[i].target, sdsrv->srv[i].targetlen);
		q += sdsrv->srv[i].targetlen;
		
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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SRV], "SRV", algorithm, labels, sd->ttl[INTERNAL_TYPE_SRV], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an SSHFP record
 */

int
sign_sshfp(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_sshfp *sdsshfp = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SSHFP) {
                if ((sdsshfp = (struct domain_sshfp *)find_substruct(sd, INTERNAL_TYPE_SSHFP)) == NULL) {
			dolog(LOG_INFO, "no SSHFP records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SSHFP));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SSHFP]));
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
	
	for (i = 0; i < sdsshfp->sshfp_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_SSHFP));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_SSHFP]));
		q += 4;
		pack16(q, htons(1 + 1 + sdsshfp->sshfp[i].fplen));
		q += 2;
		pack8(q, sdsshfp->sshfp[i].algorithm);
		q++;
		pack8(q, sdsshfp->sshfp[i].fptype);
		q++;
		pack(q, sdsshfp->sshfp[i].fingerprint, sdsshfp->sshfp[i].fplen);
		q += sdsshfp->sshfp[i].fplen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SSHFP], "SSHFP", algorithm, labels, sd->ttl[INTERNAL_TYPE_SSHFP], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a TLSA record
 */

int
sign_tlsa(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_tlsa *sdtlsa = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_TLSA) {
                if ((sdtlsa = (struct domain_tlsa *)find_substruct(sd, INTERNAL_TYPE_TLSA)) == NULL) {
			dolog(LOG_INFO, "no TLSA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_TLSA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TLSA]));
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
	
	for (i = 0; i < sdtlsa->tlsa_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_TLSA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_TLSA]));
		q += 4;
		pack16(q, htons(1 + 1 + 1 + sdtlsa->tlsa[i].datalen));
		q += 2;
		pack8(q, sdtlsa->tlsa[i].usage);
		q++;
		pack8(q, sdtlsa->tlsa[i].selector);
		q++;
		pack8(q, sdtlsa->tlsa[i].matchtype);
		q++;
		pack(q, sdtlsa->tlsa[i].data, sdtlsa->tlsa[i].datalen);
		q += sdtlsa->tlsa[i].datalen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_TLSA], "TLSA", algorithm, labels, sd->ttl[INTERNAL_TYPE_TLSA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an DS record
 */

int
sign_ds(ddDB *db, char *zonename, struct keysentry  *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ds *sdds = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_DS) {
                if ((sdds = (struct domain_ds *)find_substruct(sd, INTERNAL_TYPE_DS)) == NULL) {
			dolog(LOG_INFO, "no DS records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_DS));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DS]));
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
	
	for (i = 0; i < sdds->ds_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_DS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DS]));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + sdds->ds[i].digestlen));
		q += 2;
		pack16(q, htons(sdds->ds[i].key_tag));
		q += 2;
		pack8(q, sdds->ds[i].algorithm);
		q++;
		pack8(q, sdds->ds[i].digest_type);
		q++;
		pack(q, sdds->ds[i].digest, sdds->ds[i].digestlen);
		q += sdds->ds[i].digestlen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_DS], "DS", algorithm, labels, sd->ttl[INTERNAL_TYPE_DS], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an NS record
 */

int
sign_ns(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ns *sdns = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NS) {
                if ((sdns = (struct domain_ns *)find_substruct(sd, INTERNAL_TYPE_NS)) == NULL) {
			dolog(LOG_INFO, "no NS records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NS));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NS]));
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
	
	for (i = 0; i < sdns->ns_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_NS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_NS]));
		q += 4;
		pack16(q, htons(sdns->ns[i].nslen));
		q += 2;
		memcpy(q, sdns->ns[i].nsserver, sdns->ns[i].nslen);
		q += sdns->ns[i].nslen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NS], "NS", algorithm, labels, sd->ttl[INTERNAL_TYPE_NS], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an MX record
 */

int
sign_mx(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_mx *sdmx = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_MX) {
                if ((sdmx = (struct domain_mx *)find_substruct(sd, INTERNAL_TYPE_MX)) == NULL) {
			dolog(LOG_INFO, "no MX records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_MX));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_MX]));
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
	
	for (i = 0; i < sdmx->mx_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_MX));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_MX]));
		q += 4;
		pack16(q, htons(2 + sdmx->mx[i].exchangelen));
		q += 2;
		pack16(q, htons(sdmx->mx[i].preference));
		q += 2;
		memcpy(q, sdmx->mx[i].exchange, sdmx->mx[i].exchangelen);
		q += sdmx->mx[i].exchangelen;

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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_MX], "MX", algorithm, labels, sd->ttl[INTERNAL_TYPE_MX], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an A record
 */

int
sign_a(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_a *sda = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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

	/* get the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_A) {
                if ((sda = (struct domain_a *)find_substruct(sd, INTERNAL_TYPE_A)) == NULL) {
			dolog(LOG_INFO, "no A records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_A));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_A]));
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
	
	for (i = 0; i < sda->a_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_A));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_A]));
		q += 4;
		pack16(q, htons(sizeof(in_addr_t)));
		q += 2;
		pack32(q, sda->a[i]);
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

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
        }
	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);	
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_A], "A", algorithm, labels, sd->ttl[INTERNAL_TYPE_A], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

int
create_ds(ddDB *db, char *zonename, struct keysentry *ksk_key)
{
	FILE *f;

	struct domain *sd;
	struct domain_dnskey *sddk = NULL;
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

	struct question *qp;
	int retval, lzerrno;
	char replystring[512];

	/* silently ignore zsk's, no error here */
	if (knp->type != KEYTYPE_KSK)
		return 0;

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL) {
		dolog(LOG_INFO, "dnsname == NULL\n");
		return -1;
	}

	qp = build_fake_question(dnsname, labellen, DNS_TYPE_SOA);
	if (qp == NULL) {
		dolog(LOG_INFO, "qp == NULL\n");
		return -1;
	}

	if ((sd = lookup_zone(db, qp, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		dolog(LOG_INFO, "sd == NULL\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_DNSKEY) {
		if ((sddk = (struct domain_dnskey *)find_substruct(sd, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in apex!\n");
			return -1;
		}
	}
	
	keylen = (p - key);	

	/* work out the digest */

	p = key;
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
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
	
	snprintf(buf, sizeof(buf), "dsset-%s", convert_name(sd->zone, sd->zonelen));

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

	fprintf(f, "%s\t\tIN DS %u %d 1 %s\n", convert_name(sd->zone, sd->zonelen), keyid, algorithm, mytmp);


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

	fprintf(f, "%s\t\tIN DS %u %d 2 %s\n", convert_name(sd->zone, sd->zonelen), keyid, algorithm, mytmp);

	fclose(f);

	return 0;
}

/* 
 * From RFC 4034, appendix b 
 */

int
sign_dnskey(ddDB *db, char *zonename, struct keysentry *zsk_key, int expiry, struct domain *sd)
{
	struct domain_dnskey *sddk = NULL;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;

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
			
			labels = label_count(sd->zone);
			if (labels < 0) {
				dolog(LOG_INFO, "label_count");
				return -1;
			}

			dnsname = dns_label(zonename, &labellen);
			if (dnsname == NULL)
				return -1;

			if (sd->flags & DOMAIN_HAVE_DNSKEY) {
				if ((sddk = (struct domain_dnskey *)find_substruct(sd, INTERNAL_TYPE_DNSKEY)) == NULL) {
					dolog(LOG_INFO, "no dnskeys in apex!\n");
					return -1;
				}
			} 
			
			p = key;

			pack16(p, htons(DNS_TYPE_DNSKEY));
			p += 2;
			pack8(p, algorithm);
			p++;
			pack8(p, labels);
			p++;
			pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
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
			
			for (i = 0; i < sddk->dnskey_count; i++) {
				q = tmpkey;
				pack(q, dnsname, labellen);
				q += labellen;
				pack16(q, htons(DNS_TYPE_DNSKEY));
				q += 2;
				pack16(q, htons(DNS_CLASS_IN));
				q += 2;
				pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
				q += 4;
				pack16(q, htons(2 + 1 + 1 + sddk->dnskey[i].publickey_len));
				q += 2;
				pack16(q, htons(sddk->dnskey[i].flags));
				q += 2;
				pack8(q, sddk->dnskey[i].protocol);
				q++;
				pack8(q, sddk->dnskey[i].algorithm);
				q++;
				pack(q, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
				q += sddk->dnskey[i].publickey_len;


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

		#ifdef __linux__
			TAILQ_FOREACH(c2, &head, entries) {
		#else
			TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
		#endif
				pack(p, c2->data, c2->len);
				p += c2->len;

				TAILQ_REMOVE(&head, c2, entries);
			}
			keylen = (p - key);	

		#if 0
			debug_bindump(key, keylen);
		#endif

			switch (algorithm) {
			case ALGORITHM_RSASHA1_NSEC3_SHA1:
				SHA1_Init(&sha1);
				SHA1_Update(&sha1, key, keylen);
				SHA1_Final((u_char *)shabuf, &sha1);
				bufsize = 20;
				break;
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
				return -1;
			}
				
			rsa = get_private_key(knp);
			if (rsa == NULL) {
				dolog(LOG_INFO, "reading private key failed\n");
				return -1;
			}
				
			rsatype = alg_to_rsa(algorithm);
			if (rsatype == -1) {
				dolog(LOG_INFO, "algorithm mismatch\n");
				return -1;
			}

			if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
				dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}

			RSA_free(rsa);

			len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
			tmp[len] = '\0';

			if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, 		ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
				dolog(LOG_INFO, "fill_rrsig\n");
				return -1;
			}

		} /* if KSK */
	} /* SLIST_FOREACH */

	/* now work out the ZSK */
	if ((zone = get_key(zsk_key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, sizeof(tmp), &keyid)) == NULL) {
		dolog(LOG_INFO, "get_key %s\n", zsk_key->keyname);
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_DNSKEY) {
		if ((sddk = (struct domain_dnskey *)find_substruct(sd, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in apex!\n");
			return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_DNSKEY));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
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
	
	for (i = 0; i < sddk->dnskey_count; i++) {
		q = tmpkey;
		pack(q, dnsname, labellen);
		q += labellen;
		pack16(q, htons(DNS_TYPE_DNSKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + sddk->dnskey[i].publickey_len));
		q += 2;
		pack16(q, htons(sddk->dnskey[i].flags));
		q += 2;
		pack8(q, sddk->dnskey[i].protocol);
		q++;
		pack8(q, sddk->dnskey[i].algorithm);
		q++;
		pack(q, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
		q += sddk->dnskey[i].publickey_len;

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

#ifdef __linux__
	TAILQ_FOREACH(c2, &head, entries) {
#else
	TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
		pack(p, c2->data, c2->len);
		p += c2->len;

		TAILQ_REMOVE(&head, c2, entries);
	}

	keylen = (p - key);	

#if 0
	debug_bindump(key, keylen);
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
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
		return -1;
	}
		
	rsa = get_private_key(zsk_key);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, 			ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
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


/* pack functions */

void
pack32(char *buf, u_int32_t value)
{
	u_int32_t *p;

	p = (u_int32_t *)buf;
	*p = value;
}	

void
pack16(char *buf, u_int16_t value)
{
	u_int16_t *p;

	p = (u_int16_t *)buf;
	*p = value;
}

void
pack8(char *buf, u_int8_t value)
{
	u_int8_t *p;

	p = (u_int8_t *)buf;
	*p = value;
}

void
pack(char *buf, char *input, int len)
{
	memcpy(buf, input, len);
}	

void
free_private_key(struct keysentry *kn)
{
	BN_clear_free(kn->rsan);
	BN_clear_free(kn->rsae);
	BN_clear_free(kn->rsad);
	BN_clear_free(kn->rsap);
	BN_clear_free(kn->rsaq);
	BN_clear_free(kn->rsadmp1);
	BN_clear_free(kn->rsadmq1);
	BN_clear_free(kn->rsaiqmp);

	return;
}

RSA *
get_private_key(struct keysentry *kn)
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

u_int64_t
timethuman(time_t timet)
{
	char timebuf[512];
	struct tm *tm;
	u_int64_t retbuf;

	tm = gmtime((time_t *)&timet);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	retbuf = atoll(timebuf);

	return(retbuf);
}

int
construct_nsec3(ddDB *db, char *zone, int iterations, char *salt)
{
	struct node *n, *nx;

	struct domain *sd;
	struct question *q;

	struct nsec3param n3p;
	struct domain_nsec3param *sdn3p;
	
	char replystring[512];
	char buf[4096];
	char bitmap[4096];
	char *dnsname;
	char *hashname = NULL;
	char *p;

	int labellen;
	int retval, lzerrno;
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
	
	if (fill_nsec3param(zone, "nsec3param", 0, 1, 0, iterations, salt) < 0) {
		printf("fill_nsec3param failed\n");
		return -1;
	}

	dnsname = dns_label(zone, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_NSEC3PARAM);
	if (q == NULL) {
		return -1;
	}

	if ((sd = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	/* get the rootzone's len */
	rootlen = sd->zonelen;

	/* RFC 5155 page 3 */
	ttl = sd->ttl[INTERNAL_TYPE_SOA];

        if ((sdn3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
                return -1;
        }

	n3p.algorithm = 1;	/* still in conformance with above */
	n3p.flags = 0;
	n3p.iterations = sdn3p->nsec3param.iterations;
	n3p.saltlen = sdn3p->nsec3param.saltlen;
	memcpy(&n3p.salt, sdn3p->nsec3param.salt, n3p.saltlen);

	j = 0;

	RB_FOREACH_SAFE(n, domaintree, &rbhead, nx) {
		rs = n->datalen;
		if ((sd = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sd, (char *)n->data, n->datalen);

		hashname = hash_name(sd->zone, sd->zonelen, &n3p);
		if (hashname == NULL) {
			dolog(LOG_INFO, "hash_name return NULL");
			return -1;
		}
		
		bitmap[0] = '\0';
		if (sd->flags & DOMAIN_HAVE_A)
			strlcat(bitmap, "A ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_NS)
			strlcat(bitmap, "NS ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_CNAME)
			strlcat(bitmap, "CNAME ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SOA)
			strlcat(bitmap, "SOA ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_PTR)
			strlcat(bitmap, "PTR ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_MX)
			strlcat(bitmap, "MX ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_TXT)
			strlcat(bitmap, "TXT ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_AAAA)
			strlcat(bitmap, "AAAA ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SRV)
			strlcat(bitmap, "SRV ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_NAPTR)
			strlcat(bitmap, "NAPTR ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_DS)
			strlcat(bitmap, "DS ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SSHFP)
			strlcat(bitmap, "SSHFP ", sizeof(bitmap));	

		/* they all have RRSIG */
		strlcat(bitmap, "RRSIG ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_DNSKEY)
			strlcat(bitmap, "DNSKEY ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_NSEC3)
			strlcat(bitmap, "NSEC3 ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM)
			strlcat(bitmap, "NSEC3PARAM ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_TLSA)
			strlcat(bitmap, "TLSA ", sizeof(bitmap));	

#if 0
		printf("%s %s\n", buf, bitmap);
#endif

		n1 = malloc(sizeof(struct mynsec3));
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

	RB_FOREACH_SAFE(n, domaintree, &rbhead, nx) {
		rs = n->datalen;
		if ((sd = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sd, (char *)n->data, n->datalen);

		len = sd->zonelen;
		for (p = sd->zone; *p && len > rootlen; p++, len--) {
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

			n1 = malloc(sizeof(struct mynsec3));
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

#if 0
		printf("%s next: %s %s\n", n2->hashname, np->hashname, n2->bitmap);
#endif
		snprintf(buf, sizeof(buf), "%s.%s.", n2->hashname, zone);
		fill_nsec3(buf, "nsec3", ttl, n3p.algorithm, n3p.flags, n3p.iterations, salt, np->hashname, n2->bitmap);
	}

#if 0
	printf("%d records\n", j);
#endif
	
	return 0;
}

char *
bin2hex(char *bin, int len)
{
	static char hex[4096];
	char *p;
	int i;

	memset(&hex, 0, sizeof(hex));
	p = &hex[0];

	for (i = 0; i < len; i++) {
		snprintf(p, sizeof(hex), "%02x", bin[i] & 0xff);
		p += 2;
	}

	return ((char *)&hex);
}

char *
bitmap2human(char *bitmap, int len)
{
	static char human[4096];
	char expanded_bitmap[32];
	u_int16_t bit;
	int i, j, block, bitlen;
	int x;
	char *p;

	memset(&human, 0, sizeof(human));

	for (i = 0, p = bitmap; i < len;) {
		block = *p;
		p++;
		i++;
		memset(&expanded_bitmap, 0, sizeof(expanded_bitmap));
		bitlen = *p;
		p++;
		i++;
		memcpy(&expanded_bitmap, p, bitlen);
		p += bitlen;
		i += bitlen;
		for (j = 0; j < 32; j++) {
			if (expanded_bitmap[j] & 0x80) {
				x = 0;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x40) {
				x = 1;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x20) {
				x = 2;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x10) {
				x = 3;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x8) {
				x = 4;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x4) {
				x = 5;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x2) {
				x = 6;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x1) {
				x = 7;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}

		}
	}
		
	if (human[strlen(human) - 1] == ' ')
		human[strlen(human) - 1] = '\0';

	return ((char *)&human);
}

int
print_sd(FILE *of, struct domain *sdomain)
{
	int i, x, len;

	struct domain_soa *sdsoa;
	struct domain_ns *sdns;
	struct domain_mx *sdmx;
	struct domain_a *sda;
	struct domain_aaaa *sdaaaa;
	struct domain_cname *sdcname;
	struct domain_ptr *sdptr;
	struct domain_txt *sdtxt;
	struct domain_naptr *sdnaptr;
	struct domain_srv *sdsrv;
	struct domain_rrsig *sdrr;
	struct domain_dnskey *sddk;
	struct domain_ds *sdds;
	struct domain_nsec3 *sdn3;
	struct domain_nsec3param *sdn3param;
	struct domain_sshfp *sdsshfp;
	struct domain_tlsa *sdtlsa;
	struct rrsig *rss;
	
	char buf[4096];

	if (sdomain->flags & DOMAIN_HAVE_SOA) {
		if ((sdsoa = (struct domain_soa *)find_substruct(sdomain, INTERNAL_TYPE_SOA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,soa,%d,%s,%s,%u,%d,%d,%d,%d\n", 
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_SOA],
			convert_name(sdsoa->soa.nsserver, sdsoa->soa.nsserver_len),
			convert_name(sdsoa->soa.responsible_person, sdsoa->soa.rp_len),
			sdsoa->soa.serial, sdsoa->soa.refresh, sdsoa->soa.retry, 
			sdsoa->soa.expire, sdsoa->soa.minttl);
	}
	if (sdomain->flags & DOMAIN_HAVE_NS) {
		if ((sdns = (struct domain_ns *)find_substruct(sdomain, INTERNAL_TYPE_NS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdns->ns_count; i++) {
			fprintf(of, "  %s,ns,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NS],
				convert_name(sdns->ns[i].nsserver, sdns->ns[i].nslen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_MX) {
		if ((sdmx = (struct domain_mx *)find_substruct(sdomain, INTERNAL_TYPE_MX)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdmx->mx_count; i++) {
			fprintf(of, "  %s,mx,%d,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_MX],
				sdmx->mx[i].preference,
				convert_name(sdmx->mx[i].exchange, sdmx->mx[i].exchangelen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DS) {
		if ((sdds = (struct domain_ds *)find_substruct(sdomain, INTERNAL_TYPE_DS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdds->ds_count; i++) {
			fprintf(of, "  %s,ds,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DS],
				sdds->ds[i].key_tag,
				sdds->ds[i].algorithm,
				sdds->ds[i].digest_type,
				bin2hex(sdds->ds[i].digest, sdds->ds[i].digestlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_CNAME) {
		if ((sdcname = (struct domain_cname *)find_substruct(sdomain, INTERNAL_TYPE_CNAME)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,cname,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_CNAME],
				convert_name(sdcname->cname, sdcname->cnamelen));
	}
	if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
		if ((sdnaptr = (struct domain_naptr *)find_substruct(sdomain, INTERNAL_TYPE_NAPTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdnaptr->naptr_count; i++) {
			fprintf(of, "  %s,naptr,%d,%d,%d,\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NAPTR],
				sdnaptr->naptr[i].order,
				sdnaptr->naptr[i].preference);
			
			for (x = 0; x < sdnaptr->naptr[i].flagslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].flags[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < sdnaptr->naptr[i].serviceslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].services[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < sdnaptr->naptr[i].regexplen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].regexp[x]);
			}
			fprintf(of, "\",%s\n", (sdnaptr->naptr[i].replacement[0] == '\0') ? "." : convert_name(sdnaptr->naptr[i].replacement, sdnaptr->naptr[i].replacementlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TXT) {
		if ((sdtxt = (struct domain_txt *)find_substruct(sdomain, INTERNAL_TYPE_TXT)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,txt,%d,\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TXT]);
		for (i = 0; i < sdtxt->txtlen; i++) {
			fprintf(of, "%c", sdtxt->txt[i]);
		}
		fprintf(of, "\"\n");
	}
	if (sdomain->flags & DOMAIN_HAVE_PTR) {
		if ((sdptr = (struct domain_ptr *)find_substruct(sdomain, INTERNAL_TYPE_PTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,ptr,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_PTR],
				convert_name(sdptr->ptr, sdptr->ptrlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_SRV) {
		if ((sdsrv = (struct domain_srv *)find_substruct(sdomain, INTERNAL_TYPE_SRV)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsrv->srv_count; i++) {
			fprintf(of, "  %s,srv,%d,%d,%d,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SRV],
				sdsrv->srv[i].priority,
				sdsrv->srv[i].weight,
				sdsrv->srv[i].port,
				convert_name(sdsrv->srv[i].target,sdsrv->srv[i].targetlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TLSA) {
		if ((sdtlsa = (struct domain_tlsa *)find_substruct(sdomain, INTERNAL_TYPE_TLSA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdtlsa->tlsa_count; i++) {
			fprintf(of, "  %s,tlsa,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TLSA],
				sdtlsa->tlsa[i].usage,
				sdtlsa->tlsa[i].selector,
				sdtlsa->tlsa[i].matchtype,
				bin2hex(sdtlsa->tlsa[i].data, sdtlsa->tlsa[i].datalen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
		if ((sdsshfp = (struct domain_sshfp *)find_substruct(sdomain, INTERNAL_TYPE_SSHFP)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsshfp->sshfp_count; i++) {
			fprintf(of, "  %s,sshfp,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SSHFP],
				sdsshfp->sshfp[i].algorithm,
				sdsshfp->sshfp[i].fptype,
				bin2hex(sdsshfp->sshfp[i].fingerprint, sdsshfp->sshfp[i].fplen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_A) {
		if ((sda = (struct domain_a *)find_substruct(sdomain, INTERNAL_TYPE_A)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sda->a_count; i++) {
			inet_ntop(AF_INET, &sda->a[i], buf, sizeof(buf));
			fprintf(of, "  %s,a,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_A],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_AAAA) {
		if ((sdaaaa = (struct domain_aaaa *)find_substruct(sdomain, INTERNAL_TYPE_AAAA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdaaaa->aaaa_count; i++) {
			inet_ntop(AF_INET6, &sdaaaa->aaaa[i], buf, sizeof(buf));
			fprintf(of, "  %s,aaaa,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_AAAA],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DNSKEY) {
#if DEBUG
		printf(" has dnskey\n");
#endif
		if ((sddk = (struct domain_dnskey *)find_substruct(sdomain, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sddk->dnskey_count; i++) {
			len = mybase64_encode(sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "  %s,dnskey,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DNSKEY],
				sddk->dnskey[i].flags,
				sddk->dnskey[i].protocol,
				sddk->dnskey[i].algorithm,
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
#if DEBUG
		printf("has nsec3param\n");
#endif
		if ((sdn3param = (struct domain_nsec3param *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
			dolog(LOG_INFO, "no nsec3param in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec3param,0,%d,%d,%d,\"%s\"\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdn3param->nsec3param.algorithm,
			sdn3param->nsec3param.flags,
			sdn3param->nsec3param.iterations,
			(sdn3param->nsec3param.saltlen == 0) ? "-" : bin2hex(sdn3param->nsec3param.salt, sdn3param->nsec3param.saltlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
#if DEBUG
		printf("has nsec3\n");
#endif
		if ((sdn3 = (struct domain_nsec3 *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3)) == NULL) {
			dolog(LOG_INFO, "no nsec3 in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec3,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\"\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_NSEC3],
			sdn3->nsec3.algorithm,
			sdn3->nsec3.flags,
			sdn3->nsec3.iterations,
			(sdn3->nsec3.saltlen == 0) ? "-" : bin2hex(sdn3->nsec3.salt, sdn3->nsec3.saltlen),
			base32hex_encode(sdn3->nsec3.next, sdn3->nsec3.nextlen),
			bitmap2human(sdn3->nsec3.bitmap, sdn3->nsec3.bitmap_len));

	}
	if (sdomain->flags & DOMAIN_HAVE_RRSIG) {
#if DEBUG
		printf(" has rrsig\n");
#endif
		
		if ((sdrr = (struct domain_rrsig *)find_substruct(sdomain, INTERNAL_TYPE_RRSIG)) == NULL) {
			dolog(LOG_INFO, "no rrsigs in zone!\n");
			return -1;
		}

		if ((sdomain->flags & DOMAIN_HAVE_DNSKEY) && sdrr->rrsig_dnskey_count > 0) {
			for (i = 0; i < sdrr->rrsig_dnskey_count; i++) {
				rss = (struct rrsig *)&sdrr->rrsig_dnskey[i];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					convert_name(sdomain->zone, sdomain->zonelen),
					sdomain->ttl[INTERNAL_TYPE_DNSKEY],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}
		}
		if (sdomain->flags & DOMAIN_HAVE_SOA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SOA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_DS) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_DS];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}



		if (sdomain->flags & DOMAIN_HAVE_TLSA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TLSA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SSHFP];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_SRV) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SRV];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NAPTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_TXT) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TXT];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_AAAA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_AAAA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone,sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3PARAM];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,0,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				0, /* original ttl */
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_CNAME) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_CNAME];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_PTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_PTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}



		if (sdomain->flags & DOMAIN_HAVE_NS) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NS];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_MX) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_MX];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_A) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_A];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen), 
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}
	}

	return 0;
}

int
usage(int argc, char *argv[])
{
	int retval = 0;

	if (argc == 2 && strcmp(argv[1], "sign") == 0) {
		fprintf(stderr, "usage: dddctl sign [-KZ] [-a algorithm] [-B bits] [-e seconds] [-I iterations] [-i inputfile] [-k KSK] [-m mask] [-n zonename] [-o output] [-S pid] [-s salt] [-t ttl] [-z ZSK]\n");
		fprintf(stderr, "\t-K\t\tcreate a new KSK key.\n");
		fprintf(stderr, "\t-Z\t\tcreate a new ZSK key.\n");
		fprintf(stderr, "\t-a algorithm	use algorithm (integer)\n");
		fprintf(stderr, "\t-B bits\t\tuse number of bits (integer)\n");
		fprintf(stderr, "\t-e seconds\texpiry in seconds\n");
		fprintf(stderr, "\t-I iterations\tuse (integer) NSEC3 iterations\n");
		fprintf(stderr, "\t-i inputfile\tuse the inputfile of unsigned zone\n");
		fprintf(stderr, "\t-k KSK\t\tuse provided KSK key-signing keyname\n");
		fprintf(stderr, "\t-m mask\t\trun the following masked functions\n");
		fprintf(stderr, "\t-n zonename\trun for zonename zone\n");
		fprintf(stderr, "\t-o output\toutput to file, may be '-' for stdout\n");
		fprintf(stderr, "\t-S pid\t\tsign with this pid ('KSK' or 'ZSK' if used in\n\t\t\tconjunction with [-ZK])\n");
		fprintf(stderr, "\t-s salt\t\tsalt for NSEC3 (in hexadecimal)\n");
		fprintf(stderr, "\t-t ttl\t\ttime-to-live for dnskey's\n");
		fprintf(stderr, "\t-z ZSK\t\tuse provided ZSK zone-signing keyname\n");	
		return 0;
	} else if (argc == 2 && strcmp(argv[1], "query") == 0) {
		fprintf(stderr, "usage: dddctl query [-46BDITZ] [-@ server] [-P port] [-p file] name command\n");
		fprintf(stderr, "\t-@ server\t\tUse server ip.\n");
		fprintf(stderr, "\t-4\t\tUse IPv4 only.\n");
		fprintf(stderr, "\t-6\t\tUse IPv6 only.\n");
		fprintf(stderr, "\t-B\t\tOutput as a BIND file.\n");
		fprintf(stderr, "\t-D\t\tUse DNSSEC (DO bit) lookup.\n");
		fprintf(stderr, "\t-I\t\tIndent output.\n");
		fprintf(stderr, "\t-T\t\tUse TCP.\n");
		fprintf(stderr, "\t-Z\t\tOutput as a zonefile.\n");
		fprintf(stderr, "\t-P port\t\tUse specified port.\n");
		fprintf(stderr, "\t-p file\t\tOutput to file.\n");
		
		return 0;
	} else if (argc == 2) {
		retval = 1;
	} else {
		fprintf(stderr, "usage: command [arg ...]\n");
		fprintf(stderr, "\tbindfile zonename zonefile\n");
		fprintf(stderr, "\tconfigtest [configfile]\n");
		fprintf(stderr, "\tquery [-46BDITZ] [-@ server] [-P port] [-p file] name command\n");
		fprintf(stderr, "\thelp [command]\n");
		fprintf(stderr, "\tsign [-KZ] [-a algorithm] [-B bits] [-e seconds]\n\t\t[-I iterations] [-i inputfile] [-k KSK] [-m mask] [-n zonename]\n\t\t[-o output] [-S pid] [-s salt] [-t ttl] [-z ZSK]\n");
		fprintf(stderr, "\tsshfp hostname [-k keyfile] [-t ttl]\n");
		fprintf(stderr, "\tstart [-f configfile] [-s socket]\n");
		fprintf(stderr, "\tstop [-s socket]\n");
		fprintf(stderr, "\trestart [-s socket]\n");
		retval = 0;
	}

	return (retval);
}

int	
dig(int argc, char *argv[])
{
	FILE *f = stdout;
	struct soa mysoa;
	struct stat sb;
	struct rrtab *rt;
	struct timeval tv;
	char *outputfile = NULL;
	char *domainname = NULL;
	char *nameserver = "127.0.0.1";
	int use_v4 = 0, use_v6 = 0;
	u_int32_t format = 0;
	u_int16_t port = 53;
	int ch, so, ms;
	int type = DNS_TYPE_A;

	while ((ch = getopt(argc, argv, "@:46BDIP:TZp:")) != -1) {
		switch (ch) {
		case '@':
			nameserver = optarg;
			break;
		case '4':
			use_v4 = 1;
			break;
		case '6':
			use_v6 = 1;
			break;
		case 'B':
			format |= BIND_FORMAT;
			break;
		case 'D':
			format |= DNSSEC_FORMAT;
			break;
		case 'I':
			format |= INDENT_FORMAT;
			break;
		case 'P':
			port = atoi(optarg);
			break;
		case 'T':
			format |= TCP_FORMAT;
			break;
		case 'Z':
			format |= ZONE_FORMAT;
			break;
		case 'p':
			outputfile = optarg;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (outputfile) {
		if (lstat(outputfile, &sb) != -1) {
			fprintf(stderr, "%s exists, not clobbering\n", outputfile);
			exit(1);
		}
		
		f = fopen(outputfile, "w");
		if (f == NULL) {
			perror("fopen");
			exit(1);
		}
	
	}

	if ((format & ZONE_FORMAT) && (format & INDENT_FORMAT)) {
		fprintf(stderr, "you may not specify -I and -Z together\n");
		exit(1);
	}

	if (argc < 1) {
		fprintf(stderr, "lookup what?\n");
		exit(1);
	}

	if ((rt = rrlookup(argv[0])) != NULL) {
		domainname = argv[1];
		type = rt->type;
	} else {
		if (strcmp(argv[0], "any") == 0) {	
			domainname = argv[1];
			type = DNS_TYPE_ANY;
		} else if (strcmp(argv[0], "axfr") == 0) {
			domainname = argv[1];
			type = DNS_TYPE_AXFR;
			format |= TCP_FORMAT;
		} else {
			if (argc == 2) {
				if ((rt = rrlookup(argv[1])) != NULL) {
					domainname = argv[0];
					type = rt->type;
				} else {
					if (strcmp(argv[1], "any") == 0) {	
						domainname = argv[0];
						type = DNS_TYPE_ANY;
					} else if (strcmp(argv[1], "axfr") == 0) {
						domainname = argv[0];
						type = DNS_TYPE_AXFR;
						format |= TCP_FORMAT;
					}
				}
			} else {
				domainname = argv[0];
			}
		}
	}
			
	gettimeofday(&tv0, NULL);	
	current_time = time(NULL);

	so = connect_server(nameserver, port, format);
	if (so < 0) {
		exit(1);
	}

	if (type == DNS_TYPE_AXFR) {
		if (lookup_axfr(f, so, domainname, &mysoa, format) < 0) {
			exit(1);
		}
				
	} else {
		if (lookup_name(f, so, domainname, type, &mysoa, format, nameserver, port) < 0) {
			/* XXX maybe a packet dump here? */
			exit(1);
		}
	}

	close(so);
	gettimeofday(&tv, NULL);	

	ms = 0;

	if (tv.tv_usec < tv0.tv_usec) {
		tv.tv_sec--;
		ms += (((tv.tv_usec + 1000000) - tv0.tv_usec) / 1000);
	} else
		ms += (((tv.tv_usec) - tv0.tv_usec) / 1000);

	if (tv.tv_sec - tv0.tv_sec > 0)
		ms += 1000 * (tv.tv_sec - tv0.tv_sec);

	fprintf(f, ";; QUERY TIME: %d ms\n", ms);
	fprintf(f, ";; SERVER: %s#%u\n", nameserver, port);
	fprintf(f, ";; WHEN: %s", ctime(&current_time));
	if (type == DNS_TYPE_AXFR) {
		if (format & ZONE_FORMAT)
			answers--;

		fprintf(f, ";; XFR size %d records (bytes %d)\n", answers, \
			bytes_received);
	} else {
		fprintf(f, ";; MSG SIZE  rcvd: %d\n", bytes_received);
	}

	if (f != stdin && f != NULL)
		fclose(f);

	return 0;
}

int
connect_server(char *nameserver, int port, u_int32_t format)
{
	struct sockaddr_in sin;
	int so;

	if (format & TCP_FORMAT)
		so =  socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	else
		so =  socket(AF_INET, SOCK_DGRAM, 0);
		
	if (so < 0) {
		perror("socket");
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(nameserver);
	
	if (connect(so, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("connect");
		return -1;
	}

	return (so);	
}


int
lookup_axfr(FILE *f, int so, char *zonename, struct soa *mysoa, u_int32_t format)
{
	char query[512];
	char *reply;
	struct question *q;
	struct whole_header {
		u_int16_t len;
		struct dns_header dh;
	} *wh, *rwh;
	struct raxfr_logic *sr;
	
	u_char *p, *name;

	u_char *end, *estart;
	int len, totallen, zonelen, rrlen, rrtype;
	int soacount = 0;
	int elen = 0;
	u_int16_t *class, *type, rdlen, *plen;
	u_int16_t tcplen;
	
	if (!(format & TCP_FORMAT))
		return -1;

	memset(&query, 0, sizeof(query));
	
	wh = (struct whole_header *)&query[0];
	
	wh->dh.id = htons(arc4random() & 0xffff);
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = htons(1);;

	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);
	HTONS(wh->dh.query);

	totallen = sizeof(struct whole_header);

	name = dns_label(zonename, &len);
	if (name == NULL) {
		return -1;
	}

	zonelen = len;
	
	p = (char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;

	type = (u_int16_t *)&query[totallen];
	*type = htons(DNS_TYPE_AXFR);
	totallen += sizeof(u_int16_t);
	
	class = (u_int16_t *)&query[totallen];
	*class = htons(DNS_CLASS_IN);
	totallen += sizeof(u_int16_t);

	wh->len = htons(totallen - 2);

	if (send(so, query, totallen, 0) < 0) {
		perror("send");
		return -1;
	}

	/* catch reply */

	reply = calloc(1, 0xffff + 2);
	if (reply == NULL) {
		perror("calloc");
		return -1;
	}


	for (;;) {
		len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL);
		if (len <= 0)	
			break;

		plen = (u_int16_t *)reply;
		tcplen = ntohs(*plen) + 2;
		
		len = recv(so, reply, tcplen, MSG_WAITALL);
		if (len < 0) {
			perror("recv");
			return -1;
		}
		rwh = (struct whole_header *)&reply[0];
		bytes_received = ntohs(rwh->len);

		end = &reply[len];
		len = rwh->len;

		if (rwh->dh.id != wh->dh.id) {
			fprintf(stderr, "DNS ID mismatch\n");
			return -1;
		}

		if (!(htons(rwh->dh.query) & DNS_REPLY)) {
			fprintf(stderr, "NOT a DNS reply\n");
			return -1;
		}
		
		if (ntohs(rwh->dh.answer) < 1) {	
			fprintf(stderr, "NO ANSWER provided\n");
			return -1;
		}

		answers = ntohs(rwh->dh.answer);

		q = build_question((char *)&wh->dh, len, wh->dh.additional);
		if (q == NULL) {
			fprintf(stderr, "failed to build_question\n");
			return -1;
		}
			
		if (memcmp(q->hdr->name, name, q->hdr->namelen) != 0) {
			fprintf(stderr, "question name not for what we asked\n");
			return -1;
		}

		if (q->hdr->qclass != *class || q->hdr->qtype != *type) {
			fprintf(stderr, "wrong class or type\n");
			return -1;
		}
		
		p = (char *)&rwh[1];		
		p += q->hdr->namelen;
		p += sizeof(u_int16_t);	 	/* type */
		p += sizeof(u_int16_t);		/* class */
		
		/* end of question */
		
		estart = (u_char *)&rwh->dh;

		if ((format & ZONE_FORMAT) && f != NULL) 
			fprintf(f, "zone \"%s\" {\n", zonename);

		for (;;) {
			elen = 0;

			if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, soacount, &rdlen, format)) < 0) {
				fprintf(stderr, "not a SOA reply, or ERROR\n");
				return -1;
			}

			p = (estart + rrlen);

			if (rrtype == DNS_TYPE_SOA) {
				if ((len = raxfr_soa(f, p, estart, end, mysoa, soacount, format)) < 0) {
					fprintf(stderr, "raxxfr_soa failed\n");
					return -1;
				}
				p = (estart + len);
				soacount++;
			} else {
				for (sr = supported; sr->rrtype != 0; sr++) {
					if (rrtype == sr->rrtype) {
						if ((len = (*sr->raxfr)(f, p, estart, end, mysoa, rdlen)) < 0) {
							fprintf(stderr, "error with rrtype %d\n", sr->rrtype);
							return -1;
						}
						p = (estart + len);
						break;
					}
				}

				if (sr->rrtype == 0) {
					fprintf(stderr, "unsupported RRTYPE\n");
					return -1;
				} 
			}


			if (soacount > 1)
				break;
		}
				
		break;
	}

	if ((len = recv(so, reply, 0xffff, 0)) != 0) {	
		fprintf(stderr, ";; WARN: recieved %d more bytes.\n", len);
	}

	if (f != NULL) {
		if ((format & ZONE_FORMAT))
			fprintf(f, "}\n");
	}

	return 0;

}



int
lookup_name(FILE *f, int so, char *zonename, u_int16_t myrrtype, struct soa *mysoa, u_int32_t format, char *nameserver, u_int16_t port)
{
	int len, i;
	int numansw, numaddi, numauth;
	int printansw = 1, printauth = 1, printaddi = 1;
	int rrtype, soacount = 0;
	u_int16_t rdlen;
	char query[512];
	char *reply;
	struct raxfr_logic *sr;
	struct question *q;
	struct dns_optrr *optrr;
	struct whole_header {
		struct dns_header dh;
	} *wh, *rwh;
	
	u_char *p, *name;

	u_char *end, *estart;
	int totallen, zonelen, rrlen;
	int replysize = 0;
	u_int16_t *class, *type, *tcpsize;
	u_int16_t *plen;
	u_int16_t tcplen;

	if (format & TCP_FORMAT)
		replysize = 0xffff;
	else
		replysize = 4096;


	memset(&query, 0, sizeof(query));
	
	if (format & TCP_FORMAT) {
		tcpsize = (u_int16_t *)&query[0];
		wh = (struct whole_header *)&query[2];
	} else
		wh = (struct whole_header *)&query[0];
	
	wh->dh.id = htons(arc4random() & 0xffff);
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = htons(1);;

	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);

	
	HTONS(wh->dh.query);

	if (format & TCP_FORMAT)
		totallen = sizeof(struct whole_header) + 2;
	else
		totallen = sizeof(struct whole_header);

	name = dns_label(zonename, &len);
	if (name == NULL) {
		return -1;
	}

	zonelen = len;
	
	p = (char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;

	type = (u_int16_t *)&query[totallen];
	*type = htons(myrrtype);
	totallen += sizeof(u_int16_t);
	
	class = (u_int16_t *)&query[totallen];
	*class = htons(DNS_CLASS_IN);
	totallen += sizeof(u_int16_t);

	/* attach EDNS0 */

	optrr = (struct dns_optrr *)&query[totallen];

	optrr->name[0] = 0;
	optrr->type = htons(DNS_TYPE_OPT); 
	optrr->class = htons(replysize);
	optrr->ttl = htonl(0);		/* EDNS version 0 */
	if ((format & DNSSEC_FORMAT))
		SET_DNS_ERCODE_DNSSECOK(optrr);
	HTONL(optrr->ttl);
	optrr->rdlen = 0;
	optrr->rdata[0] = 0;

	totallen += (sizeof(struct dns_optrr));

	if (format & TCP_FORMAT)
		*tcpsize = htons(totallen - 2);

	if (send(so, query, totallen, 0) < 0) {
		return -1;
	}

	/* catch reply */

	reply = calloc(1, replysize + 2);
	if (reply == NULL) {
		perror("calloc");
		return -1;
	}
	
	if (format & TCP_FORMAT) {
		if ((len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL)) < 0) {
			perror("recv");
			return -1;
		}

		plen = (u_int16_t *)reply;
		tcplen = ntohs(*plen);

		if ((len = recv(so, reply, tcplen + 2, MSG_WAITALL)) < 0) {
			perror("recv");
			return -1;
		}
	} else {
		if ((len = recv(so, reply, replysize, 0)) < 0) {
			return -1;
		}
	}

	if (format & TCP_FORMAT)
		rwh = (struct whole_header *)&reply[2];
	else
		rwh = (struct whole_header *)&reply[0];

	bytes_received = len;

	end = &reply[len];

	if (rwh->dh.id != wh->dh.id) {
		fprintf(stderr, "DNS ID mismatch 2\n");
		return -1;
	}

	if (!(htons(rwh->dh.query) & DNS_REPLY)) {
		fprintf(stderr, "NOT a DNS reply\n");
		return -1;
	}

	if (!(format & TCP_FORMAT) && (htons(rwh->dh.query) & DNS_TRUNC)) {
		int ret;

		fprintf(f,  ";; received a truncated answer, retrying with TCP\n");
		format |= TCP_FORMAT;
		
		gettimeofday(&tv0, NULL);	
		so = connect_server(nameserver, port, format);
		if (so < 0) {
			exit(1);
		}

		ret = lookup_name(f, so, zonename, myrrtype, mysoa, format, nameserver, port);
		close(so);
		return (ret);
	}
	
	numansw = ntohs(rwh->dh.answer);
	numauth = ntohs(rwh->dh.nsrr);
	numaddi = ntohs(rwh->dh.additional);
	answers = numansw + numauth + numaddi;

	if (answers < 1) {	
		fprintf(stderr, "NO ANSWER provided\n");
		return -1;
	}


	q = build_question((char *)&wh->dh, len, wh->dh.additional);
	if (q == NULL) {
		fprintf(stderr, "failed to build_question\n");
		return -1;
	}
		
	if (memcmp(q->hdr->name, name, q->hdr->namelen) != 0) {
		fprintf(stderr, "question name not for what we asked\n");
		return -1;
	}

	if (q->hdr->qclass != *class || q->hdr->qtype != *type) {
		fprintf(stderr, "wrong class or type\n");
		return -1;
	}
	
	p = (u_char *)&rwh[1];		
	
	p += q->hdr->namelen;
	p += sizeof(u_int16_t);	 	/* type */
	p += sizeof(u_int16_t);		/* class */

	/* end of question */
	

	estart = (u_char *)&rwh->dh;

	for (i = answers; i > 0; i--) {
		if (numansw > 0) { 
			numansw--;
			if (printansw-- > 0) {
				printf(";; ANSWER SECTION:\n");
			}
			goto skip;
		}
		if (numansw <= 0 && numauth > 0) {
			numauth--;
			if (printauth-- > 0) {
				printf(";; AUTHORITY SECTION:\n");
			}
			goto skip;
		}
		if (numansw <= 0 && numauth <= 0 && numaddi > 0) {
			numaddi--;
			if (printaddi-- > 0) {
				printf(";; ADDITIONAL SECTION:\n");
			}
			goto skip;
		}

skip:


		if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, 0, &rdlen, format)) < 0) {
			fprintf(stderr, "not a SOA reply, or ERROR\n");
			return -1;
		}
		
		p = (estart + rrlen);

		if (rrtype == DNS_TYPE_SOA) {
			if ((len = raxfr_soa(f, p, estart, end, mysoa, soacount, format)) < 0) {
				fprintf(stderr, "raxxfr_soa failed\n");
				return -1;
			}
			p = (estart + len);
			soacount++;
		} else {
			for (sr = supported; sr->rrtype != 0; sr++) {
				if (rrtype == sr->rrtype) {
					if ((len = (*sr->raxfr)(f, p, estart, end, mysoa, rdlen)) < 0) {
						fprintf(stderr, "error with rrtype %d\n", sr->rrtype);
						return -1;
					}
					p = (estart + len);
					break;
				}
			}

			if (sr->rrtype == 0) {
				if (rrtype != 41)
					fprintf(stderr, "unsupported RRTYPE %u\n", rrtype);
			} 
		} /* rrtype == DNS_TYPE_SOA */


	} /* for () */

	return 0;
}



int	
start(int argc, char *argv[])
{
	struct stat sb;
	char buf[MAXPATHLEN];
	char *path = NULL;
	char *socketpath = SOCKPATH;
	char *configfile = CONFFILE;
	int ch;

	while ((ch = getopt(argc, argv, "f:s:")) != -1) {
		switch (ch) {
		case 'f':
			configfile = optarg;
			break;
		case 's':
			socketpath = optarg;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (lstat(socketpath, &sb) != -1) {
		fprintf(stderr, "%s exists, not clobbering\n", socketpath);
		exit(1);
	}
	

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

#if defined __OpenBSD__ || defined __FreeBSD__
	if (setresuid(0,0,0) < 0) {
		perror("setuid");
		exit(1);
	}
#else
        if (setgid(0) < 0) {
		perror("setgid");
                exit(1);
        }
        if (setuid(0) < 0) {
		perror("setuid");
                exit(1);
        }
#endif

	
	fprintf(stderr, "starting delphinusdnsd\n");

	path = realpath(configfile, buf);
	if (path == NULL) {
		perror("realpath");
		exit(1);
	}

	if (execl("/usr/local/sbin/delphinusdnsd", "delphinusdnsd", "-f", path, 
		"-s", socketpath, NULL) < 0) {
		perror("execl");
		exit(1);	
	}

	return 1;
}

int
command_socket(char *sockpath)
{
	int so;
	struct sockaddr_un sun;

	so = socket(AF_UNIX, SOCK_STREAM, 0);
	if (so < 0) {
		return -1;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		close(so);
		return -1;
	}
	sun.sun_len = SUN_LEN(&sun);

	if (connect(so, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(so);
		return -1;
	}

	return (so);
}

int	
restart(int argc, char *argv[])
{
	char buf[512];
	char *socketpath = SOCKPATH;
	struct dddcomm *dc;
	int so;
	int ch, len;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			socketpath = optarg;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

	fprintf(stderr, "restarting delphinusdnsd\n");

	if ((so = command_socket(socketpath)) < 0) {
		perror(socketpath);
		exit(1);
	}		

	memset(&buf, 0, sizeof(buf));
	dc = (struct dddcomm *)&buf[0];
	dc->command = IMSG_RELOAD_MESSAGE;
	if (send(so, buf, sizeof(struct dddcomm), 0) < 0) {
		perror("send");
		close(so);
		exit(1);
	}
	if ((len = recv(so, buf, sizeof(struct dddcomm), 0)) < 0) {
		perror("recv");
		close(so);
		exit(1);
	}
	close(so);
		
	return (0);
}

int	
stop(int argc, char *argv[])
{
	char buf[512];
	char *socketpath = SOCKPATH;
	struct dddcomm *dc;
	int so;
	int ch, len;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			socketpath = optarg;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

	fprintf(stderr, "stopping delphinusdnsd\n");

	if ((so = command_socket(socketpath)) < 0) {
		perror(socketpath);
		exit(1);
	}		

	memset(&buf, 0, sizeof(buf));
	dc = (struct dddcomm *)&buf[0];
	dc->command = IMSG_SHUTDOWN_MESSAGE;
	if (send(so, buf, sizeof(struct dddcomm), 0) < 0) {
		perror("send");
		close(so);
		exit(1);
	}
	if ((len = recv(so, buf, sizeof(struct dddcomm), 0)) < 0) {
		perror("recv");
		close(so);
		exit(1);
	}
	close(so);
		
	return (0);
}

int	
configtest(int argc, char *argv[])
{
	ddDB *db;
	char *zonefile = "/etc/delphinusdns.conf";

	if (argc == 2) {
		zonefile = argv[1];
	}

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif



	/* open the database(s) */
	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		return 1;
	}

	/* now we start reading our configfile */
		
	if (parse_file(db, zonefile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		return 1;
	}

	dddbclose(db);
	
	printf("OK\n");
	
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

pid_t 
getdaemonpid(void)
{
	FILE *f;
	char buf[512];
	int len;
	pid_t pid;

	f = fopen("/var/run/delphinusdnsd.pid", "r");
	if (f == NULL) {
		perror("fopen");
		exit(1);
	}

	if (fgets(buf, sizeof(buf), f) == NULL) {
		perror("fgets");
		exit(1);
	}
	
	fclose(f);

	len = strlen(buf);
	if (buf[len - 1] == '\n')
		len--;

	buf[len] = '\0';
	pid = atoi(buf);
	
	return (pid);
}

int	
sshfp(int argc, char *argv[])
{
	char buf[512];
	char *hostname = NULL;
	char *keyfile = NULL;
	FILE *po;
	char *p, *q;
	char *tmp;
	int len, ttl = 3600;
	int ch;

	if (argc < 2) {
		usage(argc, argv);
		exit(1);
	}

	hostname = argv[1];

	while ((ch = getopt(argc, argv, "f:k:t:")) != -1) {
		switch (ch) {
		case 'f':
			/* fallthrough */
		case 'k':
			keyfile = optarg;
			break;
		case 't':	
			ttl = atoi(optarg);
			break;

		}
	}

	if (keyfile)
		snprintf(buf, sizeof(buf), "/usr/bin/ssh-keygen -r %s -f %s", hostname, keyfile);
	else
		snprintf(buf, sizeof(buf), "/usr/bin/ssh-keygen -r %s", hostname);

	po = popen(buf, "r");
	if (po == NULL) {
		perror("popen");
		exit(1);
	}

	while (fgets(buf, sizeof(buf), po) != NULL) {
		len = strlen(buf);
		if (buf[len - 1] == '\n')
			len--;
		buf[len] = '\0';

		while ((p = strchr(buf, ' ')) != NULL) {
			*p = ',';
		}
	
		q = strrchr(buf, ',');
		if (q == NULL) {
			continue;
		}

		q++;
		if (*q == '\0') {
			continue;
		}

		tmp = strdup(q);
		if (tmp == NULL) {
			perror("strdup");
			exit(1);
		}
		*q = '\0';

		p = strchr(buf, ',');
		if (p == NULL) {
			continue;
		}
	
		q = strchr(p, ',');
		if (q == NULL) {
			continue;
		}

		q += 10;

		printf("  %s.,sshfp,%d,%s\"%s\"\n", hostname, ttl, q, tmp);
		free(tmp);
	}

	pclose(po);

	exit(0);	
}

int
dump_db_bind(ddDB *db, FILE *of, char *zonename)
{
	int j, rs;

        ddDBT key, data;
	
	struct node *n, *nx;
	struct question *q;
	struct domain *sdomain;
	
	char replystring[512];
	char *dnsname;
	int labellen;
	int lzerrno, retval;

	fprintf(of, ";; This file was generated by dddctl.c of delphinusdnsd\n");

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_SOA);
	if (q == NULL) {
		return -1;
	}

	if ((sdomain = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	if (print_sd_bind(of, sdomain) < 0) {
		fprintf(stderr, "print_sd_bind error\n");
		return -1;
	}
	
	memset(&key, 0, sizeof(key));   
	memset(&data, 0, sizeof(data));

	j = 0;
	RB_FOREACH_SAFE(n, domaintree, &rbhead, nx) {
		rs = n->datalen;
		if ((sdomain = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sdomain, (char *)n->data, n->datalen);

		if (strcmp(convert_name(sdomain->zone, sdomain->zonelen), zonename) == 0)
			continue;

		if (print_sd_bind(of, sdomain) < 0) {
			fprintf(stderr, "print_sd_bind error\n");
			return -1;
		}


		j++;
	} 

#if DEBUG
	printf("%d records\n", j);
#endif
	return (0);
}

/*
 * dump the RR's in BIND format 
 */

int
print_sd_bind(FILE *of, struct domain *sdomain)
{
	int i, x, len;

	struct domain_soa *sdsoa;
	struct domain_ns *sdns;
	struct domain_mx *sdmx;
	struct domain_a *sda;
	struct domain_aaaa *sdaaaa;
	struct domain_cname *sdcname;
	struct domain_ptr *sdptr;
	struct domain_txt *sdtxt;
	struct domain_naptr *sdnaptr;
	struct domain_srv *sdsrv;
	struct domain_rrsig *sdrr;
	struct domain_dnskey *sddk;
	struct domain_ds *sdds;
	struct domain_nsec3 *sdn3;
	struct domain_nsec3param *sdn3param;
	struct domain_sshfp *sdsshfp;
	struct domain_tlsa *sdtlsa;
	struct rrsig *rss;
	
	char buf[4096];

	if (sdomain->flags & DOMAIN_HAVE_SOA) {
		if ((sdsoa = (struct domain_soa *)find_substruct(sdomain, INTERNAL_TYPE_SOA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN SOA %s %s (\n\t\t\t\t%u\t; Serial\n\t\t\t\t%d\t; Refresh\n\t\t\t\t%d\t; Retry\n\t\t\t\t%d\t; Expire\n\t\t\t\t%d )\t; Minimum TTL\n\n", 
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_SOA],
			convert_name(sdsoa->soa.nsserver, sdsoa->soa.nsserver_len),
			convert_name(sdsoa->soa.responsible_person, sdsoa->soa.rp_len),
			sdsoa->soa.serial, sdsoa->soa.refresh, sdsoa->soa.retry, 
			sdsoa->soa.expire, sdsoa->soa.minttl);
	}
	if (sdomain->flags & DOMAIN_HAVE_NS) {
		if ((sdns = (struct domain_ns *)find_substruct(sdomain, INTERNAL_TYPE_NS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdns->ns_count; i++) {
			fprintf(of, "%s %d IN NS %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NS],
				convert_name(sdns->ns[i].nsserver, sdns->ns[i].nslen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_MX) {
		if ((sdmx = (struct domain_mx *)find_substruct(sdomain, INTERNAL_TYPE_MX)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdmx->mx_count; i++) {
			fprintf(of, "%s %d IN MX %d %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_MX],
				sdmx->mx[i].preference,
				convert_name(sdmx->mx[i].exchange, sdmx->mx[i].exchangelen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DS) {
		if ((sdds = (struct domain_ds *)find_substruct(sdomain, INTERNAL_TYPE_DS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdds->ds_count; i++) {
			fprintf(of, "%s %d IN DS %d %d %d (%s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DS],
				sdds->ds[i].key_tag,
				sdds->ds[i].algorithm,
				sdds->ds[i].digest_type,
				bin2hex(sdds->ds[i].digest, sdds->ds[i].digestlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_CNAME) {
		if ((sdcname = (struct domain_cname *)find_substruct(sdomain, INTERNAL_TYPE_CNAME)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN CNAME %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_CNAME],
				convert_name(sdcname->cname, sdcname->cnamelen));
	}
	if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
		if ((sdnaptr = (struct domain_naptr *)find_substruct(sdomain, INTERNAL_TYPE_NAPTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdnaptr->naptr_count; i++) {
			fprintf(of, "%s %d IN NAPTR %d\t%d\t\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NAPTR],
				sdnaptr->naptr[i].order,
				sdnaptr->naptr[i].preference);
			
			for (x = 0; x < sdnaptr->naptr[i].flagslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].flags[x]);
			}
			fprintf(of, "\"\t\"");
			for (x = 0; x < sdnaptr->naptr[i].serviceslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].services[x]);
			}
			fprintf(of, "\"\t\"");
			for (x = 0; x < sdnaptr->naptr[i].regexplen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].regexp[x]);
			}
			fprintf(of, "\"\t%s\n", (sdnaptr->naptr[i].replacement[0] == '\0') ? "." : convert_name(sdnaptr->naptr[i].replacement, sdnaptr->naptr[i].replacementlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TXT) {
		if ((sdtxt = (struct domain_txt *)find_substruct(sdomain, INTERNAL_TYPE_TXT)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN TXT \"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TXT]);
		for (i = 0; i < sdtxt->txtlen; i++) {
			fprintf(of, "%c", sdtxt->txt[i]);
		}
		fprintf(of, "\"\n");
	}
	if (sdomain->flags & DOMAIN_HAVE_PTR) {
		if ((sdptr = (struct domain_ptr *)find_substruct(sdomain, INTERNAL_TYPE_PTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN PTR %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_PTR],
				convert_name(sdptr->ptr, sdptr->ptrlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_SRV) {
		if ((sdsrv = (struct domain_srv *)find_substruct(sdomain, INTERNAL_TYPE_SRV)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsrv->srv_count; i++) {
			fprintf(of, "%s %d IN SRV %d %d %d %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SRV],
				sdsrv->srv[i].priority,
				sdsrv->srv[i].weight,
				sdsrv->srv[i].port,
				convert_name(sdsrv->srv[i].target,sdsrv->srv[i].targetlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TLSA) {
		if ((sdtlsa = (struct domain_tlsa *)find_substruct(sdomain, INTERNAL_TYPE_TLSA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdtlsa->tlsa_count; i++) {
			fprintf(of, "%s %d IN TLSA %d %d %d (%s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TLSA],
				sdtlsa->tlsa[i].usage,
				sdtlsa->tlsa[i].selector,
				sdtlsa->tlsa[i].matchtype,
				bin2hex(sdtlsa->tlsa[i].data, sdtlsa->tlsa[i].datalen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
		if ((sdsshfp = (struct domain_sshfp *)find_substruct(sdomain, INTERNAL_TYPE_SSHFP)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsshfp->sshfp_count; i++) {
			fprintf(of, "%s %d IN SSHFP %d %d (%s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SSHFP],
				sdsshfp->sshfp[i].algorithm,
				sdsshfp->sshfp[i].fptype,
				bin2hex(sdsshfp->sshfp[i].fingerprint, sdsshfp->sshfp[i].fplen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_A) {
		if ((sda = (struct domain_a *)find_substruct(sdomain, INTERNAL_TYPE_A)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sda->a_count; i++) {
			inet_ntop(AF_INET, &sda->a[i], buf, sizeof(buf));
			fprintf(of, "%s %d IN A %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_A],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_AAAA) {
		if ((sdaaaa = (struct domain_aaaa *)find_substruct(sdomain, INTERNAL_TYPE_AAAA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdaaaa->aaaa_count; i++) {
			inet_ntop(AF_INET6, &sdaaaa->aaaa[i], buf, sizeof(buf));
			fprintf(of, "%s %d IN AAAA %s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_AAAA],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DNSKEY) {
#if DEBUG
		printf(" has dnskey\n");
#endif
		if ((sddk = (struct domain_dnskey *)find_substruct(sdomain, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sddk->dnskey_count; i++) {
			len = mybase64_encode(sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "%s %d IN DNSKEY %d %d %d (%s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DNSKEY],
				sddk->dnskey[i].flags,
				sddk->dnskey[i].protocol,
				sddk->dnskey[i].algorithm,
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
#if DEBUG
		printf("has nsec3param\n");
#endif
		if ((sdn3param = (struct domain_nsec3param *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
			dolog(LOG_INFO, "no nsec3param in zone!\n");
			return -1;
		}
		
		fprintf(of, "%s 0 IN NSEC3PARAM %d %d %d (%s)\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdn3param->nsec3param.algorithm,
			sdn3param->nsec3param.flags,
			sdn3param->nsec3param.iterations,
			(sdn3param->nsec3param.saltlen == 0) ? "-" : bin2hex(sdn3param->nsec3param.salt, sdn3param->nsec3param.saltlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
#if DEBUG
		printf("has nsec3\n");
#endif
		if ((sdn3 = (struct domain_nsec3 *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3)) == NULL) {
			dolog(LOG_INFO, "no nsec3 in zone!\n");
			return -1;
		}
		
		fprintf(of, "%s %d IN NSEC3 %d %d %d %s %s %s\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_NSEC3],
			sdn3->nsec3.algorithm,
			sdn3->nsec3.flags,
			sdn3->nsec3.iterations,
			(sdn3->nsec3.saltlen == 0) ? "-" : bin2hex(sdn3->nsec3.salt, sdn3->nsec3.saltlen),
			base32hex_encode(sdn3->nsec3.next, sdn3->nsec3.nextlen),
			bitmap2human(sdn3->nsec3.bitmap, sdn3->nsec3.bitmap_len));

	}
	if (sdomain->flags & DOMAIN_HAVE_RRSIG) {
#if DEBUG
		printf(" has rrsig\n");
#endif
		
		if ((sdrr = (struct domain_rrsig *)find_substruct(sdomain, INTERNAL_TYPE_RRSIG)) == NULL) {
			dolog(LOG_INFO, "no rrsigs in zone!\n");
			return -1;
		}

		if ((sdomain->flags & DOMAIN_HAVE_DNSKEY) && sdrr->rrsig_dnskey_count > 0) {
			for (i = 0; i < sdrr->rrsig_dnskey_count; i++) {
				rss = (struct rrsig *)&sdrr->rrsig_dnskey[i];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
					convert_name(sdomain->zone, sdomain->zonelen),
					sdomain->ttl[INTERNAL_TYPE_DNSKEY],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}
		}
		if (sdomain->flags & DOMAIN_HAVE_SOA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SOA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl,
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_DS) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_DS];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}



		if (sdomain->flags & DOMAIN_HAVE_TLSA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TLSA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SSHFP];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_SRV) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SRV];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN rrsig (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NAPTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_TXT) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TXT];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_AAAA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_AAAA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone,sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}


		if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3PARAM];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s 0 IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				0, /* original ttl */
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_CNAME) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_CNAME];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_PTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_PTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}



		if (sdomain->flags & DOMAIN_HAVE_NS) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NS];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_MX) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_MX];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}

		if (sdomain->flags & DOMAIN_HAVE_A) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_A];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
				convert_name(sdomain->zone, sdomain->zonelen), 
				rss->original_ttl, 
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				convert_name(rss->signers_name, rss->signame_len),
				buf);	
		}
	}

	return 0;
}

int	
bindfile(int argc, char *argv[])
{
	ddDB *db;
	char *zonefile;
	char *zonename;
	FILE *of = stdout;
	int len;

	if (argc != 3) {
		usage(argc, argv);
		exit(1);
	}

	zonename = argv[1];
	zonefile = argv[2];

	len = strlen(zonename);
	if (zonename[len - 1] != '.') {
		len += 2;
		zonename = malloc(len);
		if (zonename == NULL) {
			perror("malloc");
			return 1;
		}

		strlcpy(zonename, argv[1], len);
		strlcat(zonename, ".", len);
	}
			

#if __OpenBSD__
	if (pledge("stdio rpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif



	/* open the database(s) */
	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		return 1;
	}

	/* now we start reading our configfile */
		
	if (parse_file(db, zonefile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		return 1;
	}

	if (dump_db_bind(db, of, zonename) < 0) {
		dddbclose(db);
		return 1;
	}

	dddbclose(db);
	
	
	return 0;
}

char *
get_key(struct keysentry *kn, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int keylen, int *keyid)
{
	*ttl = kn->ttl;
	*flags = kn->flags;
	*protocol = kn->protocol;
	*algorithm = kn->algorithm;
	*keyid = kn->keyid;
	
	strlcpy(key, kn->key, keylen);
	
	return (kn->zone);
}

char *
key2zone(char *keyname, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int *keyid)
{
	int fd;
	char *zone;
	char buf[MAXPATHLEN];

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
