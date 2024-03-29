/*
 * Copyright (c) 2020-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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

#include <sys/param.h>
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


#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-config.h"
#include "ddd-crypto.h"


SLIST_HEAD(, keysentry) keyshead;

static struct keysentry {
	char *keypath;
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
	DDD_BIGNUM *rsan;
	DDD_BIGNUM *rsae;
	DDD_BIGNUM *rsad;
	DDD_BIGNUM *rsap;
	DDD_BIGNUM *rsaq;
	DDD_BIGNUM *rsadmp1;
	DDD_BIGNUM *rsadmq1;
	DDD_BIGNUM *rsaiqmp;

	/* private key Elliptic Curve */

	BIGNUM *ecprivate;

	/* private and public keys for ED25519 */
	uint8_t ed_private[DDD_ED25519_PRIVATE_KEY_LENGTH];
	uint8_t ed_public[DDD_ED25519_PUBLIC_KEY_LENGTH];

        SLIST_ENTRY(keysentry) keys_entry;
} *kn, *knp;


struct mynsec {
		char *name;
		char *nextname;
		char *bitmap;
		RB_ENTRY(mynsec) entries;
} *n1, *n2, *np;

extern	int 		count_dots(char *name);

static int
slcmp(void *a, void *b)
{
	char aname[DNS_MAXNAME + 1];
	char bname[DNS_MAXNAME + 1];
	char *a2name = ((struct mynsec *)a)->name;
	char *b2name = ((struct mynsec *)b)->name;
	int dots0, dots1;
	int ret;

	memset(&aname, 0, sizeof(aname));
	memset(&bname, 0, sizeof(bname));
	memcpy(&aname, a2name, sizeof(aname) - 1);
	memcpy(&bname, b2name, sizeof(bname) - 1);

	/* count the dots we need this for canonical compare */

	dots0 = count_dots(a2name);
	dots1 = count_dots(b2name);

	if (dots0 > dots1)
		return 1;
	else if (dots1 > dots0)
		return -1;

	ret = strcmp(a2name, b2name);

	return (ret);
}


RB_HEAD(nsectree, mynsec) nsechead = RB_INITIALIZER(&nsechead);
RB_PROTOTYPE(nsectree, mynsec, entries, slcmp)
RB_GENERATE(nsectree, mynsec, entries, slcmp)


/* prototypes */

int	add_dnskey(ddDB *);
int	add_zonemd(ddDB *, char *, int);
int	fixup_zonemd(ddDB *, char *, int, int);
char * 	parse_keyfile(int, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  key2zone(struct keysentry *, char *, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *  get_key(struct keysentry *,uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int, int *);

char *	create_key(char *, int, int, int, int, uint32_t *);
char *	create_key_rsa(char *, int, int, int, int, uint32_t *);
char *	create_key_ec(char *, int, int, int, int, uint32_t *);
char *  create_key_ed25519(char *, int, int, int, int, uint32_t *);
int	create_key_ec_getpid(DDD_EC_KEY *, DDD_EC_GROUP *, DDD_EC_POINT *, int, int);
int	create_key_ed_getpid(uint8_t *, int, int);

char * 	alg_to_name(int);
int 	alg_to_rsa(int);

int 	construct_nsec3(ddDB *, char *, int, char *);
int	construct_nsec(ddDB *, char *);
int 	calculate_rrsigs(ddDB *, char *, int, int);

static int	sign_hinfo(ddDB *, char *, int, struct rbtree *, int);
static int	sign_zonemd(ddDB *, char *, int, struct rbtree *, int);
static int	sign_rp(ddDB *, char *, int, struct rbtree *, int);
static int	sign_caa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_dnskey(ddDB *, char *, int, struct rbtree *, int);
static int	sign_cdnskey(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_cert(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_a(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_eui48(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_eui64(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_mx(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_kx(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_ipseckey(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_ns(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_srv(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_cname(ddDB *, char *, int, struct rbtree *, int);
static int 	sign_soa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_txt(ddDB *, char *, int, struct rbtree *, int);
static int	sign_svcb(ddDB *, char *, int, struct rbtree *, int);
static int	sign_https(ddDB *, char *, int, struct rbtree *, int);
static int	sign_aaaa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_ptr(ddDB *, char *, int, struct rbtree *, int);
static int	sign_nsec3(ddDB *, char *, int, struct rbtree *, int);
static int	sign_nsec3param(ddDB *, char *, int, struct rbtree *, int);
static int	sign_nsec(ddDB *, char *, int, struct rbtree *, int);
static int	sign_naptr(ddDB *, char *, int, struct rbtree *, int);
static int	sign_sshfp(ddDB *, char *, int, struct rbtree *, int);
static int	sign_tlsa(ddDB *, char *, int, struct rbtree *, int);
static int	sign_loc(ddDB *, char *, int, struct rbtree *, int);
static int	sign_ds(ddDB *, char *, int, struct rbtree *, int);
static int	sign_cds(ddDB *, char *, int, struct rbtree *, int);


int 		sign(int, char *, int, struct keysentry *, char *, int *);
int 		create_ds(ddDB *, char *, struct keysentry *);
u_int 		keytag(u_char *key, u_int keysize);
u_int 		dnskey_keytag(struct dnskey *dnskey);
void		free_private_key(struct keysentry *);
DDD_RSA * 	get_private_key_rsa(struct keysentry *);
DDD_EC_KEY *	get_private_key_ec(struct keysentry *);
uint8_t *	get_private_key_ed25519(struct keysentry *);
uint8_t *	get_public_key_ed25519(struct keysentry *);
int		store_private_key(struct keysentry *, char *, int, int);
int 		print_rbt(FILE *, struct rbtree *);
int 		print_rbt_bind(FILE *, struct rbtree *);
int		signmain(int argc, char *argv[]);
void 		init_keys(void);
uint32_t 	getkeypid(struct keysentry *, char *);
void		update_soa_serial(ddDB *, char *, time_t);
void		debug_bindump(const char *, int);
int 		dump_db(ddDB *, FILE *, char *);
int		notglue(ddDB *, struct rbtree *, char *);
static int 	rbt_isapex(struct rbtree *, char *);

/* externs */

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
extern uint64_t expiredon, signedon;
extern int dnssec;
extern int tsig;


extern char *			canonical_sort(char **, int, int *);
extern char *			cert_type(struct cert *);
extern char *			ipseckey_type(struct ipseckey *);
extern char *			param_tlv2human(char *, int, int);
extern char *			bin2hex(char *, int);
extern char *			bitmap2human(char *, int);
extern char *			base32hex_encode(u_char *, int);
extern char *			convert_name(char *, int);
extern char *			dns_label(char *, int *);
extern char *			hash_name(char *, int, struct nsec3param *);
extern char *			get_dns_type(int, int);
extern ddDB *			dddbopen(void);
extern ddDB *			opendatabase(ddDB *);
extern int			check_ent(char *, int);
extern int			init_entlist(ddDB *);
extern int			memcasecmp(u_char *, u_char *, int);
extern int			mybase64_decode(char const *, u_char *, size_t);
extern int			mybase64_encode(u_char const *, size_t, char *, size_t);
extern int			add_rr(struct rbtree *, char *, int, uint16_t, void *);
extern int			fill_dnskey(ddDB *,char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *, uint16_t);
extern int			fill_nsec(ddDB *, char *, char *, uint32_t, char *, char *);
extern int			fill_nsec3(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *, char *, char *, char *);
extern int			fill_nsec3param(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *);
extern int			fill_rrsig(ddDB *,char *, char *, uint32_t, char *, uint8_t, uint8_t, uint32_t, uint64_t, uint64_t, uint16_t, char *, char *);
extern int			fill_zonemd(ddDB *, char *, char *, int, uint32_t, uint8_t, uint8_t, char *, int);
extern int			insert_axfr(char *, char *);
extern int			insert_filter(char *, char *);
extern int			insert_notifyddd(char *, char *);
extern int			insert_passlist(char *, char *);
extern int			label_count(char *);
extern int			parse_file(ddDB *, char *, uint32_t, int);
extern size_t			plength(void *, void *);
extern struct question *	build_fake_question(char *, int, uint16_t, char *, int);
extern struct rbtree *		Lookup_zone(ddDB *, char *, int, int, int);
extern struct rbtree *		find_rrset(ddDB *, char *, int);
extern struct rrset *		find_rr(struct rbtree *, uint16_t);
extern struct zonemd *		zonemd_hash_zonemd(struct rrset *, struct rbtree *);
extern uint16_t			unpack16(char *);
extern uint32_t			unpack32(char *);
extern uint64_t			timethuman(time_t);
extern void			dolog(int, char *, ...);
extern void			pack(char *, char *, int);
extern void			pack16(char *, uint16_t);
extern void			pack32(char *, uint32_t);
extern void			pack8(char *, uint8_t);
extern void			unpack(char *, char *, int);
extern void			zonemd_hash_a(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_aaaa(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_caa(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_cdnskey(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_cds(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_cert(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_cname(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_dnskey(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_ds(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_eui48(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_eui64(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_hinfo(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_https(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_ipseckey(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_kx(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_loc(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_mx(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_naptr(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_ns(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_nsec(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_nsec3(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_nsec3param(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_ptr(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_rp(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_rrsig(SHA512_CTX *, struct rrset *, struct rbtree *, int);
extern void			zonemd_hash_soa(SHA512_CTX *, struct rrset *, struct rbtree *, uint32_t *);
extern void			zonemd_hash_srv(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_sshfp(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_svcb(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_tlsa(SHA512_CTX *, struct rrset *, struct rbtree *);
extern void			zonemd_hash_txt(SHA512_CTX *, struct rrset *, struct rbtree *);


/* Aliases */

#define ROLLOVER_METHOD_PRE_PUBLICATION		0
#define ROLLOVER_METHOD_DOUBLE_SIGNATURE	1

#define KEYTYPE_NONE	0
#define KEYTYPE_KSK 	1
#define KEYTYPE_ZSK	2

#define SCHEME_OFF	0
#define SCHEME_YYYY	1
#define SCHEME_TSTAMP	2

#define ALGORITHM_RSASHA256		8	/* rfc 5702 */
#define ALGORITHM_RSASHA512		10	/* rfc 5702 */
#define ALGORITHM_ECDSAP256SHA256	13	/* rfc 6605 */
#define ALGORITHM_ECDSAP384SHA384	14	/* rfc 6605 */
#define ALGORITHM_ED25519		15	/* rfc 8080 */

#define DDD_RSA_F5			0x100000001

#define PROVIDED_SIGNTIME			0
#define	SIGNEDON				20161230073133
#define EXPIREDON 				20170228073133

#define SIGNEDON_DRIFT				(14 * 86400)
#define DEFAULT_EXPIRYTIME			(60 * 86400)

#define DEFAULT_TTL				3600
#define DEFAULT_BITS				3072
#define DEFAULT_NSEC				3

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
 * ZONEMD - the heart of dddctl zonemd ...
 */

int
zonemd(int argc, char *argv[])
{
	FILE *of = stdout;
	int ch, checkhash = 0;

	char *zonefile = NULL;
	char *zonename = NULL;

	uint32_t parseflags = PARSEFILE_FLAG_NOSOCKET;
	struct stat sb;
	
	ddDB *db;

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif


	while ((ch = getopt(argc, argv, "cn:o:")) != -1) {
		switch (ch) {
		case 'c':
			checkhash = 1;
			break;			
		case 'n':
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
		}
	}

	argc -= optind;
	argv += optind;

	zonefile = argv[0];

	if (zonefile == NULL || zonename == NULL) {
		fprintf(stderr, "must provide a zonefile and a zonename!\n");
		exit(1);
	}

	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		exit(1);
	}

	/* now we start reading our configfile */
		
	if (parse_file(db, zonefile, parseflags, -1) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		exit(1);
	}

	/* add zonemd to zone */

	if (! checkhash) {
		add_zonemd(db, zonename, 0);
	
		/* write new zone file */
		if (dump_db(db, of, zonename) < 0)
			exit (1);
	} else {
		if (add_zonemd(db, zonename, 1) == 0) {
			printf("(ZONEMD) %s: OK\n", zonename);
		} else {
			fprintf(stderr, "(ZONEMD) %s: FAILED\n", zonename);
			exit(1);
		}
	}

	return 0;
}


/*
 * SIGNMAIN - the heart of dddctl sign ...
 */

#ifdef DDD_NOSIGN
int
signmain(int argc, char *argv[])
{
	kn = NULL;
	knp = NULL; 	/* squelch warnings */

	fprintf(stderr, "signing has been disabled in dddctl\n");
	exit(1);
}
#else
int
signmain(int argc, char *argv[])
{
	FILE *of = stdout;
	struct stat sb;

	int ch;
	int bits = DEFAULT_BITS;
	int ttl = DEFAULT_TTL;
	int nsec = DEFAULT_NSEC;
	int create_zsk = 0;
	int create_ksk = 0;
	int rollmethod = ROLLOVER_METHOD_PRE_PUBLICATION;
	int algorithm = ALGORITHM_ECDSAP256SHA256;
	int expiry = DEFAULT_EXPIRYTIME;
	int iterations = 10;
	int zonemd = 0;
	uint32_t mask = (MASK_PARSE_FILE | MASK_ADD_DNSKEY | MASK_CONSTRUCT_NSEC3 | MASK_CALCULATE_RRSIGS | MASK_CREATE_DS | MASK_DUMP_DB);

	char *salt = "-";
	char *zonefile = NULL;
	char *zonename = NULL;
	char *ep;
	char *p;
	
	int ksk_key = 0, zsk_key = 0;
	int numkeys = 0, search = 0;

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


	while ((ch = getopt(argc, argv, "a:B:e:hI:i:Kk:Mm:N:n:o:R:S:s:t:vXx:Zz:")) != -1) {
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
			kn->keypath = strdup(optarg);
			if (kn->keypath == NULL) {
				perror("strdup");
				exit(1);
			}
			p = strrchr(kn->keypath, '/');
			if (p == NULL) {
				free(kn->keypath);
				kn->keypath = NULL;

				kn->keyname = strdup(optarg);
				if (kn->keyname == NULL) {
					perror("strdup");
					exit(1);
				}
			} else {
				*p = '\0';
				p++;
				
				if (*p != '\0') {
					kn->keyname = strdup(p);
					if (kn->keyname == NULL) {
						perror("strdup");
						exit(1);
					}
				}
			}
			

			kn->type = KEYTYPE_KSK;
			kn->pid = getkeypid(kn, kn->keyname);
#if DEBUG
			printf("opened %s with pid %u\n", kn->keyname, kn->pid);
#endif
			kn->sign = 0;
			ksk_key = 1;

			if ((key_zone = key2zone(kn, kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
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
			break;

		case 'M':
			zonemd = 1;
			break;

		case 'm':
			/* mask */
			mask = strtoull(optarg, &ep, 16); 
			break;

		case 'N':
			nsec = atoi(optarg);
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
			kn->keypath = strdup(optarg);
			if (kn->keypath == NULL) {
				perror("strdup");
				exit(1);
			}
			p = strrchr(kn->keypath, '/');
			if (p == NULL) {
				free(kn->keypath);
				kn->keypath = NULL;

				kn->keyname = strdup(optarg);
				if (kn->keyname == NULL) {
					perror("strdup");
					exit(1);
				}
			} else {
				*p = '\0';
				p++;
				
				if (*p != '\0') {
					kn->keyname = strdup(p);
					if (kn->keyname == NULL) {
						perror("strdup");
						exit(1);
					}
				}
			}

			kn->type = KEYTYPE_ZSK;
			kn->pid = getkeypid(kn, kn->keyname);
#if DEBUG
			printf("opened %s with pid %u\n", kn->keyname, kn->pid);
#endif
			kn->sign = 0;
			zsk_key = 1;

			if ((key_zone = key2zone(kn, kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
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

			break;
		}
	
	}


	if (zonename == NULL) {
		fprintf(stderr, "must provide a zonename with the -n flag\n");
		exit(1);
	}

	if (create_ksk) {
		kn = calloc(sizeof(struct keysentry), 1);
		if (kn == NULL) {
			perror("calloc");
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
		
		if ((key_zone = key2zone(kn, kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
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
	}
	if (create_zsk) {
		kn = calloc(sizeof(struct keysentry), 1);
		if (kn == NULL) {
			perror("calloc");
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
	
		if ((key_zone = key2zone(kn, kn->keyname, &key_ttl, &key_flags, &key_protocol, &key_algorithm, (char *)&key_key, &key_keyid)) == NULL) {
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
		
	if ((mask & MASK_PARSE_FILE) && parse_file(db, zonefile, parseflags, -1) < 0) {
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

	/* add RFC 8976 ZONEMD placeholder */
	if (zonemd) {
		add_zonemd(db, zonename, 0);
	}

	/* three passes to "sign" our zones */
	/* first pass, add dnskey records, on apex */

	if ((mask & MASK_ADD_DNSKEY) && add_dnskey(db) < 0) {
		dolog(LOG_INFO, "add_dnskey failed\n");
		exit(1);
	}

	/* second pass construct NSEC3 records, including ENT's */	

	switch (nsec) {
	case DEFAULT_NSEC:			/* NSEC3 is default */
		if ((mask & MASK_CONSTRUCT_NSEC3) && 
			construct_nsec3(db, zonename, iterations, salt) < 0) {
			dolog(LOG_INFO, "construct nsec3 failed\n");
			exit(1);
		}

		break;
	case 1:
		if ((mask & MASK_CONSTRUCT_NSEC3) &&
			construct_nsec(db, zonename) < 0) {
			dolog(LOG_INFO, "construct nsec failed\n");
			exit(1);
		}

		break;
	default:
		dolog(LOG_INFO, "unknown nsec version %d\n", nsec);
		exit(1);
		break;
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

	/* fixup zonemd */
	if (zonemd) {
		if (fixup_zonemd(db, zonename, expiry, rollmethod) < 0)
			exit(1);
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
#endif /* NOSIGN */



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
			if (fill_dnskey(db, zone, "dnskey", ttl, flags, protocol, algorithm, key, DNS_TYPE_DNSKEY) < 0) {
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
			if (fill_dnskey(db, zone, "dnskey", ttl, flags, protocol, algorithm, key, DNS_TYPE_DNSKEY) < 0) {
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
	int rs;

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

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		if (rbt->zonelen == rbt0->zonelen && 
			memcasecmp((u_char *)rbt->zone, (u_char *)rbt0->zone, rbt->zonelen) == 0) {
			continue;
		}

		if (print_rbt(of, rbt) < 0) {
			fprintf(stderr, "print_rbt error\n");
			return -1;
		}

	} 

	fprintf(of, "}\n");

	return (0);
}

char *	
create_key(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	switch (algorithm) {
	case ALGORITHM_RSASHA256:
	case ALGORITHM_RSASHA512:
		return (create_key_rsa(zonename, ttl, flags, algorithm, bits, pid));
		break;
	case ALGORITHM_ECDSAP256SHA256:
	case ALGORITHM_ECDSAP384SHA384:
		return (create_key_ec(zonename, ttl, flags, algorithm, bits, pid));
		break;
	case ALGORITHM_ED25519:
		return (create_key_ed25519(zonename, ttl, flags, algorithm, bits, pid));
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
	DDD_EC_KEY *eckey;
	DDD_EC_GROUP *ecgroup;
	const DDD_BIGNUM *ecprivatekey;
	const DDD_EC_POINT *ecpublickey;

	struct stat sb;

	char bin[4096];
	char b64[4096];
	char tmp[4096];
	char buf[512];
	char *retval;
	char *p;

	int binlen;

	mode_t savemask;
	time_t now;
	struct tm *tm;

	switch (algorithm) {
	case ALGORITHM_ECDSAP256SHA256:
	case ALGORITHM_ECDSAP384SHA384:
		break;
	default:
		return NULL;	
		break;
	}

	eckey = delphinusdns_EC_KEY_new();
	if (eckey == NULL) {
		dolog(LOG_ERR, "EC_KEY_new(): %s\n", strerror(errno));
		return NULL;
	}

	switch (algorithm) {
	case ALGORITHM_ECDSAP256SHA256:
		ecgroup = delphinusdns_EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		break;
	default:
		ecgroup = delphinusdns_EC_GROUP_new_by_curve_name(NID_secp384r1);
		break;
	}

	if (ecgroup == NULL) {
		dolog(LOG_ERR, "EC_GROUP_new_by_curve_name(): %s\n", strerror(errno));
		delphinusdns_EC_KEY_free(eckey);
		return NULL;
	}

	if (delphinusdns_EC_KEY_set_group(eckey, ecgroup) != 1) {
		dolog(LOG_ERR, "EC_KEY_set_group(): %s\n", strerror(errno));	
		goto out;
	}

	if (delphinusdns_EC_KEY_generate_key(eckey) == 0) {
		dolog(LOG_ERR, "EC_KEY_generate_key(): %s\n", strerror(errno));	
		goto out;
	}

	ecprivatekey = delphinusdns_EC_KEY_get0_private_key(eckey);
	if (ecprivatekey == NULL) {
		dolog(LOG_INFO, "EC_KEY_get0_private_key(): %s\n", strerror(errno));
		goto out;
	}

	ecpublickey = delphinusdns_EC_KEY_get0_public_key(eckey);
	if (ecpublickey == NULL) {
		dolog(LOG_ERR, "EC_KEY_get0_public_key(): %s\n", strerror(errno));
		goto out;
	}
		
	*pid = create_key_ec_getpid(eckey, ecgroup, (DDD_EC_POINT *)ecpublickey, algorithm, flags);
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
		delphinusdns_EC_GROUP_free(ecgroup);
		delphinusdns_EC_KEY_free(eckey);
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
	binlen = delphinusdns_BN_bn2bin(ecprivatekey, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
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

	if ((binlen = delphinusdns_EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, (u_char *)tmp, sizeof(tmp), NULL)) == 0) {
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

	mybase64_encode((const u_char *)p, binlen, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);

	delphinusdns_EC_GROUP_free(ecgroup);
	delphinusdns_EC_KEY_free(eckey);
	
	return (retval);

out:
	delphinusdns_EC_GROUP_free(ecgroup);
	delphinusdns_EC_KEY_free(eckey);
	
	return NULL;
}

char *
create_key_ed25519(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	FILE *f;
	uint8_t ed_private[DDD_ED25519_PRIVATE_KEY_LENGTH];
	uint8_t ed_public[DDD_ED25519_PUBLIC_KEY_LENGTH];

	struct stat sb;

	char bin[4096];
	char b64[4096];
	char buf[512];
	char *retval;

	mode_t savemask;
	time_t now;
	struct tm *tm;

	if (algorithm != ALGORITHM_ED25519) {
		return NULL;
	}

	/* XXX create Ed keys here */
	delphinusdns_ED25519_keypair((uint8_t *)&ed_public, (uint8_t *)&ed_private);

	/* insert keys here */
	*pid = create_key_ed_getpid((uint8_t *)&ed_public, algorithm, flags);
	if (*pid == -1) {
		dolog(LOG_ERR, "create_key_ed_getpid(): %s\n", strerror(errno));
		goto out;
	}

	/* check for collisions, XXX should be rare */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->pid == *pid)
			break;
	}

	if (knp != NULL) {
		dolog(LOG_INFO, "create_key: collision with existing pid %d\n", *pid);
		return (create_key_ed25519(zonename, ttl, flags, algorithm, bits, pid));
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
	mybase64_encode((const u_char *)&ed_private, DDD_ED25519_PRIVATE_KEY_LENGTH, b64, sizeof(b64));
	fprintf(f, "PrivateKey: %s\n", b64);

	now = time(NULL);
	tm = gmtime(&now);
	
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	fprintf(f, "Created: %s\n", buf);
	fprintf(f, "Publish: %s\n", buf);
	fprintf(f, "Activate: %s\n", buf);
	fclose(f);

	/* now for the ED25519 public key */

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

	mybase64_encode((const u_char *)&ed_public, DDD_ED25519_PUBLIC_KEY_LENGTH, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);

	explicit_bzero((u_char *)&ed_private, DDD_ED25519_PRIVATE_KEY_LENGTH);
	explicit_bzero((u_char *)&b64, sizeof(b64));

	return (retval);

out:
	return NULL;
}

int
create_key_ed_getpid(uint8_t *public_key, int algorithm, int flags)
{
	int binlen;
	char bin[4096];
	char *p;

	p = &bin[0];
	pack16(p, htons(flags));
	p += 2;
	pack8(p, 3);	/* protocol always 3 */
	p++;
 	pack8(p, algorithm);
	p++;

	pack(p, public_key, DDD_ED25519_PUBLIC_KEY_LENGTH);
	p += DDD_ED25519_PUBLIC_KEY_LENGTH;

	binlen = (plength(p, &bin[0]));

	return (keytag((u_char *)bin, binlen));
}

int
create_key_ec_getpid(DDD_EC_KEY *eckey, DDD_EC_GROUP *ecgroup, DDD_EC_POINT *ecpublickey, int algorithm, int flags)
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

	binlen = delphinusdns_EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);

	if (binlen == 0) {
		dolog(LOG_ERR, "EC_POINT_point2oct(): %s\n", strerror(errno));
		return -1;
	} 

	tmp = malloc(binlen);
	if (tmp == NULL) {
		dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
		return (-1);
	}

	if (delphinusdns_EC_POINT_point2oct(ecgroup, ecpublickey, POINT_CONVERSION_UNCOMPRESSED, (u_char *)tmp, binlen, NULL) == 0) {
		dolog(LOG_ERR, "EC_POINT_point2oct(): %s\n", strerror(errno));
		return -1; 
	}

	q = tmp;
	q++;
	binlen--;
	
	pack(p, q, binlen);
	p += binlen;

	free(tmp);
	binlen = (plength(p, &bin[0]));

	return (keytag((u_char *)bin, binlen));
}

char *	
create_key_rsa(char *zonename, int ttl, int flags, int algorithm, int bits, uint32_t *pid)
{
	FILE *f;
        DDD_RSA *rsa;
        DDD_BIGNUM *e;
	DDD_BIGNUM *rsan, *rsae, *rsad, *rsap, *rsaq;
	DDD_BIGNUM *rsadmp1, *rsadmq1, *rsaiqmp;
        DDD_BN_GENCB *cb;
	char buf[512];
	char bin[4096];
	char b64[4096];
	char tmp[4096];
	int i, binlen;
	char *retval;
	char *p;
	time_t now;
	struct tm *tm;
	struct stat sb;
	mode_t savemask;
	int rlen;

	if ((rsa = delphinusdns_RSA_new()) == NULL) {
		dolog(LOG_INFO, "delphinusdns_RSA_new: %s\n", strerror(errno));
		return NULL;
	}

	if ((e = delphinusdns_BN_new()) == NULL) {
		dolog(LOG_INFO, "delphinusdns_BN_new: %s\n", strerror(errno));
		delphinusdns_RSA_free(rsa);
		return NULL;
	}
	if ((rsan = delphinusdns_BN_new()) == NULL ||
		(rsae = delphinusdns_BN_new()) == NULL ||
		(rsad = delphinusdns_BN_new()) == NULL ||
		(rsap = delphinusdns_BN_new()) == NULL ||
		(rsaq = delphinusdns_BN_new()) == NULL ||
		(rsadmp1 = delphinusdns_BN_new()) == NULL ||
		(rsadmq1 = delphinusdns_BN_new()) == NULL ||
		(rsaiqmp = delphinusdns_BN_new()) == NULL) {
		dolog(LOG_INFO, "delphinusdns_BN_new: %s\n", strerror(errno));
		delphinusdns_RSA_free(rsa);
		return NULL;
	}
	
	if ((cb = delphinusdns_BN_GENCB_new()) == NULL) {
		dolog(LOG_INFO, "BN_GENCB_new: %s\n", strerror(errno));
		delphinusdns_RSA_free(rsa);
		return NULL;
	}

	for (i = 0; i < 32; i++) {
		if (DDD_RSA_F4 & (1 << i)) {
			delphinusdns_BN_set_bit(e, i);
		}
	}

	BN_GENCB_set_old(cb, NULL, NULL);
	
	switch (algorithm) {
	case ALGORITHM_RSASHA256:
		/* FALLTHROUGH */
	case ALGORITHM_RSASHA512:
		break;
	default:
		dolog(LOG_INFO, "invalid algorithm in key\n");
		return NULL;
	}

	if (delphinusdns_RSA_generate_key_ex(rsa, bits, e, cb) == 0) {
		dolog(LOG_INFO, "RSA_generate_key_ex: %s\n", strerror(errno));
		delphinusdns_BN_free(e);
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_GENCB_free(cb);
		return NULL;
	}

	/* cb is not used again */
	delphinusdns_BN_GENCB_free(cb);

	/* get the bignums for now hidden struct */
	delphinusdns_RSA_get0_key(rsa, (const DDD_BIGNUM **)&rsan, (const DDD_BIGNUM **)&rsae, (const DDD_BIGNUM **)&rsad);

	/* get the keytag, this is a bit of a hard process */
	p = (char *)&bin[0];
	pack16(p, htons(flags));
	p+=2;
	pack8(p, 3);	/* protocol always 3 */
	p++;
 	pack8(p, algorithm);
	p++;
	binlen = delphinusdns_BN_bn2bin(rsae, (u_char *)tmp); 
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
	binlen = delphinusdns_BN_bn2bin(rsan, (u_char *)tmp);
	pack(p, tmp, binlen);
	p += binlen;
	rlen = (plength(p, &bin[0]));
	*pid = keytag((u_char *)bin, rlen);

	/* check for collisions, XXX should be rare */
	SLIST_FOREACH(knp, &keyshead, keys_entry) {
		if (knp->pid == *pid)
			break;
	}
	
	if (knp != NULL) {
		dolog(LOG_INFO, "create_key: collision with existing pid %d\n", *pid);
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_free(e);
		return (create_key_rsa(zonename, ttl, flags, algorithm, bits, pid));
	}
	
	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, *pid);

	retval = strdup(buf);
	if (retval == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_free(e);
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
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_free(e);
		return NULL;
	}
	
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_free(e);
		return NULL;
	}

	fprintf(f, "Private-key-format: v1.3\n");
	fprintf(f, "Algorithm: %d (%s)\n", algorithm, alg_to_name(algorithm));
	/* modulus */
	binlen = delphinusdns_BN_bn2bin(rsan, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Modulus: %s\n", b64);
	/* public exponent */
	binlen = delphinusdns_BN_bn2bin(rsae, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "PublicExponent: %s\n", b64);
	/* private exponent */
	binlen = delphinusdns_BN_bn2bin(rsad, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "PrivateExponent: %s\n", b64);
	/* get the RSA factors */
	delphinusdns_RSA_get0_factors(rsa, (const DDD_BIGNUM **)&rsap, (const DDD_BIGNUM **)&rsaq);
	/* prime1 */
	binlen = delphinusdns_BN_bn2bin(rsap, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime1: %s\n", b64);
	/* prime2 */
	binlen = delphinusdns_BN_bn2bin(rsaq, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime2: %s\n", b64);
	/* get the RSA crt params */
	delphinusdns_RSA_get0_crt_params(rsa, (const DDD_BIGNUM **)&rsadmp1, (const DDD_BIGNUM **)&rsadmq1, (const DDD_BIGNUM **)&rsaiqmp);
	/* exponent1 */
	binlen = delphinusdns_BN_bn2bin(rsadmp1, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent1: %s\n", b64);
	/* exponent2 */
	binlen = delphinusdns_BN_bn2bin(rsadmq1, (u_char *)&bin);
	mybase64_encode((u_char*)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent2: %s\n", b64);
	/* coefficient */
	binlen = delphinusdns_BN_bn2bin(rsaiqmp, (u_char *)&bin);
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "Coefficient: %s\n", b64);

	now = time(NULL);
	tm = gmtime(&now);
	
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	fprintf(f, "Created: %s\n", buf);
	fprintf(f, "Publish: %s\n", buf);
	fprintf(f, "Activate: %s\n", buf);
	
	fclose(f);
	delphinusdns_BN_free(e);

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
		delphinusdns_RSA_free(rsa);
		delphinusdns_BN_free(e);
		return NULL;
	}
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		delphinusdns_RSA_free(rsa);
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
	binlen = delphinusdns_BN_bn2bin(rsae, (u_char *)tmp);
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
	binlen = delphinusdns_BN_bn2bin(rsan, (u_char *)tmp);
	pack(p, tmp, binlen);
	p += binlen; 
	binlen = (plength(p, &bin[0]));
	mybase64_encode((const u_char *)bin, binlen, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);
	delphinusdns_RSA_free(rsa);
	
	return (retval);
}

char *
alg_to_name(int algorithm)
{
	
	switch (algorithm) {
	case ALGORITHM_RSASHA256:
		return ("RSASHA256");
		break;
	case ALGORITHM_RSASHA512:
		return ("RSASHA512");
		break;
	case ALGORITHM_ECDSAP256SHA256:
		return ("ECDSAP256SHA256");
		break;
	case ALGORITHM_ECDSAP384SHA384:
		return ("ECDSAP384SHA384");
		break;
	case ALGORITHM_ED25519:
		return ("ED25519");
	}

	return (NULL);
}

int
alg_to_rsa(int algorithm)
{
	
	switch (algorithm) {
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
	int rs;

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
		if ((rrset = find_rr(rbt, DNS_TYPE_CERT)) != NULL) {
			if (sign_cert(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_cert error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_IPSECKEY)) != NULL) {
			if (sign_ipseckey(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_ipseckey error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
			if (sign_cdnskey(db, zonename, expiry, rbt, rollmethod) < 0) {
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
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
			if (sign_eui48(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_eui48 error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
			if (sign_eui64(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_eui64 error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
			if (sign_kx(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_kx error\n");
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
			int isapex;

			if ((isapex = rbt_isapex(rbt, zonename)) < 0) {
				fprintf(stderr, "sign_ns error\n");
				return -1;
			}

			/*
			 * check if we're a delegation point.
			 * RFC 4035 section 2.2 says:
			 * The NS RRset that appears at the zone apex 
			 * name MUST be signed, but the NS RRsets that 
			 * appear at delegation points (that is, the NS
   			 * RRsets in the parent zone that delegate the 
			 * name to the child zone's name servers) MUST NOT 
			 * be signed.  Glue address RRsets associated with 
			 * delegations MUST NOT be signed.
			 */

			if (isapex && sign_ns(db, zonename, expiry, rbt, 
				rollmethod) < 0) {
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
		if ((rrset = find_rr(rbt, DNS_TYPE_SVCB)) != NULL) {
			if (sign_svcb(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_svcb error\n");
				return -1;
			}
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_HTTPS)) != NULL) {
			if (sign_https(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_https error\n");
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
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
			if (sign_nsec(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_nsec error\n");
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
		if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != NULL) {
			if (sign_loc(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_loc error\n");
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
		if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
			if (sign_cds(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_cds error\n");
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
		if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != NULL) {
			if (sign_zonemd(db, zonename, expiry, rbt, rollmethod) < 0) {
				fprintf(stderr, "sign_zonemd error\n");
				return -1;
			}
		}
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		p += sizeof(uint32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->refresh));
		p += sizeof(uint32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->retry));
		p += sizeof(uint32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->expire));
		p += sizeof(uint32_t);
		pack32(p, htonl(((struct soa *)rrp->rdata)->minttl));
		p += sizeof(uint32_t);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
		
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SOA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}

	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a HTTPS record
 */

static int
sign_https(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL, *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey = NULL;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_HTTPS)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no HTTPS records but have rrset entry!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no HTTPS records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_HTTPS));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += sizeof(uint32_t);
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
  			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_HTTPS));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			/* the below uses rrp! because we can't have an rrsig differ */
			pack32(q, htonl(rrset->ttl));
			q += 4;
			/* insert */
			pack16(q, htons(((struct https *)rrp2->rdata)->paramlen + ((struct https *)rrp2->rdata)->targetlen + 2));
			q += 2;

			pack16(q, htons(((struct https *)rrp2->rdata)->priority));
			q += 2;
			pack(q, (char *)((struct https *)rrp2->rdata)->target, ((struct https *)rrp2->rdata)->targetlen);
			q += ((struct https *)rrp2->rdata)->targetlen;

			pack(q, (char *)((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen);
			q += ((struct https *)rrp2->rdata)->paramlen;

#if 0
			printf("%d == paramlen\n", ((struct https *)rrp2->rdata)->paramlen);
#endif

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "HTTPS", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a SVCB record
 */

static int
sign_svcb(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL, *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey = NULL;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_SVCB)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no SVCB records but have rrset entry!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no SVCB records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_SVCB));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += sizeof(uint32_t);
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		

		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
  			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_SVCB));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			/* the below uses rrp! because we can't have an rrsig differ */
			pack32(q, htonl(rrset->ttl));
			q += 4;

			pack16(q, htons(((struct svcb *)rrp2->rdata)->paramlen + ((struct svcb *)rrp2->rdata)->targetlen + 2));
			q += 2;

			pack16(q, htons(((struct svcb *)rrp2->rdata)->priority));
			q += 2;
			pack(q, (char *)((struct svcb *)rrp2->rdata)->target, ((struct svcb *)rrp2->rdata)->targetlen);
			q += ((struct svcb *)rrp2->rdata)->targetlen;

			pack(q, (char *)((struct svcb *)rrp2->rdata)->param, ((struct svcb *)rrp2->rdata)->paramlen);
			q += ((struct svcb *)rrp2->rdata)->paramlen;

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SVCB", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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

	char tmp[8192];
	char signature[8192];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey = NULL;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
		p += sizeof(uint32_t);
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		

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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		
		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NSEC3", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}


/*
 * create a RRSIG for an NSEC record
 */

static int
sign_nsec(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no NSEC records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no NSEC records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_NSEC));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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

		pack16(p, htons(DNS_TYPE_NSEC));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(rrset->ttl));
		p += 4;
		pack16(p, htons(((struct nsec *)rrp->rdata)->next_len + ((struct nsec *)rrp->rdata)->bitmap_len));
		p += 2;
		pack(p, ((struct nsec *)rrp->rdata)->next, ((struct nsec *)rrp->rdata)->next_len);
		p += ((struct nsec *)rrp->rdata)->next_len;
		if (((struct nsec *)rrp->rdata)->bitmap_len) {
			pack(p, ((struct nsec *)rrp->rdata)->bitmap, ((struct nsec *)rrp->rdata)->bitmap_len);
			p += ((struct nsec *)rrp->rdata)->bitmap_len;
		}
		
		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NSEC", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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
			
			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "SSHFP", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a LOC record
 */

static int
sign_loc(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no LOC records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no LOC records\n");
			return -1;

		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_LOC));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_LOC));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(4 + (3 * sizeof(uint32_t))));
			q += 2;
			pack8(q, ((struct loc *)rrp2->rdata)->version);
			q++;
			pack8(q, ((struct loc *)rrp2->rdata)->size);
			q++;
			pack8(q, ((struct loc *)rrp2->rdata)->horiz_pre);
			q++;
			pack8(q, ((struct loc *)rrp2->rdata)->vert_pre);
			q++;
			pack32(q, htonl(((struct loc *)rrp2->rdata)->latitude));
			q += 4;
			pack32(q, htonl(((struct loc *)rrp2->rdata)->longitude));
			q += 4;
			pack32(q, htonl(((struct loc *)rrp2->rdata)->altitude));
			q += 4;

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "LOC", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
		
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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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


			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "RP", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	
	} while ((*++zsk_key) != NULL);

	return 0;
}

static int
sign_zonemd(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no ZONEMD records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no ZONEMD records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_ZONEMD));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif


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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_ZONEMD));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(4 + 1 + 1 + ((struct zonemd *)rrp2->rdata)->hashlen));
			q += 2;

			pack32(q, htonl(((struct zonemd *)rrp2->rdata)->serial));
			q += 4;
			pack8(q, ((struct zonemd *)rrp2->rdata)->scheme);
			q++;
			pack8(q, ((struct zonemd *)rrp2->rdata)->algorithm);
			q++;
			pack(q, ((struct zonemd *)rrp2->rdata)->hash, ((struct zonemd *)rrp2->rdata)->hashlen);
			q += ((struct zonemd *)rrp2->rdata)->hashlen;

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "ZONEMD", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

			r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}


		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
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


		        r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		} /* tailq foreach */

		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "CAA", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);

	return 0;
}

/*
 * create a RRSIG for an CDS record
 */

static int
sign_cds(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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

	/* CDNSKEY gets signed with the KSK key */

		
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
			keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
			pack(p, signature, keylen);
			p += keylen;
			keylen = (plength(p, key));
			if (keyid != keytag((u_char *)key, keylen)) {
				dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

			if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
				rrp = TAILQ_FIRST(&rrset->rr_head);
				if (rrp == NULL) {
					dolog(LOG_INFO, "no cdnskeys in apex!\n");
					return -1;
				}
			} else {
				dolog(LOG_INFO, "no cdnskeys\n");
				return -1;
			}
			
			p = key;

			pack16(p, htons(DNS_TYPE_CDS));
			p += 2;
			pack8(p, algorithm);
			p++;
			pack8(p, labels);
			p++;
			pack32(p, htonl(rrset->ttl));
			p += 4;
				
#if defined __FreeBSD__ || defined __linux__
			snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#else
			snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#endif

			pack32(p, htonl(expiredon2));
			p += 4;
			pack32(p, htonl(signedon2));	
			p += 4;
			pack16(p, htons(keyid));
			p += 2;
			pack(p, dnsname, labellen);
			p += labellen;

			/* no signature here */	

			canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
			if (canonsort == NULL) {
				dolog(LOG_INFO, "canonsort out of memory\n");
				return -1;
			}

			csort = 0;
				
			
			TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
				q = tmpkey;
				pack(q, dnsname, labellen);
				q += labellen;
				pack16(q, htons(DNS_TYPE_CDS));
				q += 2;
				pack16(q, htons(DNS_CLASS_IN));
				q += 2;
				pack32(q, htonl(rrset->ttl));
				q += 4;
				pack16(q, htons(2 + 1 + 1 + ((struct cds *)rrp2->rdata)->digestlen));
				q += 2;
				pack16(q, htons(((struct cds *)rrp2->rdata)->key_tag));
				q += 2;
				pack8(q, ((struct cds *)rrp2->rdata)->algorithm);
				q++;
				pack8(q, ((struct cds *)rrp2->rdata)->digest_type);
				q++;
				pack(q, ((struct cds *)rrp2->rdata)->digest, ((struct cds *)rrp2->rdata)->digestlen);
				q += ((struct cds *)rrp2->rdata)->digestlen;

				r = canonsort[csort] = calloc(1, 68000);
				if (r == NULL) {
					dolog(LOG_INFO, "out of memory\n");
					return -1;
				}

				clen = (plength(q, tmpkey));
				pack16(r, clen);
				r += 2;
				pack(r, tmpkey, clen);

				csort++;
			}

	
			r = canonical_sort(canonsort, csort, &rlen);
			if (r == NULL) {
				dolog(LOG_INFO, "canonical_sort failed\n");
				return -1;
			}

			memcpy(p, r, rlen);
			p += rlen;

			free(r);
			for (i = 0; i < csort; i++) {
				free(canonsort[i]);
			}
			free(canonsort);

			keylen = (plength(p, key));	

			if (sign(algorithm, key, keylen, knp, (char *)&signature, &siglen) < 0) {
				dolog(LOG_INFO, "signing failed\n");
				return -1;
			}

			len = mybase64_encode((u_char *)signature, siglen, tmp, sizeof(tmp));
			tmp[len] = '\0';

			if (fill_rrsig(db, rbt->humanname, "RRSIG", ttl, "CDS", algorithm, labels, 		ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
				dolog(LOG_INFO, "fill_rrsig\n");
				return -1;
			}

		} /* if KSK */
	} /* SLIST_FOREACH */

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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

		        r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
                }
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

		        r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}

		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

#if 0
		debug_bindump(key, keylen);
#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "NS", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a KX record
 */

static int
sign_kx(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no KX records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no KX records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_KX));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_KX));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(2 + ((struct kx *)rrp2->rdata)->exchangelen));
			q += 2;
			pack16(q, htons(((struct kx *)rrp2->rdata)->preference));
			q += 2;
			memcpy(q, ((struct kx *)rrp2->rdata)->exchange, ((struct kx *)rrp2->rdata)->exchangelen);
			q += ((struct kx *)rrp2->rdata)->exchangelen;

		        r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}

		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "KX", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, clen, i;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		
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

		        r = canonsort[csort] = malloc(68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}

		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		pack(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

	#if 0
		debug_bindump(key, keylen);
	#endif
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "MX", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for a CERT record
 */

static int
sign_cert(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, i;
	uint16_t clen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_CERT)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no CERT records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no CERT records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_CERT));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_CERT));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;

			pack16(q, htons(5 + ((struct cert *)rrp2->rdata)->certlen));
			q += 2;
			pack16(q, htons(((struct cert *)rrp2->rdata)->type));
			q += 2;
			pack16(q, htons(((struct cert *)rrp2->rdata)->keytag));
			q += 2;
			pack8(q, ((struct cert *)rrp2->rdata)->algorithm);
			q++;

			if (((struct cert *)rrp2->rdata)->certlen) {
				pack(q, (char *)&((struct cert *)rrp2->rdata)->cert, ((struct cert *)rrp2->rdata)->certlen);
				q += ((struct cert *)rrp2->rdata)->certlen;
			}

		        r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}
		
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "CERT", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an IPSECKEY record
 */

static int
sign_ipseckey(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, i;
	uint16_t clen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;
	int ipseckeylen;



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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_IPSECKEY)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no IPSECKEY records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no IPSECKEY records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_IPSECKEY));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_IPSECKEY));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;

			switch (((struct ipseckey *)rrp2->rdata)->gwtype) {
			case 1:
				ipseckeylen = 4;
				break;
			case 2:
				ipseckeylen = 16;
				break;
			case 3:
				ipseckeylen = ((struct ipseckey *)rrp2->rdata)->dnsnamelen;
				break;
			default:
				ipseckeylen = 0;
				break;
			}	

			pack16(q, htons(3 + ipseckeylen + ((struct ipseckey *)rrp2->rdata)->keylen));
			q += 2;
			pack8(q, ((struct ipseckey *)rrp2->rdata)->precedence);
			q++;
			pack8(q, ((struct ipseckey *)rrp2->rdata)->gwtype);
			q++;
			pack8(q, ((struct ipseckey *)rrp2->rdata)->alg);
			q++;

			if (ipseckeylen) {
				pack(q, (char *)&((struct ipseckey *)rrp2->rdata)->gateway, ipseckeylen);
				q += ipseckeylen;
			}

			pack(q, ((struct ipseckey *)rrp2->rdata)->key,
					((struct ipseckey *)rrp2->rdata)->keylen);
			q += ((struct ipseckey *)rrp2->rdata)->keylen;

		        r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}
		
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "IPSECKEY", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, i;
	uint16_t clen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;


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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
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

		        r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}
		
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "A", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an EUI48 record
 */

static int
sign_eui48(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, i;
	uint16_t clen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;


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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no EUI48 records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no EUI48 records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_EUI48));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_EUI48));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(sizeof(struct eui48)));
			q += 2;
			pack(q, ((struct eui48 *)rrp2->rdata)->eui48, 6);
			q += 6;

		        r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}
		
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "EUI48", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
			dolog(LOG_INFO, "fill_rrsig\n");
			return -1;
		}
	} while ((*++zsk_key) != NULL);
	
	return 0;
}

/*
 * create a RRSIG for an EUI48 record
 */

static int
sign_eui64(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	

	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
	int keyid;
	int len, rlen, i;
	uint16_t clen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int nzk = 0;
	int csort = 0;

	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;


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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

		if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			if (rrp == NULL) {
				dolog(LOG_INFO, "no EUI64 records but have flags!\n");
				return -1;
			}
		} else {
			dolog(LOG_INFO, "no EUI64 records\n");
			return -1;
		}
		
		p = key;

		pack16(p, htons(DNS_TYPE_EUI64));
		p += 2;
		pack8(p, algorithm);
		p++;
		pack8(p, labels);
		p++;
		pack32(p, htonl(rrset->ttl));
		p += 4;
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

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
		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
			dolog(LOG_INFO, "canonsort out of memory\n");
			return -1;
		}
		
		csort = 0;
		
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			q = tmpkey;
			pack(q, rbt->zone, rbt->zonelen);
			q += rbt->zonelen;
			pack16(q, htons(DNS_TYPE_EUI64));
			q += 2;
			pack16(q, htons(DNS_CLASS_IN));
			q += 2;
			pack32(q, htonl(rrset->ttl));
			q += 4;
			pack16(q, htons(sizeof(struct eui64)));
			q += 2;
			pack(q, ((struct eui64 *)rrp2->rdata)->eui64, 8);
			q += 8;

			r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "c1 out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}
		
		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free (r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
		tmp[len] = '\0';

		if (fill_rrsig(db, rbt->humanname, "RRSIG", rrset->ttl, "EUI64", algorithm, labels, rrset->ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
	pack(p, signature, keylen);
	p += keylen;
	keylen = (plength(p, key));
	if (keyid != keytag((u_char *)key, keylen)) {
		dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
	
	keylen = (plength(p, key));	

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
	keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
	pack(p, signature, keylen);
	p += keylen;
	
	keylen = (plength(p, key));

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
 * CDNSKEY
 */

static int
sign_cdnskey(ddDB *db, char *zonename, int expiry, struct rbtree *rbt, int rollmethod)
{
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;
	struct keysentry **zsk_key;

	char tmp[4096];
	char signature[4096];
	char shabuf[64];
	
	char *dnsname;
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int csort = 0;
	int labellen;
	int keyid;
	int len, i, rlen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int clen = 0;


	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}
		
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

	/* CDNSKEY gets signed with the KSK key */

		
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
			keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
			pack(p, signature, keylen);
			p += keylen;
			keylen = (plength(p, key));
			if (keyid != keytag((u_char *)key, keylen)) {
				dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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

			if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
				rrp = TAILQ_FIRST(&rrset->rr_head);
				if (rrp == NULL) {
					dolog(LOG_INFO, "no cdnskeys in apex!\n");
					return -1;
				}
			} else {
				dolog(LOG_INFO, "no cdnskeys\n");
				return -1;
			}
			
			p = key;

			pack16(p, htons(DNS_TYPE_CDNSKEY));
			p += 2;
			pack8(p, algorithm);
			p++;
			pack8(p, labels);
			p++;
			pack32(p, htonl(rrset->ttl));
			p += 4;
				
#if defined __FreeBSD__ || defined __linux__
			snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#else
			snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#endif

			pack32(p, htonl(expiredon2));
			p += 4;
			pack32(p, htonl(signedon2));	
			p += 4;
			pack16(p, htons(keyid));
			p += 2;
			pack(p, dnsname, labellen);
			p += labellen;

			/* no signature here */	

			canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
			if (canonsort == NULL) {
				dolog(LOG_INFO, "canonsort out of memory\n");
				return -1;
			}

			csort = 0;
				
			
			TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
				q = tmpkey;
				pack(q, dnsname, labellen);
				q += labellen;
				pack16(q, htons(DNS_TYPE_CDNSKEY));
				q += 2;
				pack16(q, htons(DNS_CLASS_IN));
				q += 2;
				pack32(q, htonl(rrset->ttl));
				q += 4;
				pack16(q, htons(2 + 1 + 1 + ((struct cdnskey *)rrp2->rdata)->publickey_len));
				q += 2;
				pack16(q, htons(((struct cdnskey *)rrp2->rdata)->flags));
				q += 2;
				pack8(q, ((struct cdnskey *)rrp2->rdata)->protocol);
				q++;
				pack8(q, ((struct cdnskey *)rrp2->rdata)->algorithm);
				q++;
				pack(q, ((struct cdnskey *)rrp2->rdata)->public_key, ((struct cdnskey *)rrp2->rdata)->publickey_len);
				q += ((struct cdnskey *)rrp2->rdata)->publickey_len;

				r = canonsort[csort] = calloc(1, 68000);
				if (r == NULL) {
					dolog(LOG_INFO, "out of memory\n");
					return -1;
				}

				clen = (plength(q, tmpkey));
				pack16(r, clen);
				r += 2;
				pack(r, tmpkey, clen);

				csort++;
			}

	
			r = canonical_sort(canonsort, csort, &rlen);
			if (r == NULL) {
				dolog(LOG_INFO, "canonical_sort failed\n");
				return -1;
			}

			memcpy(p, r, rlen);
			p += rlen;

			free(r);
			for (i = 0; i < csort; i++) {
				free(canonsort[i]);
			}
			free(canonsort);

			keylen = (plength(p, key));	

			if (sign(algorithm, key, keylen, knp, (char *)&signature, &siglen) < 0) {
				dolog(LOG_INFO, "signing failed\n");
				return -1;
			}

			len = mybase64_encode((u_char *)signature, siglen, tmp, sizeof(tmp));
			tmp[len] = '\0';

			if (fill_rrsig(db, rbt->humanname, "RRSIG", ttl, "CDNSKEY", algorithm, labels, 		ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
				dolog(LOG_INFO, "fill_rrsig\n");
				return -1;
			}

		} /* if KSK */
	} /* SLIST_FOREACH */

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
	char *p, *q, *r;
	char **canonsort;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int nzk = 0;
	int csort = 0;
	int labellen;
	int keyid;
	int len, i, rlen;
	int keylen, siglen = sizeof(signature);
	int labels;
	int clen = 0;


	char timebuf[32];
	struct tm tm;
	uint32_t expiredon2, signedon2;

	zsk_key = calloc(3, sizeof(struct keysentry *));
	if (zsk_key == NULL) {
		dolog(LOG_INFO, "out of memory\n");	
		return -1;
	}
		
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
			keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
			pack(p, signature, keylen);
			p += keylen;
			keylen = (plength(p, key));
			if (keyid != keytag((u_char *)key, keylen)) {
				dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
				
#if defined __FreeBSD__ || defined __linux__
			snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#else
			snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			expiredon2 = timegm(&tm);
			snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
			strptime(timebuf, "%Y%m%d%H%M%S", &tm);
			signedon2 = timegm(&tm);
#endif

			pack32(p, htonl(expiredon2));
			p += 4;
			pack32(p, htonl(signedon2));	
			p += 4;
			pack16(p, htons(keyid));
			p += 2;
			pack(p, dnsname, labellen);
			p += labellen;

			/* no signature here */	

			canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
			if (canonsort == NULL) {
				dolog(LOG_INFO, "canonsort out of memory\n");
				return -1;
			}

			csort = 0;
				
			
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

				r = canonsort[csort] = calloc(1, 68000);
				if (r == NULL) {
					dolog(LOG_INFO, "out of memory\n");
					return -1;
				}

				clen = (plength(q, tmpkey));
				pack16(r, clen);
				r += 2;
				pack(r, tmpkey, clen);

				csort++;
			}

	
			r = canonical_sort(canonsort, csort, &rlen);
			if (r == NULL) {
				dolog(LOG_INFO, "canonical_sort failed\n");
				return -1;
			}

			memcpy(p, r, rlen);
			p += rlen;

			free(r);
			for (i = 0; i < csort; i++) {
				free(canonsort[i]);
			}
			free(canonsort);

			keylen = (plength(p, key));	

			if (sign(algorithm, key, keylen, knp, (char *)&signature, &siglen) < 0) {
				dolog(LOG_INFO, "signing failed\n");
				return -1;
			}

			len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
		keylen = mybase64_decode(tmp, (u_char *)&signature, sizeof(signature));
		pack(p, signature, keylen);
		p += keylen;
		keylen = (plength(p, key));
		if (keyid != keytag((u_char *)key, keylen)) {
			dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag((u_char *)key, keylen));
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
			
#if defined __FreeBSD__ || defined __linux__
		snprintf(timebuf, sizeof(timebuf), "%lu", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lu", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#else
		snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		expiredon2 = timegm(&tm);
		snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
		strptime(timebuf, "%Y%m%d%H%M%S", &tm);
		signedon2 = timegm(&tm);
#endif

		pack32(p, htonl(expiredon2));
		p += 4;
		pack32(p, htonl(signedon2));	
		p += 4;
		pack16(p, htons(keyid));
		p += 2;
		pack(p, dnsname, labellen);
		p += labellen;

		/* no signature here */	

		canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
		if (canonsort == NULL) {
				dolog(LOG_INFO, "canonsort2 out of memory\n");
				return -1;
		}

		csort = 0;
		
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


			r = canonsort[csort] = calloc(1, 68000);
			if (r == NULL) {
				dolog(LOG_INFO, "out of memory\n");
				return -1;
			}

			clen = (plength(q, tmpkey));
			pack16(r, clen);
			r += 2;
			pack(r, tmpkey, clen);

			csort++;
		}

		r = canonical_sort(canonsort, csort, &rlen);
		if (r == NULL) {
			dolog(LOG_INFO, "canonical_sort failed\n");
			return -1;
		}

		memcpy(p, r, rlen);
		p += rlen;

		free(r);
		for (i = 0; i < csort; i++) {
			free(canonsort[i]);
		}
		free(canonsort);

		keylen = (plength(p, key));	

		siglen = sizeof(signature);
		if (sign(algorithm, key, keylen, *zsk_key, (char *)&signature, &siglen) < 0) {
			dolog(LOG_INFO, "signing failed\n");
			return -1;
		}

		len = mybase64_encode((const u_char *)signature, siglen, tmp, sizeof(tmp));
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
	keylen = (plength(p, key));

	ret = keytag((u_char *)key, keylen);
	free(key);
	
	return (ret);
}


void
free_private_key(struct keysentry *kn)
{
	if (kn->algorithm < 13) {
		/* RSA */
		delphinusdns_BN_clear_free(kn->rsan);
		delphinusdns_BN_clear_free(kn->rsae);
		delphinusdns_BN_clear_free(kn->rsad);
		delphinusdns_BN_clear_free(kn->rsap);
		delphinusdns_BN_clear_free(kn->rsaq);
		delphinusdns_BN_clear_free(kn->rsadmp1);
		delphinusdns_BN_clear_free(kn->rsadmq1);
		delphinusdns_BN_clear_free(kn->rsaiqmp);
	} else if (kn->algorithm == 13) {
		/* EC */
		delphinusdns_BN_clear_free(kn->ecprivate);
	} else {
		/* ED25519 */
		explicit_bzero(kn->ed_private, DDD_ED25519_PRIVATE_KEY_LENGTH);
	}

	return;
}

RSA *
get_private_key_rsa(struct keysentry *kn)
{
	DDD_RSA *rsa;

	DDD_BIGNUM *rsan;
	DDD_BIGNUM *rsae;
	DDD_BIGNUM *rsad;
	DDD_BIGNUM *rsap;
	DDD_BIGNUM *rsaq;
	DDD_BIGNUM *rsadmp1;
	DDD_BIGNUM *rsadmq1;
	DDD_BIGNUM *rsaiqmp;

	rsa = delphinusdns_RSA_new();
	if (rsa == NULL) {
		dolog(LOG_INFO, "RSA creation\n");
		return NULL;
	}

	if ( 	(rsan = delphinusdns_BN_dup(kn->rsan)) == NULL ||
		(rsae = delphinusdns_BN_dup(kn->rsae)) == NULL ||
		(rsad = delphinusdns_BN_dup(kn->rsad)) == NULL ||
		(rsap = delphinusdns_BN_dup(kn->rsap)) == NULL ||
		(rsaq = delphinusdns_BN_dup(kn->rsaq)) == NULL ||
		(rsadmp1 = delphinusdns_BN_dup(kn->rsadmp1)) == NULL ||
		(rsadmq1 = delphinusdns_BN_dup(kn->rsadmq1)) == NULL ||
		(rsaiqmp = delphinusdns_BN_dup(kn->rsaiqmp)) == NULL) {
		dolog(LOG_INFO, "delphinusdns_BN_dup\n");
		return NULL;
	}

	if (delphinusdns_RSA_set0_key(rsa, rsan, rsae, rsad) == 0 ||
		delphinusdns_RSA_set0_factors(rsa, rsap, rsaq) == 0 ||
		delphinusdns_RSA_set0_crt_params(rsa, rsadmp1, rsadmq1, rsaiqmp) == 0) {
		dolog(LOG_INFO, "RSA_set0_* failed\n");
		return NULL;
	}

	return (rsa);
}

uint8_t *
get_private_key_ed25519(struct keysentry *kn)
{
	static uint8_t key[DDD_ED25519_PRIVATE_KEY_LENGTH];

	memcpy(key, kn->ed_private, DDD_ED25519_PRIVATE_KEY_LENGTH);

	return (key);
}

uint8_t *
get_public_key_ed25519(struct keysentry *kn)
{
	static uint8_t key[DDD_ED25519_PUBLIC_KEY_LENGTH];

	memcpy(key, kn->ed_public, DDD_ED25519_PUBLIC_KEY_LENGTH);

	return (key);
}

DDD_EC_KEY *
get_private_key_ec(struct keysentry *kn)
{
	DDD_EC_KEY *eckey;
	DDD_EC_GROUP *ecgroup;

	const DDD_EC_POINT *ecpoint = NULL;
	const DDD_BIGNUM *ecprivate;
	DDD_BN_CTX *bn_ctx = NULL;

	eckey = delphinusdns_EC_KEY_new();
	if (eckey == NULL) {
		dolog(LOG_INFO, "EC creation\n");
		return NULL;
	}

	
	if ((ecprivate = delphinusdns_BN_dup(kn->ecprivate)) == NULL) {
		dolog(LOG_INFO, "delphinusdns_BN_dup\n");
		goto out;
	}


	ecgroup = NULL;

	switch (kn->algorithm) {
	case ALGORITHM_ECDSAP256SHA256:
		ecgroup = delphinusdns_EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		break;
	case ALGORITHM_ECDSAP384SHA384:

		ecgroup = delphinusdns_EC_GROUP_new_by_curve_name(NID_secp384r1);
		break;
	}

	if (ecgroup == NULL) {
		dolog(LOG_ERR, "EC_GROUP_new_by_curve_name(): %s\n", strerror(errno));
		goto out;
	}

	if (delphinusdns_EC_KEY_set_group(eckey, ecgroup) != 1) {
		dolog(LOG_ERR, "EC_KEY_set_group(): %s\n", strerror(errno));	
		delphinusdns_EC_GROUP_free(ecgroup);
		goto out;
	}

	if (delphinusdns_EC_KEY_set_private_key(eckey, ecprivate) != 1) {
		dolog(LOG_INFO, "EC_KEY_set_private_key failed\n");
		delphinusdns_EC_GROUP_free(ecgroup);
		goto out;
	}

	ecpoint = delphinusdns_EC_POINT_new(ecgroup);
	if (ecpoint == NULL) {
		dolog(LOG_ERR, "EC_POINT_new(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		delphinusdns_EC_GROUP_free(ecgroup);
		goto out;
	}

	if (delphinusdns_EC_POINT_mul(ecgroup, (DDD_EC_POINT *)ecpoint, ecprivate, NULL, NULL, bn_ctx) != 1) {
		dolog(LOG_ERR, "EC_POINT_mul(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		delphinusdns_EC_GROUP_free(ecgroup);
		goto out;
	}

	if (delphinusdns_EC_KEY_set_public_key(eckey, ecpoint) != 1) { 
		dolog(LOG_ERR, "EC_KEY_set_public_key(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		delphinusdns_EC_GROUP_free(ecgroup);
		goto out;
	}

	return (eckey);	

out:
	delphinusdns_EC_KEY_free(eckey);
	return NULL;
}

int
store_private_key(struct keysentry *kn, char *zonename, int keyid, int algorithm)
{
	FILE *f, *publicf;

	char buf[4096];
	char key[4096];
	char *p, *q;

	int keylen;

	if (kn && kn->keypath != NULL) {
		snprintf(buf, sizeof(buf), "%s/K%s%s+%03d+%d.private", 
			kn->keypath, zonename,
			(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
			algorithm, keyid);
	} else {
		snprintf(buf, sizeof(buf), "K%s%s+%03d+%d.private", 
			zonename,
			(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
			algorithm, keyid);
	}

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
	
			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsan = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL)  {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PublicExponent: ")) != NULL) {
			p += 16;	

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsae = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PrivateExponent: ")) != NULL) {
			p += 17;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsad = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Prime1: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsap = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Prime2: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsaq = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Exponent1: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsadmp1 = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Exponent2: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsadmq1 = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "Coefficient: ")) != NULL) {
			p += 13;

			keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
			if ((kn->rsaiqmp = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
				return -1;
			}
		} else if ((p = strstr(buf, "PrivateKey: ")) != NULL) {
			p += 12;

			switch (algorithm) {
			case ALGORITHM_ECDSAP256SHA256:
			case ALGORITHM_ECDSAP384SHA384:
				keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
				if ((kn->ecprivate = delphinusdns_BN_bin2bn((const u_char *)key, keylen, NULL)) == NULL) {
					dolog(LOG_INFO, "delphinusdns_BN_bin2bn failed\n");
					return -1;
				}
				break;
			case ALGORITHM_ED25519:

				keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
				memcpy((uint8_t *)&kn->ed_private, key, DDD_ED25519_PRIVATE_KEY_LENGTH);
				/* get the public key */
				if (kn && kn->keypath != NULL) {
					snprintf(buf, sizeof(buf), "%s/K%s%s+%03d+%d.key", 
						kn->keypath, zonename,
						(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
						algorithm, keyid);
				} else {
					snprintf(buf, sizeof(buf), "K%s%s+%03d+%d.key", 
						zonename,
						(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
						algorithm, keyid);
				}

				publicf = fopen(buf, "r");
				if (publicf == NULL) {
					dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
					return -1;
				}
		
				while (fgets(buf, sizeof(buf), publicf) != NULL) {
					p = &buf[0];
					while (*p && isspace(*p))
						p++;
					if (*p == ';')
						continue;
		
					p = strrchr(buf, ' ');
					if (p == NULL) {
						break;
					}

					p++;
					keylen = mybase64_decode(p, (u_char *)&key, sizeof(key));
					memcpy((uint8_t *)&kn->ed_public, key, DDD_ED25519_PUBLIC_KEY_LENGTH);
					break;
				}
			
				fclose(publicf);
				break;
			default:
				dolog(LOG_INFO, "got PrivateKey in keyfile, but not on algorithm 13!\n");
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
fixup_zonemd(ddDB *db, char *zonename, int expiry, int rollmethod)
{
	struct rbtree *rbt = NULL;
	struct node *n, *nx;
	int rs;
	uint32_t serial;
	struct rrset *rrset = NULL;
	struct rr *rrp;
	SHA512_CTX ctx;
	uint8_t sharesult[SHA384_DIGEST_LENGTH];
	char *dnsname;
	int labellen;

	SHA384_Init(&ctx);

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
			zonemd_hash_a(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CERT)) != NULL) {
			zonemd_hash_cert(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_IPSECKEY)) != NULL) {
			zonemd_hash_ipseckey(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
			zonemd_hash_eui48(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
			zonemd_hash_eui64(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SVCB)) != NULL) {
			zonemd_hash_svcb(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_HTTPS)) != NULL) {
			zonemd_hash_https(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
			zonemd_hash_ns(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
			zonemd_hash_cname(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
			zonemd_hash_soa(&ctx, rrset, rbt, &serial);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
			zonemd_hash_ptr(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
			zonemd_hash_hinfo(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
			zonemd_hash_mx(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
			zonemd_hash_txt(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
			zonemd_hash_rp(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
			zonemd_hash_aaaa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
			zonemd_hash_srv(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
			zonemd_hash_naptr(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
			zonemd_hash_kx(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
			zonemd_hash_sshfp(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
			zonemd_hash_tlsa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
			zonemd_hash_caa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
			zonemd_hash_ds(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
			zonemd_hash_dnskey(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
			zonemd_hash_cds(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
			zonemd_hash_cdnskey(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != NULL) {
			zonemd_hash_rrsig(&ctx, rrset, rbt, 1); /*skip zonemd*/
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
			zonemd_hash_nsec3(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
			zonemd_hash_nsec3param(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
			zonemd_hash_nsec(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != NULL) {
			zonemd_hash_loc(&ctx, rrset, rbt);
		}
		free(rbt);
	}

	SHA384_Final(sharesult, &ctx);

	/* remove old zonemd */
	
	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_ZONEMD, 0)) == NULL) {
		return -1;
	}

	rrset = find_rr(rbt, DNS_TYPE_ZONEMD);
	if (rrset == NULL)
		return -1;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		return -1;

	/* just replace the sharesult */
	memcpy(((struct zonemd *)rrp->rdata)->hash, sharesult, 
		((struct zonemd *)rrp->rdata)->hashlen);

	/* fixup rrsig */
	rrset = find_rr(rbt, DNS_TYPE_RRSIG);
	if (rrset == NULL)
		return -1;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (((struct rrsig *)rrp->rdata)->type_covered == \
			DNS_TYPE_ZONEMD) {
			break;
		}
	}
	if (rrp == NULL) {
		return -1;
	}

	TAILQ_REMOVE(&rrset->rr_head, rrp, entries);	 /* remove the ol' entry */

	free(rrp);

	if (sign_zonemd(db, zonename, expiry, rbt, rollmethod) < 0) {
		fprintf(stderr, "fixup_zonemd: sign_zonemd error\n");
		return -1;
	}
		
	return 0;
}

int
add_zonemd(ddDB *db, char *zonename, int check)
{
	struct rbtree *rbt = NULL;
	struct node *n, *nx;
	struct zonemd *zonemd = NULL;
	int rs, labellen;
	uint32_t serial, ttl;
	struct rrset *rrset = NULL;
	SHA512_CTX ctx;
	uint8_t sharesult[SHA384_DIGEST_LENGTH];
	char *dnsname;

	SHA384_Init(&ctx);

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
			zonemd_hash_a(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
			zonemd_hash_eui48(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
			zonemd_hash_eui64(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
			zonemd_hash_ns(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
			zonemd_hash_cname(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
			zonemd_hash_soa(&ctx, rrset, rbt, &serial);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
			zonemd_hash_ptr(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
			zonemd_hash_hinfo(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
			zonemd_hash_mx(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
			zonemd_hash_txt(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
			zonemd_hash_rp(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
			zonemd_hash_aaaa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
			zonemd_hash_srv(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
			zonemd_hash_naptr(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
			zonemd_hash_kx(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
			zonemd_hash_sshfp(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
			zonemd_hash_tlsa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
			zonemd_hash_caa(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
			zonemd_hash_ds(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
			zonemd_hash_dnskey(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
			zonemd_hash_cds(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
			zonemd_hash_cdnskey(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != NULL) {
			zonemd_hash_rrsig(&ctx, rrset, rbt, 1); /*skip zonemd*/
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
			zonemd_hash_nsec3(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
			zonemd_hash_nsec3param(&ctx, rrset, rbt);
		}
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
			//zonemd_hash_nsec(&ctx, rrset, rbt);
		}
		if (check && (rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != NULL) {
			if ((zonemd = zonemd_hash_zonemd(rrset, rbt)) == NULL)
				return -1;
		}

		free(rbt);
	}

	SHA384_Final(sharesult, &ctx);

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
		return -1;
	}

	rrset = find_rr(rbt, DNS_TYPE_SOA);
	if (rrset == NULL)
		return -1;

	ttl = rrset->ttl;

	if (check == 0) {
		if (fill_zonemd(db, zonename, "zonemd", ttl, serial, ZONEMD_SIMPLE, ZONEMD_SHA384, (char *)sharesult, SHA384_DIGEST_LENGTH) < 0) {
			printf("fill_zonemd failed\n");
			return -1;
		}
	} else {
		if (zonemd == NULL) {
			return -1;
		}

		if (memcmp(sharesult, zonemd->hash, zonemd->hashlen) != 0) {
			free(zonemd);
			return -1;
		}

		free(zonemd);
	}
	
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
	uint32_t ttl = 0;

	int rs, len, rootlen;

	TAILQ_HEAD(, mynsec3) nsec3head;

	struct mynsec3 {
		char *hashname;
		char *humanname;
		char *bitmap;
		TAILQ_ENTRY(mynsec3) entries;
	} *n1, *n2, *np;
		
		
	TAILQ_INIT(&nsec3head);

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
		if (find_rr(rbt, DNS_TYPE_HINFO) != NULL)
			strlcat(bitmap, "HINFO ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_MX) != NULL)
			strlcat(bitmap, "MX ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_TXT) != NULL)
			strlcat(bitmap, "TXT ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_RP) != NULL)
			strlcat(bitmap, "RP ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_AAAA) != NULL)
			strlcat(bitmap, "AAAA ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_LOC) != NULL)
			strlcat(bitmap, "LOC ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SRV) != NULL)
			strlcat(bitmap, "SRV ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_NAPTR) != NULL)	 /* 35 */
			strlcat(bitmap, "NAPTR ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_KX) != NULL)
			strlcat(bitmap, "KX ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_CERT) != NULL)
			strlcat(bitmap, "CERT ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_DS) != NULL)		/* 43 */
			strlcat(bitmap, "DS ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SSHFP) != NULL)	 /* 44 */
			strlcat(bitmap, "SSHFP ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_IPSECKEY) != NULL)
			strlcat(bitmap, "IPSECKEY ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_ZONEMD) != NULL) 	  /* 63 */
			strlcat(bitmap, "ZONEMD ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_SVCB) != NULL)
			strlcat(bitmap, "SVCB ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_HTTPS) != NULL)
			strlcat(bitmap, "HTTPS ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_EUI48) != NULL)	/* 108 */
			strlcat(bitmap, "EUI48 ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_EUI64) != NULL)	/* 109 */
			strlcat(bitmap, "EUI64 ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_CAA) != NULL)
			strlcat(bitmap, "CAA ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NS) != NULL) {
			int isapex;

			if ((isapex = rbt_isapex(rbt, zone)) < 0) {
				dolog(LOG_INFO, "rbt_isapex failed\n");
				return -1;
			}

			if (isapex) {
				strlcat(bitmap, "RRSIG ", sizeof(bitmap));
			}
		} else 
			strlcat(bitmap, "RRSIG ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_DNSKEY) != NULL)
			strlcat(bitmap, "DNSKEY ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NSEC3) != NULL)
			strlcat(bitmap, "NSEC3 ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM) != NULL)
			strlcat(bitmap, "NSEC3PARAM ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_NSEC) != NULL)
			strlcat(bitmap, "NSEC ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_TLSA) != NULL)
			strlcat(bitmap, "TLSA ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_CDS) != NULL)
			strlcat(bitmap, "CDS ", sizeof(bitmap));	

		if (find_rr(rbt, DNS_TYPE_CDNSKEY) != NULL)
			strlcat(bitmap, "CDNSKEY ", sizeof(bitmap));	

#if 0
		printf("%s\n", bitmap);
#endif

		n1 = calloc(1, sizeof(struct mynsec3));
		if (n1 == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}

		n1->hashname = strdup(hashname);
		n1->humanname = rbt->humanname;
		if (n1->humanname == NULL) {
			n1->humanname = convert_name(rbt->zone, rbt->zonelen);
		}

		n1->bitmap = strdup(bitmap);	
		if (n1->hashname == NULL || n1->bitmap == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}
	
		if (TAILQ_EMPTY(&nsec3head))
			TAILQ_INSERT_TAIL(&nsec3head, n1, entries);
		else {
			TAILQ_FOREACH(n2, &nsec3head, entries) {
				if (strcmp(n1->hashname, n2->hashname) < 0)
					break;
			}

			if (n2 != NULL) 
				TAILQ_INSERT_BEFORE(n2, n1, entries);
			else
				TAILQ_INSERT_TAIL(&nsec3head, n1, entries);
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
			n1->humanname = convert_name(p, len);
			if (n1->humanname == NULL) {
				n1->humanname = n1->hashname;
			}
			n1->bitmap = strdup(bitmap);	
			if (n1->hashname == NULL || n1->bitmap == NULL) {
				dolog(LOG_INFO, "out of memory");
				return -1;
			}
		
			if (TAILQ_EMPTY(&nsec3head))
				TAILQ_INSERT_TAIL(&nsec3head, n1, entries);
			else {
				TAILQ_FOREACH(n2, &nsec3head, entries) {
					if (strcmp(n1->hashname, n2->hashname) < 0)
						break;
				}

				if (n2 != NULL) 
					TAILQ_INSERT_BEFORE(n2, n1, entries);
				else
					TAILQ_INSERT_TAIL(&nsec3head, n1, entries);
			}

		} /* if len > rootlen */


	} /* RB_FOREACH_SAFE */


	TAILQ_FOREACH(n2, &nsec3head, entries) {
		np = TAILQ_NEXT(n2, entries);
		if (np == NULL)
			np = TAILQ_FIRST(&nsec3head);

		/*
		 * Below can happen for example when 2+ ENT's exist in the
		 * same zonefile ie. _465._tcp.mail.tld, _25._tcp.mail.tld..
		 * where they get sorted beside each other and thus have the
		 * same hash, just skip those.  Funny thing is that it did
		 * not get found when struct domain's were still used.. odd.
		 */
		if (np != n2 && strcmp(n2->hashname, np->hashname) == 0)
			continue;
#if 0
		printf("%s next: %s %s\n", n2->hashname, np->hashname, n2->bitmap);
#endif
		snprintf(buf, sizeof(buf), "%s.%s.", n2->hashname, zone);
		fill_nsec3(db, buf, "nsec3", ttl, n3p.algorithm, n3p.flags, n3p.iterations, salt, np->hashname, n2->bitmap, n2->humanname);
	}

	return 0;
}


int
construct_nsec(ddDB *db, char *zone)
{
	struct node *n, *nx;

	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	char bitmap[4096];
	struct mynext {
		char *name;
		char nextname[DNS_MAXNAME + 1];
		char *bitmap;
	};
		
	char *dnsname;
	char *p;

	int labellen;
	uint32_t ttl = 0;

	int rs, len, rootlen;
	int count = 0;


	dnsname = dns_label(zone, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
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

	count = 0;
	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt, (char *)n->data, n->datalen);

		/* if we're a glue record, skip */
		if (! notglue(db, rbt, zone)) {
			continue;
		}

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
		if (find_rr(rbt, DNS_TYPE_HINFO) != NULL)
			strlcat(bitmap, "HINFO ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_MX) != NULL)
			strlcat(bitmap, "MX ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_TXT) != NULL)
			strlcat(bitmap, "TXT ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_RP) != NULL)
			strlcat(bitmap, "RP ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_AAAA) != NULL)
			strlcat(bitmap, "AAAA ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_LOC) != NULL)
			strlcat(bitmap, "LOC ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_SRV) != NULL)
			strlcat(bitmap, "SRV ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_NAPTR) != NULL)	 /* 35 */
			strlcat(bitmap, "NAPTR ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_KX) != NULL)
			strlcat(bitmap, "KX ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_CERT) != NULL)
			strlcat(bitmap, "CERT ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_DS) != NULL)		/* 43 */
			strlcat(bitmap, "DS ", sizeof(bitmap));	
		if (find_rr(rbt, DNS_TYPE_SSHFP) != NULL)	 /* 44 */
			strlcat(bitmap, "SSHFP ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_IPSECKEY) != NULL)
			strlcat(bitmap, "IPSECKEY ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_ZONEMD) != NULL) 	  /* 63 */
			strlcat(bitmap, "ZONEMD ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_SVCB) != NULL)
			strlcat(bitmap, "SVCB ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_HTTPS) != NULL)
			strlcat(bitmap, "HTTPS ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_EUI48) != NULL)	/* 108 */
			strlcat(bitmap, "EUI48 ", sizeof(bitmap));
		if (find_rr(rbt, DNS_TYPE_EUI64) != NULL)	/* 109 */
			strlcat(bitmap, "EUI64 ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_CAA) != NULL)
			strlcat(bitmap, "CAA ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_NS) != NULL) {
			int isapex;

			if ((isapex = rbt_isapex(rbt, zone)) < 0) {
				dolog(LOG_INFO, "rbt_isapex failed\n");
				return -1;
			}

			if (isapex) {
				strlcat(bitmap, "RRSIG ", sizeof(bitmap));
			}
		} else  {
			strlcat(bitmap, "RRSIG ", sizeof(bitmap));	
		}

		if (find_rr(rbt, DNS_TYPE_DNSKEY) != NULL)
			strlcat(bitmap, "DNSKEY ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_NSEC3) != NULL) {
			strlcat(bitmap, "NSEC3 ", sizeof(bitmap));
		}

		strlcat(bitmap, "NSEC ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM) != NULL)
			strlcat(bitmap, "NSEC3PARAM ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_TLSA) != NULL)
			strlcat(bitmap, "TLSA ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_CDS) != NULL)
			strlcat(bitmap, "CDS ", sizeof(bitmap));

		if (find_rr(rbt, DNS_TYPE_CDNSKEY) != NULL)
			strlcat(bitmap, "CDNSKEY ", sizeof(bitmap));

		n1 = calloc(1, sizeof(struct mynsec));
		if (n1 == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}

		n1->name = strdup(rbt->humanname);
		n1->nextname = strdup(rbt->humanname);
		n1->bitmap = strdup(bitmap);
		if (n1->nextname == NULL || n1->bitmap == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}

		RB_INSERT(nsectree, &nsechead, n1);

		count++;
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

#if 0
		if (len > rootlen) {
			bitmap[0] = '\0';

			n1 = calloc(1, sizeof(struct mynsec));
			if (n1 == NULL) {
				dolog(LOG_INFO, "out of memory");
				return -1;
			}
			
			n1->name = strdup(rbt->humanname);
			n1->nextname = strdup(rbt->humanname);
			n1->bitmap = strdup(bitmap);	
			if (n1->nextname == NULL || n1->bitmap == NULL) {
				dolog(LOG_INFO, "out of memory");
				return -1;
			}

			TAILQ_INSERT_TAIL(&nsechead, n1, entries);
			count++;
		} /* if len > rootlen */
#endif

	} /* RB_FOREACH_SAFE */

	count = 0;
	RB_FOREACH(n2, nsectree, &nsechead) {
		if (count == 0) {
			count++;
			n1 = n2;
			continue;
		} else if (count == 1) {
			fill_nsec(db, n1->name, "nsec", ttl, n2->nextname, n1->bitmap);
		} else {
			fill_nsec(db, np->name, "nsec", ttl, n2->nextname, np->bitmap);
		}

		np = n2;
		count++;
	}
	fill_nsec(db, np->name, "nsec", ttl, n1->nextname, np->bitmap);

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
	if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no zonemd in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,zonemd,%d,%d,%d,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct zonemd *)rrp2->rdata)->serial,
				((struct zonemd *)rrp2->rdata)->scheme,
				((struct zonemd *)rrp2->rdata)->algorithm,
				bin2hex(((struct zonemd *)rrp2->rdata)->hash, ((struct zonemd *)rrp2->rdata)->hashlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no kx in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,kx,%d,%d,%s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct kx *)rrp2->rdata)->preference,
				convert_name(((struct kx *)rrp2->rdata)->exchange, ((struct kx *)rrp2->rdata)->exchangelen));
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
	if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no cds in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,cds,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct cds *)rrp2->rdata)->key_tag,
				((struct cds *)rrp2->rdata)->algorithm,
				((struct cds *)rrp2->rdata)->digest_type,
				bin2hex(((struct cds *)rrp2->rdata)->digest, ((struct cds *)rrp2->rdata)->digestlen));
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
	if ((rrset = find_rr(rbt, DNS_TYPE_HTTPS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no https in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,https,%d,%u,%s,\"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					((struct https *)rrp2->rdata)->priority,
					convert_name(((struct https *)rrp->rdata)->target, ((struct https *)rrp->rdata)->targetlen));

			fprintf(of, "%s", param_tlv2human(((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen, 0));
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SVCB)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no svcb in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "  %s,svcb,%d,%u,%s,\"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					((struct svcb *)rrp2->rdata)->priority,
					convert_name(((struct svcb *)rrp->rdata)->target, ((struct svcb *)rrp->rdata)->targetlen));

			fprintf(of, "%s", param_tlv2human(((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen, 0));
			fprintf(of, "\"\n");
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
	if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != NULL) {
		static u_int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};
		char latitude, longitude;
		uint32_t latsecfrac, latval, latsec, latmin, latdeg;
		uint32_t longsecfrac, longval, longsec, longmin, longdeg;
		int mantissa, exponent;
		uint32_t valsize, valhprec, valvprec;


		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no loc in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			longval = (((struct loc *)rrp2->rdata)->longitude - (1<<31));
			if (longval < 0) {
				longitude = 'W';
				longval = -longval;
			} else
				longitude = 'E';

			latval = (((struct loc *)rrp2->rdata)->latitude - (1<<31));
			if (latval < 0) {
				latitude = 'S';
				latval = -latval;
			} else
				latitude = 'N';

			latsecfrac = latval % 1000;
			latval = latval / 1000;
			latsec = latval % 60;
			latval = latval / 60;
			latmin = latval % 60;
			latval = latval / 60;
			latdeg = latval;

			longsecfrac = longval % 1000;
			longval = longval / 1000;
			longsec = longval % 60;
			longval = longval / 60;
			longmin = longval % 60;
			longval = longval / 60;
			longdeg = longval;

			mantissa = (int)((((struct loc *)rrp2->rdata)->size >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->size >> 0) & 0x0f) % 10;

			valsize = mantissa * poweroften[exponent];

			mantissa = (int)((((struct loc *)rrp2->rdata)->horiz_pre >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->horiz_pre >> 0) & 0x0f) % 10;

			valhprec = mantissa * poweroften[exponent];

			mantissa = (int)((((struct loc *)rrp2->rdata)->vert_pre >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->vert_pre >> 0) & 0x0f) % 10;

			valvprec = mantissa * poweroften[exponent];

			fprintf(of, "  %s,loc,%d,%u,%u,%u.%.3u,%c,%u,%u,%u.%.3u,%c,%u,%u,%u,%u\n",
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				latdeg, latmin, latsec, latsecfrac, latitude,
				longdeg, longmin, longsec, longsecfrac, longitude,
				((struct loc *)rrp2->rdata)->altitude, valsize,
				valhprec, valvprec);
	
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no tlsa in zone!\n");
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
			dolog(LOG_INFO, "no sshfp in zone!\n");
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
	if ((rrset = find_rr(rbt, DNS_TYPE_CERT)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no cert in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
                        len = mybase64_encode((const u_char *)((struct cert *)rrp2->rdata)->cert, ((struct cert *)rrp2->rdata)->certlen, buf, sizeof(buf));
                        buf[len] = '\0';

			fprintf(of, "  %s,cert,%d,%s,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				cert_type((struct cert *)rrp->rdata),
				((struct cert *)rrp2->rdata)->keytag,
				((struct cert *)rrp2->rdata)->algorithm,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_IPSECKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ipseckey in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
                        len = mybase64_encode((const u_char *)((struct ipseckey *)rrp2->rdata)->key, ((struct ipseckey *)rrp2->rdata)->keylen, buf, sizeof(buf));
                        buf[len] = '\0';

			fprintf(of, "  %s,ipseckey,%d,%d,%d,%d,\"%s\",\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct ipseckey *)rrp2->rdata)->precedence,
				((struct ipseckey *)rrp2->rdata)->gwtype,
				((struct ipseckey *)rrp2->rdata)->alg,
				ipseckey_type((struct ipseckey *)rrp2->rdata),
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a in zone!\n");
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
	if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
		uint8_t e[6];

		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no eui48 in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			memcpy(&e, &((struct eui48 *)rrp2->rdata)->eui48, 6);
			fprintf(of, "  %s,eui48,%d,\"%02x-%02x-%02x-%02x-%02x-%02x\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				e[0], e[1], e[2], e[3], e[4], e[5]);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
		uint8_t e[8];

		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no eui64 in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			inet_ntop(AF_INET, &((struct a *)rrp2->rdata)->a, buf, sizeof(buf));
			memcpy(&e, &((struct eui64 *)rrp2->rdata)->eui64, 8);
			fprintf(of, "  %s,eui64,%d,\"%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]);
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
	if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no cdnskey in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct cdnskey *)rrp2->rdata)->public_key, ((struct cdnskey *)rrp2->rdata)->publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "  %s,cdnskey,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				((struct cdnskey *)rrp2->rdata)->flags,
				((struct cdnskey *)rrp2->rdata)->protocol,
				((struct cdnskey *)rrp2->rdata)->algorithm,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no dnskey in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len, buf, sizeof(buf));
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
			dolog(LOG_INFO, "no nsec3 in zone!\n");
			return -1;
		}
		
		fprintf(of, "  ; H(%.*s) = %s\n  %s,nsec3,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\"\n",
			(strlen(rbt->unhashed_name) <= 40) ? (int)strlen(rbt->unhashed_name) : 40,
			rbt->unhashed_name,
			convert_name(rbt->zone, rbt->zonelen),
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl,
			((struct nsec3 *)rrp->rdata)->algorithm, 
			((struct nsec3 *)rrp->rdata)->flags,
			((struct nsec3 *)rrp->rdata)->iterations,
			(((struct nsec3 *)rrp->rdata)->saltlen == 0) ? "-" : bin2hex(((struct nsec3 *)rrp->rdata)->salt, ((struct nsec3 *)rrp->rdata)->saltlen),
			base32hex_encode((u_char *)((struct nsec3 *)rrp->rdata)->next, ((struct nsec3 *)rrp->rdata)->nextlen),
			bitmap2human(((struct nsec3 *)rrp->rdata)->bitmap, ((struct nsec3 *)rrp->rdata)->bitmap_len));

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no nsec in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec,%d,%s,\"%s\"\n",
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl,
			convert_name((u_char *)((struct nsec *)rrp->rdata)->next, ((struct nsec *)rrp->rdata)->next_len),
			bitmap2human(((struct nsec *)rrp->rdata)->bitmap, ((struct nsec *)rrp->rdata)->bitmap_len));

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no naptr in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct rrsig *)rrp2->rdata)->signature, ((struct rrsig *)rrp2->rdata)->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

#if defined __FreeBSD__ || defined __linux__
			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%lu,%lu,%d,%s,\"%s\"\n", 
#else
			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
#endif

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
getkeypid(struct keysentry *kn, char *key)
{
	char tmp[4096];

	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	int keyid;

	if ((zone = key2zone(kn, key, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, &keyid)) == NULL) {
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
key2zone(struct keysentry *kn, char *keyname, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int *keyid)
{
	int fd;
	char *zone;
	char buf[PATH_MAX];

	if (kn != NULL && kn->keypath != NULL) {
		snprintf(buf, sizeof(buf), "%s/%s.key", kn->keypath, keyname);
	} else {
		snprintf(buf, sizeof(buf), "%s.key", keyname);
	}

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
	static int ix = 0;
	char buf[512];

	
	snprintf(buf, sizeof(buf), "bindump.bin.%d", ix++);
	fd = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (const void *)&key[i], 1);
	}
	close(fd);
	
	return;
}

/*
 * sign() - sign an RR
 */

int
sign(int algorithm, char *key, int keylen, struct keysentry *key_entry, char *signature, int *siglen)
{
	DDD_RSA *rsa;
	DDD_EC_KEY *eckey;

	DDD_SHA256_CTX sha256;
	DDD_SHA384_CTX sha384;
	DDD_SHA512_CTX sha512;

	char shabuf[64];
	int bufsize;
	int rsatype;

	DDD_ECDSA_SIG *tmpsig;
	const DDD_BIGNUM *r = NULL, *s = NULL;

	uint8_t *ed_private;
	uint8_t *ed_public;

	char buf[512];
	int buflen = 0;
	
	/* digest */
	switch (algorithm) {
	case ALGORITHM_ECDSAP384SHA384:
		SHA384_Init(&sha384);
		SHA384_Update(&sha384, key, keylen);
		SHA384_Final((u_char *)shabuf, &sha384);
		bufsize = 48;
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
	case ALGORITHM_ED25519:
		break;
	default:
		dolog(LOG_INFO, "algorithm not supported\n");
		return -1;
	}

	/* sign */
	switch (algorithm) {
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
			delphinusdns_RSA_free(rsa);
			return -1;
		}

		if (delphinusdns_RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, (u_int*)siglen, rsa) != 1) {
			dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (delphinusdns_RSA_verify(rsatype, (u_char*)shabuf, bufsize, (u_char*)signature, *siglen, rsa) != 1) {
			dolog(LOG_INFO, "unable to verify with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
			
		delphinusdns_RSA_free(rsa);
		break;

	case ALGORITHM_ECDSAP256SHA256:
		/* FALLTHROUGH */
	case ALGORITHM_ECDSAP384SHA384:
		eckey = get_private_key_ec(key_entry);
		if (eckey == NULL) {
			dolog(LOG_INFO, "reading EC private key failed\n");
			return -1;
		}

			
		if ((tmpsig = delphinusdns_ECDSA_do_sign((u_char*)shabuf, bufsize, eckey)) == NULL) {
			dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			delphinusdns_EC_KEY_free(eckey);
			return -1;
		}

		if (delphinusdns_ECDSA_do_verify((u_char*)shabuf, bufsize, (const DDD_ECDSA_SIG *)tmpsig, eckey) != 1) {
			dolog(LOG_INFO, "unable to verify signature with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
			delphinusdns_EC_KEY_free(eckey);
			delphinusdns_ECDSA_SIG_free(tmpsig);
			return -1;
		}

		delphinusdns_ECDSA_SIG_get0(tmpsig, &r, &s);

		/*
		 * taken from PowerDNS's opensslsigners.cc, apparently a
		 * signature's r and s must be pre-padded with 0x0 if the
		 * size of r or s is less than full 32 bytes.
		 */

		memset(signature, 0, *siglen);

		buflen = delphinusdns_BN_bn2bin(r, (u_char*)buf);

		switch (algorithm) {
		case ALGORITHM_ECDSAP256SHA256:
			memcpy((char *)&signature[32 - buflen], buf, buflen);
			break;
		default:
			memcpy((char *)&signature[48 - buflen], buf, buflen);
			break;
		}

		buflen = delphinusdns_BN_bn2bin(s, (u_char*)buf);

		switch (algorithm) {
		case ALGORITHM_ECDSAP256SHA256:
			memcpy((char *)&signature[64 - buflen], buf, buflen);
			*siglen = (32 * 2);
			break;
		default:
			memcpy((char *)&signature[96 - buflen], buf, buflen);
			*siglen = (48 * 2);
			break;
		}

		delphinusdns_ECDSA_SIG_free(tmpsig);
		delphinusdns_EC_KEY_free(eckey);
		break;

	case ALGORITHM_ED25519:
		ed_private = get_private_key_ed25519(key_entry);
		if (ed_private == NULL) {
			dolog(LOG_INFO, "reading ED25519 private key failed\n");
			return -1;
		}

		ed_public = get_public_key_ed25519(key_entry);
		if (ed_public == NULL) {
			dolog(LOG_INFO, "reading ED25519 public key failed\n");
			return -1;
		}

		memset(signature, 0, *siglen);
		if (delphinusdns_ED25519_sign((uint8_t *)signature, key, keylen, ed_public, ed_private) == 0) {
			dolog(LOG_INFO, "ED25519 memory: %s\n", strerror(errno));
			return -1;
		}

		*siglen = DDD_ED25519_SIGNATURE_LENGTH;

		if (delphinusdns_ED25519_verify(key, keylen, signature, ed_public) == 0) {
			dolog(LOG_INFO, "ED25519 verification failed: %s\n", strerror(errno));
			return -1;
		}

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
		memcasecmp((u_char*)rbt->zone, (u_char*)zoneapex, rbt->zonelen) == 0) {
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
		

	} while (*p && len > 0 && ! (len == apexlen && memcasecmp((u_char*)p, (u_char*)zoneapex, len) == 0));
		

	free(zoneapex);
	/* let's pretend we're not glue here */
	return 1;
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

static int
rbt_isapex(struct rbtree *rbt, char *zonename)
{
	char *zoneapex;
	int apexlen, ret = 0;

	zoneapex = dns_label(zonename, &apexlen);
	if (zoneapex == NULL) {	
		dolog(LOG_INFO, "dns_label() in %s\n", __func__);
		return -1;
	}

	if (rbt->zonelen == apexlen && 
		memcasecmp((u_char*)rbt->zone, (u_char*)zoneapex, 
			rbt->zonelen) == 0) {
				ret = 1;
	}

	free(zoneapex);

	return (ret);
}

