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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>

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

static struct timeval tv0;
static time_t current_time;
uint16_t port = 53;
int noedns = 0;


/* prototypes */

int	dig(int argc, char *argv[]);
int	command_socket(char *);
int 	connect_server(char *, int, uint32_t);
int 	lookup_name(FILE *, int, char *, uint16_t, struct soa *, uint32_t, char *, uint16_t, int *, int*, uint16_t, struct tls *);
int	notglue(ddDB *, struct rbtree *, char *);
static struct tls * configure_client(void);



extern int debug;
extern int verbose;

extern int dnssec;
extern int tsig;
extern int bytes_received;
extern int cookies;

/* externs */

extern int insert_axfr(char *, char *);
extern int insert_filter(char *, char *);
extern int insert_passlist(char *, char *);
extern int insert_notifyddd(char *, char *);
extern int	usage(int argc, char *argv[]);
extern void	dolog(int pri, char *fmt, ...);

extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern int fill_dnskey(char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *);
extern int fill_rrsig(char *, char *, uint32_t, char *, uint8_t, uint8_t, uint32_t, uint64_t, uint64_t, uint16_t, char *, char *);
extern int fill_nsec3param(char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *);
extern int fill_nsec3(char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *, char *, char *);
extern int fill_nsec(char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *, char *, char *);
extern char * convert_name(char *name, int namelen);

extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);
extern struct rbtree *         Lookup_zone(ddDB *, char *, int, int, int);
extern struct question         *build_fake_question(char *, int, uint16_t, char *, int);
extern char * dns_label(char *, int *);
extern int label_count(char *);
extern char *get_dns_type(int, int);
extern char * hash_name(char *, int, struct nsec3param *);
extern char * base32hex_encode(u_char *input, int len);
extern int  	init_entlist(ddDB *);
extern int	check_ent(char *, int);
extern struct question          *build_question(char *, int, uint16_t, char *);
struct rrtab    *rrlookup(char *);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, uint16_t rrtype, void *rdata);
extern char * 	bin2hex(char *, int);
extern uint64_t timethuman(time_t);
extern char * 	bitmap2human(char *, int);

extern int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_svcb(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_https(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_eui48(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_eui64(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_loc(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_kx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ipseckey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cert(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cdnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_hinfo(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_caa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_rp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_zonemd(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern uint16_t raxfr_skip(FILE *, u_char *, u_char *);
extern int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, uint32_t, uint16_t, DDD_HMAC_CTX *, struct soa_constraints *);
extern int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, uint16_t *, uint32_t, DDD_HMAC_CTX *, char *, int, int);

extern int                      memcasecmp(u_char *, u_char *, int);
extern int 			tsig_pseudoheader(char *, uint16_t, time_t, DDD_HMAC_CTX *);
extern int  lookup_axfr(FILE *, int, char *, struct soa *, uint32_t, char *, char *, int *, int *, int *, struct soa_constraints *, uint32_t, int);
extern int 			insert_tsig(char *, char *);
extern int  			find_tsig_key(char *, int, char *, int);
extern int  			insert_tsig_key(char *, int, char *);
extern int 			insert_region(char *, char *);

extern int			add_cookie(char *, int, int, DDD_BIGNUM *, u_char *, int);
extern char *			input_sanitize(char *);


/* this struct must be under externs */

static struct raxfr_logic supported[] = {
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
	{ DNS_TYPE_RP, 0, raxfr_rp },
	{ DNS_TYPE_HINFO, 0, raxfr_hinfo },
	{ DNS_TYPE_CAA, 0, raxfr_caa },
	{ DNS_TYPE_ZONEMD, 0, raxfr_zonemd },
	{ DNS_TYPE_CDNSKEY, 1, raxfr_cdnskey },
	{ DNS_TYPE_CDS, 1, raxfr_cds },
	{ DNS_TYPE_LOC, 0, raxfr_loc },
	{ DNS_TYPE_EUI48, 0, raxfr_eui48 },
	{ DNS_TYPE_EUI64, 0, raxfr_eui64 },
	{ DNS_TYPE_SVCB, 0, raxfr_svcb },
	{ DNS_TYPE_HTTPS, 0, raxfr_https },
	{ DNS_TYPE_KX, 0, raxfr_kx },
	{ DNS_TYPE_IPSECKEY, 0, raxfr_ipseckey },
	{ DNS_TYPE_CERT, 0, raxfr_cert },
	{ DNS_TYPE_NSEC, 1, raxfr_nsec },
	/* end new support */
	{ 0, 0, NULL }
};

DDD_BIGNUM *provided_cookie = NULL;
int nocookie = 0;
extern int tls;

/*
 * DDDCTL QUERY 
 */

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
	char *yopt, *tsigpass = NULL, *tsigkey = NULL;
	uint32_t format = 0;
	uint16_t port = 53;
	uint16_t class = DNS_CLASS_IN;
	int ch, so, ms;
	int type = DNS_TYPE_A;
	int segment = 0;
	int answers = 0;
	int additionalcount = 0;
	int oldbehaviour = 0;
	struct soa_constraints constraints = { 0, 0, 0 };
	struct tls *ctx = NULL;

	while ((ch = getopt(argc, argv, "C:c:@:DEIONP:tTZp:Q:y:")) != -1) {
		switch (ch) {
		case 'C':
			provided_cookie = delphinusdns_BN_new();
			if (provided_cookie == NULL) {
				fprintf(stderr, "bignum failure\n");
				exit(1);
			}
			delphinusdns_BN_hex2bn(&provided_cookie, optarg);
			if (delphinusdns_BN_num_bytes(provided_cookie) != 24) {
				fprintf(stderr, "cookie must be 24 bytes!\n");
				exit(1);
			}
			break;
		case 'c':
			class = atoi(optarg);
			break;
		case '@':
		case 'Q':
			nameserver = optarg;
			break;
		case 'D':
			format |= DNSSEC_FORMAT;
			break;
		case 'E':
			noedns = 1;
			nocookie = 1;
			break;
		case 'I':
			format |= INDENT_FORMAT;
			break;
		case 'O':
			oldbehaviour = 1;
			break;	
		case 'N':
			nocookie = 1;
			break;
		case 'P':
			port = atoi(optarg);
			break;
		case 't':
			format |= TCP_FORMAT;
			port = 853;
			tls = 1;
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
		case 'y':
			yopt = strdup(optarg);
			if (yopt == NULL) {
				perror("strdup");
				exit(1);
			}
			tsigkey = yopt;
			tsigpass = strchr(yopt, ':');
			if (tsigpass == NULL) {
				fprintf(stderr, "must provide keyname:password for option -y\n");
				exit(1);
			}
			*tsigpass = '\0';
			tsigpass++;
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

	if (tls) {
		ctx = configure_client();	
		if (ctx == NULL) {
			perror("TLS");
			exit(1);
		}

		if (tls_connect(ctx, nameserver, "853") < 0) {
			exit(1);
		}
		if (tls_handshake(ctx) == -1) {
			fprintf(stderr, "handshake failed: %s\n", tls_error(ctx));
			exit(1);
		}
	} else {
		so = connect_server(nameserver, port, format);
		if (so < 0) {
			exit(1);
		}
	}


	segment = 0;
	answers = 0;

	if (type == DNS_TYPE_AXFR) {
		if ((format & ZONE_FORMAT) && f != NULL) 
			fprintf(f, "zone \"%s\" {\n", domainname);

		if (lookup_axfr(f, so, domainname, &mysoa, format, tsigkey, tsigpass, &segment, &answers, &additionalcount, &constraints, 0xffffffff, oldbehaviour) < 0) {
			exit(1);
		}

		if ((format & ZONE_FORMAT) && f != NULL)
			fprintf(f, "}\n");

				
	} else {
		if (lookup_name(f, so, domainname, type, &mysoa, format, nameserver, port, &answers, &additionalcount, class, ctx) < 0) {
			/* XXX maybe a packet dump here? */
			exit(1);
		}
	}

	if (tls) {
		tls_close(ctx);
	} else {
		close(so);
	}

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

		if (additionalcount)
			answers -= additionalcount;

		fprintf(f, ";; XFR size %d records (messages %d, bytes %d)\n", 
			answers, segment, bytes_received);
	} else {
		fprintf(f, ";; MSG SIZE  rcvd: %d\n", bytes_received);
	}

	if (f != stdout && f != NULL)
		fclose(f);

	return 0;
}

int
connect_server(char *nameserver, int port, uint32_t format)
{
	struct sockaddr_in sin;
	int so;
	int window = 32768;

	if (format & TCP_FORMAT)
		so =  socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	else
		so =  socket(AF_INET, SOCK_DGRAM, 0);
		
	if (so < 0) {
		perror("socket");
		return -1;
	}

#ifndef __linux__
	/* biggen the window */

	while (setsockopt(so, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) != -1)
		window <<= 1;
#endif


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(nameserver);
	
	if (connect(so, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("connect");
		return -1;
	}

	if (tls) {
	}

	return (so);	
}

int
lookup_name(FILE *f, int so, char *zonename, uint16_t myrrtype, struct soa *mysoa, uint32_t format, char *nameserver, uint16_t port, int *answers, int *additionalcount, uint16_t qclass, struct tls *ctx)
{
	ssize_t slen = 0;
	int len, i, tmp32;
	int numansw, numaddi, numauth;
	int printansw = 1, printauth = 1, printaddi = 1;
	int rrtype, soacount = 0;
	int tmplen;
	uint16_t rdlen;
	char query[4096];
	char *pq = NULL;
	char *reply;
	struct raxfr_logic *sr;
	struct question *q;
	struct dns_optrr *optrr;
	struct whole_header {
		struct dns_header dh;
	} *wh, *rwh;
	struct soa_constraints constraints = { 60, 60, 60 };
	
	u_char *p, *name;

	u_char *end, *estart;
	u_char cookie[64];
	int totallen, zonelen, rrlen;
	int replysize = 0;
	uint16_t class = 0, type = 0, tcpsize;
	uint16_t plen;
	uint16_t tcplen;

	if (format & TCP_FORMAT)
		replysize = 0xffff;
	else
		replysize = 4096;


	memset(&query, 0, sizeof(query));
	
	if (format & TCP_FORMAT) {
		tcpsize = unpack16(&query[0]);
		wh = (struct whole_header *)&query[2];
	} else
		wh = (struct whole_header *)&query[0];
	
	wh->dh.id = htons(arc4random_uniform(0xffff));
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	if (! noedns)
		wh->dh.additional = htons(1);
	else
		wh->dh.additional = htons(0);

	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);

	
	HTONS(wh->dh.query);

	if (format & TCP_FORMAT)
		totallen = sizeof(struct whole_header) + 2;
	else
		totallen = sizeof(struct whole_header);

	name = (u_char*)dns_label(zonename, &len);
	if (name == NULL) {
		return -1;
	}

	zonelen = len;
	
	p = (u_char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;

	type = htons(myrrtype);
	pack16(&query[totallen], type);
	totallen += sizeof(uint16_t);
	
	class = htons(qclass);
	pack16(&query[totallen], class);
	totallen += sizeof(uint16_t);

	if (! noedns) {
		/* attach EDNS0 */

		optrr = (struct dns_optrr *)&query[totallen];

		optrr->name[0] = 0;
		optrr->type = htons(DNS_TYPE_OPT); 
		optrr->class = htons(replysize);
		optrr->ttl = htonl(0);		/* EDNS version 0 */
		if ((format & DNSSEC_FORMAT))
			SET_DNS_ERCODE_DNSSECOK(optrr);
		HTONL(optrr->ttl);

		if (! nocookie) {
			cookies = 1;
			if (provided_cookie != NULL)
				optrr->rdlen = htons(2 + 2 + 24);
			else
				optrr->rdlen = htons(2 + 2 + 8);
		} else
			optrr->rdlen = 0;

		optrr->rdata[0] = 0;

		totallen += (sizeof(struct dns_optrr));

		/* add cookie */
		if (! nocookie) {
			tmplen = add_cookie(query, sizeof(query), totallen, provided_cookie, (u_char *)&cookie, sizeof(cookie));
			if (tmplen > totallen) {
				totallen = tmplen;
				printf("; COOKIE: %s\n", cookie);
			}
		}
	}

	if (format & TCP_FORMAT) {
		tcpsize = htons(totallen - 2);
		pack16(&query[0], tcpsize);
	}

	if (tls) {
		pq = query;
		while (totallen > 0) {
                   ssize_t ret;

                   ret = tls_write(ctx, pq, totallen);
                   if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
                           continue;
                   if (ret == -1)
                           fprintf(stderr, "tls_write: %s", tls_error(ctx));

                   pq += (int)ret;
                   totallen -= (int)ret;
           	}

	} else {
		if (send(so, query, totallen, 0) < 0) {
			return -1;
		}
	}

	printf(";; QUESTION SECTION:\n");
	printf("; %s.\tIN\t%s\n", zonename, get_dns_type(myrrtype, 0));

	/* catch reply */

	reply = calloc(1, replysize + 2);
	if (reply == NULL) {
		perror("calloc");
		return -1;
	}
	
	if (tls || (format & TCP_FORMAT)) {
		if (tls) {
			char *pb = reply;
			size_t expect = 2;

			while (expect > 0) {
				ssize_t rret;

				rret = tls_read(ctx, pb, expect);

				if (rret == TLS_WANT_POLLIN || rret == TLS_WANT_POLLOUT)
					continue;

				if (rret == -1) {
					fprintf(stderr, "tls_read(): %s\n", tls_error(ctx));
					exit(1);
				}

				expect -= rret;
				pb += rret;
			}	

			len = 2;

			plen = unpack16(reply);
			tcplen = ntohs(plen);

			expect = tcplen;
			pb = &reply[2];

			while (expect > 0) {
				ssize_t rret;

				rret = tls_read(ctx, pb, expect);

				if (rret == TLS_WANT_POLLIN || rret == TLS_WANT_POLLOUT)
					continue;

				if (rret == -1) {
					fprintf(stderr, "tls_read(): %s\n", tls_error(ctx));
					exit(1);
				}

				expect -= rret;
				pb += rret;
				slen += rret;
			}	

			plen = unpack16(reply);
			tcplen = ntohs(plen);

			len += slen;
		} else {
			if ((len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL)) < 0) {
				perror("recv");
				return -1;
			}

			plen = unpack16(reply);
			tcplen = ntohs(plen);

			if ((len = recv(so, reply, tcplen + 2, MSG_WAITALL)) < 0) {
				perror("recv");
				return -1;
			}
		}
	} else {
		if ((len = recv(so, reply, replysize, 0)) < 0) {
			return -1;
		}
	}


	if (tls || (format & TCP_FORMAT))
		rwh = (struct whole_header *)&reply[2];
	else
		rwh = (struct whole_header *)&reply[0];

	bytes_received += len;

	end = (u_char*)&reply[len];

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

		ret = lookup_name(f, so, zonename, myrrtype, mysoa, format, nameserver, port, answers, additionalcount, qclass, ctx);
		close(so);
		return (ret);
	}
	
	numansw = ntohs(rwh->dh.answer);
	numauth = ntohs(rwh->dh.nsrr);
	numaddi = ntohs(rwh->dh.additional);
	tmp32 = (numansw + numauth + numaddi);
	pack32((char *)answers, tmp32);

	if (tmp32 < 1) {	
		fprintf(stderr, "NO ANSWER provided\n");
		return -1;
	}

#if 0
	for (i = 0; i < len; i++) {
		if (i && i % 16 == 0)
			printf("\n");

		printf("%02X ", reply[i] & 0xff);
	}
	printf("\n");
#endif


	q = build_question((char *)&wh->dh, len, ntohs(wh->dh.additional), NULL);
	if (q == NULL) {
		fprintf(stderr, "failed to build_question\n");
		return -1;
	}
		
	if (memcmp(q->hdr->name, name, q->hdr->namelen) != 0) {
		fprintf(stderr, "question name not for what we asked\n");
		return -1;
	}

	if (q->hdr->qclass != class || q->hdr->qtype != type) {
		fprintf(stderr, "wrong class or type\n");
		return -1;
	}
	
	p = (u_char *)&rwh[1];		
	
	p += q->hdr->namelen;
	p += sizeof(uint16_t);	 	/* type */
	p += sizeof(uint16_t);		/* class */

	/* end of question */

	if (q->cookie.have_cookie) {
		int have_client_cookie = 0;
		int j;

		printf("; SERVER COOKIE: ");
		
		for (i = len - 9; i >= sizeof(struct dns_header); i--) {
			if (memcmp(&reply[i], q->cookie.clientcookie, 8) == 0) {
				uint16_t *cookie_len;
			
				if (i >= 2) {
					cookie_len = (uint16_t *)&reply[i - 2];
					NTOHS(*cookie_len);
				} else
					break;

				have_client_cookie = 1;
				for (j = 0; i < len && j < *cookie_len; i++, j++) {
					printf("%02X", reply[i] & 0xff);
				
				}
				break;
			}
		}

		if (! have_client_cookie)
			printf("[client cookie not copied]");
		else
			printf(" (good)");

		printf("\n");
	}

	estart = (u_char *)&rwh->dh;

	for (i = *answers; i > 0; i--) {
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


		if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, 0, &rdlen, format, NULL, (char *)name, zonelen, 0)) < 0) {
			fprintf(stderr, "not a SOA reply, or ERROR\n");
			return -1;
		}
		
		p = (estart + rrlen);

		if (rrtype == DNS_TYPE_SOA) {
			if ((len = raxfr_soa(f, p, estart, end, mysoa, soacount, format, rdlen, NULL, &constraints)) < 0) {
				fprintf(stderr, "raxxfr_soa failed\n");
				return -1;
			}
			p = (estart + len);
			soacount++;
		} else {
			for (sr = supported; sr->rrtype != 0; sr++) {
				if (rrtype == sr->rrtype) {
					if ((len = (*sr->raxfr)(f, p, estart, end, mysoa, rdlen, NULL)) < 0) {
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

static struct tls *
configure_client(void)
{
	struct tls_config *tls_config;
	struct tls *ctx;
	uint32_t protocols = (TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOLS_DEFAULT);
	char  *tls_protocols = NULL;
	char *tls_ciphers = NULL;
	char *tls_ca_mem = NULL;
	size_t tls_ca_size;

	tls_config = tls_config_new();
	if (tls_config == NULL) {
		exit(1);
	}

	if ((ctx = tls_client()) == NULL) {
		exit(1);
	}

	if (tls_protocols) {
		if (tls_config_parse_protocols(&protocols, 
				tls_protocols) < 0) {
			
			exit(1);
		}
	}
		
	if (tls_config_set_protocols(tls_config, TLS_PROTOCOLS_ALL) < 0) {
		exit(1);
	}


	if (tls_config_set_ciphers(tls_config, tls_ciphers) < 0) {
		exit(1);
	}

#if 0
	if (! tls_certfile || tls_config_set_cert_file(tls_config,
		tls_certfile) < 0) {
		exit(1);
	}
	
	if (! tls_keyfile || tls_config_set_key_file(tls_config,
		tls_keyfile) < 0) {
		exit(1);
	}
#endif

	/* thanks rpki-client.c */

#ifndef __NetBSD__
	tls_ca_mem = tls_load_file(tls_default_ca_cert_file(), &tls_ca_size,
			NULL);
	
	if (tls_ca_mem == NULL) {
		fprintf(stderr, "tls_load_file: %s", tls_default_ca_cert_file());
		exit(1);
	}


	tls_config_set_ca_mem(tls_config, tls_ca_mem, tls_ca_size);

#endif

	//tls_config_verify_client_optional(tls_config)I;

	
	if (tls_configure(ctx, tls_config) < 0) {
		exit(1);
	}

	//tls_config_clear_keys(tls_config);

	return (ctx);
}
