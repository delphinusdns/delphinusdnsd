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
 * $Id: query.c,v 1.7 2020/07/15 20:27:15 pjp Exp $
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
u_int16_t port = 53;
int bytes_received;


/* prototypes */

int	dig(int argc, char *argv[]);
int	command_socket(char *);
int 	connect_server(char *, int, u_int32_t);
int 	lookup_name(FILE *, int, char *, u_int16_t, struct soa *, u_int32_t, char *, u_int16_t, int *, int*);
int	notglue(ddDB *, struct rbtree *, char *);



extern int debug;
extern int verbose;

extern int dnssec;
extern int tsig;

/* externs */

extern int insert_axfr(char *, char *);
extern int insert_filter(char *, char *);
extern int insert_whitelist(char *, char *);
extern int insert_notifyddd(char *, char *);
extern int	usage(int argc, char *argv[]);
extern void	dolog(int pri, char *fmt, ...);

extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern int fill_dnskey(char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);
extern int fill_rrsig(char *, char *, u_int32_t, char *, u_int8_t, u_int8_t, u_int32_t, u_int64_t, u_int64_t, u_int16_t, char *, char *);
extern int fill_nsec3param(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *);
extern int fill_nsec3(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *, char *, char *);
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

extern int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern u_int16_t raxfr_skip(FILE *, u_char *, u_char *);
extern int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, u_int32_t, u_int16_t, HMAC_CTX *);
extern int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, u_int16_t *, u_int32_t, HMAC_CTX *);

extern int                      memcasecmp(u_char *, u_char *, int);
extern int 			tsig_pseudoheader(char *, uint16_t, time_t, HMAC_CTX *);
extern int  lookup_axfr(FILE *, int, char *, struct soa *, u_int32_t, char *, char *, int *, int *, int *);
extern int 			insert_tsig(char *, char *);
extern int  			find_tsig_key(char *, int, char *, int);
extern int  			insert_tsig_key(char *, int, char *);
extern int 			insert_region(char *, char *);


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
	{ 0, 0, NULL }
};


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
	u_int32_t format = 0;
	u_int16_t port = 53;
	int ch, so, ms;
	int type = DNS_TYPE_A;
	int segment = 0;
	int answers = 0;
	int additionalcount = 0;

	while ((ch = getopt(argc, argv, "@:DIP:TZp:Q:y:")) != -1) {
		switch (ch) {
		case '@':
		case 'Q':
			nameserver = optarg;
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

	so = connect_server(nameserver, port, format);
	if (so < 0) {
		exit(1);
	}

	segment = 0;
	answers = 0;

	if (type == DNS_TYPE_AXFR) {
		if (lookup_axfr(f, so, domainname, &mysoa, format, tsigkey, tsigpass, &segment, &answers, &additionalcount) < 0) {
			exit(1);
		}
				
	} else {
		if (lookup_name(f, so, domainname, type, &mysoa, format, nameserver, port, &answers, &additionalcount) < 0) {
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
connect_server(char *nameserver, int port, u_int32_t format)
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


	return (so);	
}

int
lookup_name(FILE *f, int so, char *zonename, u_int16_t myrrtype, struct soa *mysoa, u_int32_t format, char *nameserver, u_int16_t port, int *answers, int *additionalcount)
{
	int len, i, tmp32;
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
	u_int16_t class = 0, type = 0, tcpsize;
	u_int16_t plen;
	u_int16_t tcplen;

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

	type = htons(myrrtype);
	pack16(&query[totallen], type);
	totallen += sizeof(u_int16_t);
	
	class = htons(DNS_CLASS_IN);
	pack16(&query[totallen], class);
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

	if (format & TCP_FORMAT) {
		tcpsize = htons(totallen - 2);
		pack16(&query[0], tcpsize);
	}

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

		plen = unpack16(reply);
		tcplen = ntohs(plen);

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

	bytes_received += len;

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

		ret = lookup_name(f, so, zonename, myrrtype, mysoa, format, nameserver, port, answers, additionalcount);
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


	q = build_question((char *)&wh->dh, len, wh->dh.additional, NULL);
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
	p += sizeof(u_int16_t);	 	/* type */
	p += sizeof(u_int16_t);		/* class */

	/* end of question */
	

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


		if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, 0, &rdlen, format, NULL)) < 0) {
			fprintf(stderr, "not a SOA reply, or ERROR\n");
			return -1;
		}
		
		p = (estart + rrlen);

		if (rrtype == DNS_TYPE_SOA) {
			if ((len = raxfr_soa(f, p, estart, end, mysoa, soacount, format, rdlen, NULL)) < 0) {
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
