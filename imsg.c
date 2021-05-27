/*	$OpenBSD: imsg.c,v 1.16 2017/12/14 09:27:44 kettenis Exp $	*/

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "imsg.h"

int	 imsg_fd_overhead = 0;

static int	 imsg_get_fd(struct imsgbuf *);
static int	 getdtablecount(void);

void
imsg_init(struct imsgbuf *ibuf, int fd)
{
	msgbuf_init(&ibuf->w);
	memset(&ibuf->r, 0, sizeof(ibuf->r));
	ibuf->fd = fd;
	ibuf->w.fd = fd;
	ibuf->pid = getpid();
	TAILQ_INIT(&ibuf->fds);
}

ssize_t
imsg_read(struct imsgbuf *ibuf)
{
	struct msghdr		 msg;
	struct cmsghdr		*cmsg;
	union {
		struct cmsghdr hdr;
		char	buf[CMSG_SPACE(sizeof(int) * 1)];
	} cmsgbuf;
	struct iovec		 iov;
	ssize_t			 n = -1;
	int			 fd;
	struct imsg_fd		*ifd;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));

	iov.iov_base = ibuf->r.buf + ibuf->r.wpos;
	iov.iov_len = sizeof(ibuf->r.buf) - ibuf->r.wpos;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((ifd = calloc(1, sizeof(struct imsg_fd))) == NULL)
		return (-1);

again:
	if (getdtablecount() + imsg_fd_overhead +
	    (int)((CMSG_SPACE(sizeof(int))-CMSG_SPACE(0))/sizeof(int))
	    >= getdtablesize()) {
		errno = EAGAIN;
		free(ifd);
		return (-1);
	}

	if ((n = recvmsg(ibuf->fd, &msg, 0)) == -1) {
		if (errno == EINTR)
			goto again;
		goto fail;
	}

	ibuf->r.wpos += n;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			int i;
			int j;

			/*
			 * We only accept one file descriptor.  Due to C
			 * padding rules, our control buffer might contain
			 * more than one fd, and we must close them.
			 */
			j = ((char *)cmsg + cmsg->cmsg_len -
			    (char *)CMSG_DATA(cmsg)) / sizeof(int);
			for (i = 0; i < j; i++) {
				fd = ((int *)CMSG_DATA(cmsg))[i];
				if (ifd != NULL) {
					ifd->fd = fd;
					TAILQ_INSERT_TAIL(&ibuf->fds, ifd,
					    entry);
					ifd = NULL;
				} else
					close(fd);
			}
		}
		/* we do not handle other ctl data level */
	}

fail:
	free(ifd);
	return (n);
}

ssize_t
imsg_get(struct imsgbuf *ibuf, struct imsg *imsg)
{
	size_t			 av, left, datalen;

	av = ibuf->r.wpos;

	if (IMSG_HEADER_SIZE > av)
		return (0);

	memcpy(&imsg->hdr, ibuf->r.buf, sizeof(imsg->hdr));
	if (imsg->hdr.len < IMSG_HEADER_SIZE ||
	    imsg->hdr.len > MAX_IMSGSIZE) {
		errno = ERANGE;
		return (-1);
	}
	if (imsg->hdr.len > av)
		return (0);
	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	ibuf->r.rptr = ibuf->r.buf + IMSG_HEADER_SIZE;
	if (datalen == 0)
		imsg->data = NULL;
	else if ((imsg->data = malloc(datalen)) == NULL)
		return (-1);

	if (imsg->hdr.flags & IMSGF_HASFD)
		imsg->fd = imsg_get_fd(ibuf);
	else
		imsg->fd = -1;

	memcpy(imsg->data, ibuf->r.rptr, datalen);

	if (imsg->hdr.len < av) {
		left = av - imsg->hdr.len;
		memmove(&ibuf->r.buf, ibuf->r.buf + imsg->hdr.len, left);
		ibuf->r.wpos = left;
	} else
		ibuf->r.wpos = 0;

	return (datalen + IMSG_HEADER_SIZE);
}

int
imsg_compose(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid,
    int fd, const void *data, uint16_t datalen)
{
	struct ibuf	*wbuf;

	if ((wbuf = imsg_create(ibuf, type, peerid, pid, datalen)) == NULL)
		return (-1);

	if (imsg_add(wbuf, data, datalen) == -1)
		return (-1);

	wbuf->fd = fd;

	imsg_close(ibuf, wbuf);

	return (1);
}

int
imsg_composev(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid,
    int fd, const struct iovec *iov, int iovcnt)
{
	struct ibuf	*wbuf;
	int		 i, datalen = 0;

	for (i = 0; i < iovcnt; i++)
		datalen += iov[i].iov_len;

	if ((wbuf = imsg_create(ibuf, type, peerid, pid, datalen)) == NULL)
		return (-1);

	for (i = 0; i < iovcnt; i++)
		if (imsg_add(wbuf, iov[i].iov_base, iov[i].iov_len) == -1)
			return (-1);

	wbuf->fd = fd;

	imsg_close(ibuf, wbuf);

	return (1);
}

/* ARGSUSED */
struct ibuf *
imsg_create(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid,
    uint16_t datalen)
{
	struct ibuf	*wbuf;
	struct imsg_hdr	 hdr;

	datalen += IMSG_HEADER_SIZE;
	if (datalen > MAX_IMSGSIZE) {
		errno = ERANGE;
		return (NULL);
	}

	hdr.type = type;
	hdr.flags = 0;
	hdr.peerid = peerid;
	if ((hdr.pid = pid) == 0)
		hdr.pid = ibuf->pid;
	if ((wbuf = ibuf_dynamic(datalen, MAX_IMSGSIZE)) == NULL) {
		return (NULL);
	}
	if (imsg_add(wbuf, &hdr, sizeof(hdr)) == -1)
		return (NULL);

	return (wbuf);
}

int
imsg_add(struct ibuf *msg, const void *data, uint16_t datalen)
{
	if (datalen)
		if (ibuf_add(msg, data, datalen) == -1) {
			ibuf_free(msg);
			return (-1);
		}
	return (datalen);
}

void
imsg_close(struct imsgbuf *ibuf, struct ibuf *msg)
{
	struct imsg_hdr	*hdr;

	hdr = (struct imsg_hdr *)msg->buf;

	hdr->flags &= ~IMSGF_HASFD;
	if (msg->fd != -1)
		hdr->flags |= IMSGF_HASFD;

	hdr->len = (uint16_t)msg->wpos;

	ibuf_close(&ibuf->w, msg);
}

void
imsg_free(struct imsg *imsg)
{
	memset(imsg->data, 0, imsg->hdr.len - IMSG_HEADER_SIZE);
	free(imsg->data);
}

static int
imsg_get_fd(struct imsgbuf *ibuf)
{
	int		 fd;
	struct imsg_fd	*ifd;

	if ((ifd = TAILQ_FIRST(&ibuf->fds)) == NULL)
		return (-1);

	fd = ifd->fd;
	TAILQ_REMOVE(&ibuf->fds, ifd, entry);
	free(ifd);

	return (fd);
}

int
imsg_flush(struct imsgbuf *ibuf)
{
	while (ibuf->w.queued)
		if (msgbuf_write(&ibuf->w) <= 0)
			return (-1);
	return (0);
}

void
imsg_clear(struct imsgbuf *ibuf)
{
	int	fd;

	msgbuf_clear(&ibuf->w);
	while ((fd = imsg_get_fd(ibuf)) != -1)
		close(fd);
}

static int
setbit(int fd, uint8_t *bitmap)
{
	int block;
	int bit;

	block = fd / 8;
	bit = fd % 8;

	bitmap[block] |= (1 << bit);

	return (block);
}

static int
countbitmap(uint8_t *bitmap, int limit)
{
	int i;
	int block, bit;
	int ret = 0;

	for (i = 0; i < limit; i++) {
		block = i / 8;
		bit = i % 8;

		if (bitmap[block] & (1 << bit))
			ret++;
	}
	
	return (ret);
}


/*
 * really there is no way to know what descriptors are open in linux in an
 * atomic manner, this function is really bad for general usage, but it may
 * do it for my daemon, AND you don't know how many glasses of vodkas I had!
 */

#ifndef MIN
#define     MIN(a,b) (((a)<(b))?(a):(b))
#endif

static int
getdtablecount(void)
{
	int fd, i = 0, save;
	struct rlimit rl;
	struct stat sb;
	static char *bitmap = NULL;
	static int bc = 0, hb = 0;
	int block, bit;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return 0;

	if (bitmap == NULL) {
		bitmap = calloc((rl.rlim_cur + 7) / 8, 1);
		if (bitmap == NULL)
			return (rl.rlim_cur); /* XXX */
	
		goto scanbitmap;
	}

	for (fd = 0; fd <= (hb * 8); fd++) {
		block = fd / 8;
		bit = fd % 8;

		if (bitmap[block] & (1 << bit)) {
			if (fstat(fd, &sb) == 0)
				i++;
		}
	}

	if (i != bc) {
		/* scan entire bitmap again */
		memset(bitmap, 0, (rl.rlim_cur + 7) / 8);
		goto scanbitmap;
	} else {
		save = (hb * 8);
		for (fd = save + 1; fd < MIN(rl.rlim_cur, save + 128); fd++) {
			if (fstat(fd, &sb) == 0) {
				hb = setbit(fd, bitmap);
			}
		}
	}

	bc = countbitmap((uint8_t *)bitmap, rl.rlim_cur);	
	return (bc);

scanbitmap:

	for (fd = 0; fd < rl.rlim_cur; fd++) {
		if (fstat(fd, &sb) == 0) {
			hb = setbit(fd, bitmap);
		}
	}

	bc = countbitmap((uint8_t *)bitmap, rl.rlim_cur);	
	return (bc);
}
