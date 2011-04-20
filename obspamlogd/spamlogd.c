/*	$OpenBSD: spamlogd.c,v 1.19 2007/03/05 14:55:09 beck Exp $	*/

/*
 * Copyright (c) 2010 Martin Hedenfalk <martin@bzero.se>
 * Copyright (c) 2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2006 Berk D. Demir.
 * Copyright (c) 2004-2007 Bob Beck.
 * Copyright (c) 2001 Theo de Raadt.
 * Copyright (c) 2001 Can Erkin Acar.
 * All rights reserved
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

/* watch pf log for mail connections, update whitelist entries. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "compat.h"

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <db_185.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "grey.h"
#include "sync.h"

int quit = 0;
int debug = 1;
int greylist = 1;
FILE *grey = NULL;

u_short sync_port;
int syncsend;
u_int8_t		 flag_inbound = 0;
char			*networkif = NULL;
extern char		*__progname;

void	logmsg(int , const char *, ...);
void	sighandler_close(int);
int	dbupdate(char *, char *);
void	usage(void);

void
logmsg(int pri, const char *msg, ...)
{
	va_list	ap;
	va_start(ap, msg);

	if (debug) {
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	} else
		vsyslog_r(pri, &sdata, msg, ap);

	va_end(ap);
}

/* ARGSUSED */
void
sighandler_close(int signal)
{
	quit = 1;
}

/* Parse iptables -j LOG output, example:

Nov 19 13:16:56 ubuntu kernel: [52143.476929] obspamlogd: IN= OUT=eth0 SRC=172.16.116.143 DST=172.16.116.134 LEN=60 TOS=0x10 PREC=0x00 TTL=64 ID=18248 DF PROTO=TCP SPT=51006 DPT=25 WINDOW=5840 RES=0x00 SYN URGP=0 

Nov 19 13:17:39 ubuntu kernel: [52186.567444] obspamlogd: IN=eth0 OUT= MAC=00:0c:29:3d:25:7d:00:50:56:c0:00:08:08:00 SRC=172.16.116.1 DST=172.16.116.143 LEN=64 TOS=0x10 PREC=0x00 TTL=64 ID=2445 DF PROTO=TCP SPT=55832 DPT=25 WINDOW=65535 RES=0x00 SYN URGP=0 
 */

void
logpkt_handler(char *line)
{
	char *iface = NULL, *ip;
	char *p;
	int outbound = 0;

	if ((p = strstr(line, " obspamlogd: ")) == NULL) {
		logmsg(LOG_WARNING, "missing obspamlogd prefix");
		return;
	}

	if (strstr(p, " SYN ") == NULL) {
		logmsg(LOG_WARNING, "not a TCP connect");
		return;
	}

	if (strstr(p, " DPT=25 ") == NULL) {
		logmsg(LOG_WARNING, "not SMTP traffic");
		return;
	}

	if ((p = strstr(p, " IN=")) == NULL) {
		logmsg(LOG_WARNING, "missing inbound interface");
		return;
	}
	p += 4;
	if (*p == ' ') {
		outbound = 1;
		if ((p = strstr(p, " OUT=")) == NULL) {
			logmsg(LOG_WARNING, "missing outbound interface");
			return;
		}
		p += 5;

		if (*p == ' ') {
			logmsg(LOG_WARNING, "missing interface");
			return;
		}
	}

	iface = p;
	p += strcspn(p, " ");
	if (*p == '\0') {
		logmsg(LOG_WARNING, "premature end of line");
		return;
	}
	*p++ = '\0';

	if (outbound && flag_inbound)
		return;
	if (networkif != NULL && strcmp(networkif, iface) != 0)
		return;

	if (outbound) {
		if ((p = strstr(p, " DST=")) == NULL) {
			logmsg(LOG_WARNING, "missing destination address");
			return;
		}
	} else if ((p = strstr(p, " SRC=")) == NULL) {
		logmsg(LOG_WARNING, "missing source address");
		return;
	}
	p += 5;
	ip = p;
	p += strcspn(ip, " ");
	*p = '\0';

	logmsg(LOG_DEBUG, "%sbound %s (interface %s)", outbound ? "out" : "in", ip, iface);
	dbupdate(PATH_SPAMD_DB, ip);
}

int
dbupdate(char *dbname, char *ip)
{
	HASHINFO	hashinfo;
	DBT		dbk, dbd;
	DB		*db;
	struct gdata	gd;
	time_t		now;
	int		r;
	struct in_addr	ia;

	now = time(NULL);
	memset(&hashinfo, 0, sizeof(hashinfo));
	db = dbopen(dbname, O_EXLOCK|O_RDWR, 0600, DB_HASH, &hashinfo);
	if (db == NULL) {
		logmsg(LOG_ERR, "Can not open db %s: %s", dbname,
		    strerror(errno));
		return (-1);
	}
	if (inet_pton(AF_INET, ip, &ia) != 1) {
		logmsg(LOG_NOTICE, "Invalid IP address %s", ip);
		goto bad;
	}
	memset(&dbk, 0, sizeof(dbk));
	dbk.size = strlen(ip);
	dbk.data = ip;
	memset(&dbd, 0, sizeof(dbd));

	/* add or update whitelist entry */
	r = db->get(db, &dbk, &dbd, 0);
	if (r == -1) {
		logmsg(LOG_NOTICE, "db->get failed (%m)");
		goto bad;
	}

	if (r) {
		/* new entry */
		memset(&gd, 0, sizeof(gd));
		gd.first = now;
		gd.bcount = 1;
		gd.pass = now;
		gd.expire = now + WHITEEXP;
		memset(&dbk, 0, sizeof(dbk));
		dbk.size = strlen(ip);
		dbk.data = ip;
		memset(&dbd, 0, sizeof(dbd));
		dbd.size = sizeof(gd);
		dbd.data = &gd;
		r = db->put(db, &dbk, &dbd, 0);
		if (r) {
			logmsg(LOG_NOTICE, "db->put failed (%m)");
			goto bad;
		}
	} else {
		if (dbd.size != sizeof(gd)) {
			/* whatever this is, it doesn't belong */
			db->del(db, &dbk, 0);
			goto bad;
		}
		memcpy(&gd, dbd.data, sizeof(gd));
		gd.pcount++;
		gd.expire = now + WHITEEXP;
		memset(&dbk, 0, sizeof(dbk));
		dbk.size = strlen(ip);
		dbk.data = ip;
		memset(&dbd, 0, sizeof(dbd));
		dbd.size = sizeof(gd);
		dbd.data = &gd;
		r = db->put(db, &dbk, &dbd, 0);
		if (r) {
			logmsg(LOG_NOTICE, "db->put failed (%m)");
			goto bad;
		}
	}
	db->close(db);
	db = NULL;
	if (syncsend)
		sync_white(now, now + WHITEEXP, ip);
	return (0);
 bad:
	db->close(db);
	db = NULL;
	return (-1);
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-DI] [-i interface] [-l log_pipe] [-Y synctarget]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	char buf[4096];
	int ch;
	struct passwd	*pw;
	int syncfd = 0;
	int fd, nfds;
	ssize_t sz;
	struct servent *ent;
	char *sync_iface = NULL;
	char *sync_baddr = NULL;
	char *fifofile = "/var/run/obspamlogd.pipe";
	char *p, *nl, *end;
	struct pollfd pfd[1];
	u_int8_t flag_debug = 0;

	if ((ent = getservbyname("obspamd-sync", "udp")) == NULL)
		errx(1, "Can't find service \"obspamd-sync\" in /etc/services");
	sync_port = ntohs(ent->s_port);

	while ((ch = getopt(argc, argv, "DIi:l:Y:")) != -1) {
		switch (ch) {
		case 'D':
			flag_debug = 1;
			break;
		case 'I':
			flag_inbound = 1;
			break;
		case 'i':
			networkif = optarg;
			break;
		case 'l':
			fifofile = optarg;
			break;
		case 'Y':
			if (sync_addhost(optarg, sync_port) != 0)
				sync_iface = optarg;
			syncsend++;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	signal(SIGINT , sighandler_close);
	signal(SIGQUIT, sighandler_close);
	signal(SIGTERM, sighandler_close);

	logmsg(LOG_NOTICE, "opening %s", fifofile);
	if ((fd = open(fifofile, O_NONBLOCK)) == -1) {
		if (errno == ENOENT) {
			logmsg(LOG_DEBUG, "creating fifo %s", fifofile);
			if (mkfifo(fifofile, 0644) == -1)
				err(1, "%s", fifofile);
			fd = open(fifofile, O_NONBLOCK);
		}
		if (fd == -1 && errno != ENXIO)
			err(1, "%s", fifofile);
	}

	logmsg(LOG_DEBUG, "Listening on %s for %s %s", fifofile,
	    (networkif == NULL) ? "all interfaces." : networkif,
	    (flag_inbound) ? "Inbound direction only." : "");

	if (syncsend) {
		syncfd = sync_init(sync_iface, sync_baddr, sync_port);
		if (syncfd == -1)
			err(1, "sync init");
	}

	/* privdrop */
	pw = getpwnam("spamd");
	if (pw == NULL)
		errx(1, "User 'spamd' not found! ");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		err(1, "failed to drop privs");

	debug = flag_debug;
	if (!debug) {
		if (daemon(0, 0) == -1)
			err(1, "daemon");
		tzset();
		openlog_r("obspamlogd", LOG_PID | LOG_NDELAY, LOG_DAEMON, &sdata);
	}

	while (!quit) {
		memset(&pfd, 0, sizeof(pfd));
		pfd[0].fd = fd;
		pfd[0].events = POLLIN;

		errno = 0;
		nfds = poll(pfd, 1, -1);
		if (nfds < 0) {
			logmsg(LOG_WARNING, "poll: %m");
			if (errno == EINTR)
				continue;
			break;
		}
		if (nfds == 0)
			continue;

		if (pfd[0].revents & (POLLERR|POLLNVAL)) {
			logmsg(LOG_WARNING, "%s: poll error", fifofile);
			break;
		}

		if (pfd[0].revents & POLLHUP) {
			logmsg(LOG_NOTICE, "POLLHUP on fd %i", pfd[0]);
			sz = 0;
		} else {
			sz = read(fd, buf, sizeof(buf));
			if (sz == 0)
				logmsg(LOG_NOTICE, "end-of-file on fd %i", fd);
		}

		if (sz == 0) {
			close(fd);
			logmsg(LOG_NOTICE, "re-opening %s", fifofile);
			if ((fd = open(fifofile, O_NONBLOCK)) == -1 && errno != ENXIO) {
				logmsg(LOG_WARNING, "%s: %m", fifofile);
				break;
			}
			continue;
		} else if (sz < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			logmsg(LOG_WARNING, "%s: %m", fifofile);
			break;
		}

		end = buf + sz;
		for (p = buf; p < end; p = nl + 1) {
			nl = memchr(p, '\n', end - p);
			if (nl == NULL) {
				logmsg(LOG_WARNING, "unhandled partial input");
				break;
			}
			*nl = '\0';
			logpkt_handler(p);
		}
	}

	logmsg(LOG_NOTICE, "exiting");
	if (!debug)
		closelog_r(&sdata);

	exit(0);
}

