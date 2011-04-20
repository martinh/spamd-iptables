PROG=	obspamlogd
SRCS=	spamlogd.c ../obspamd/sync.c
SRCS+=	../compat/strlcat.c
SRCS+=	../compat/strlcpy.c
SRCS+=	../compat/fgetln.c
SRCS+=	../compat/strtonum.c
MAN=	spamlogd.8

CFLAGS+= -Wall -Wstrict-prototypes -D_GNU_SOURCE
CFLAGS+= -I../compat -I../obspamd
LDADD+= -ldb -lcrypto

all: $(PROG)

OBJS=	$(SRCS:.c=.o)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDADD)

clean:
	rm -f $(OBJS) $(PROG)

install: $(PROG)
	install -d /usr/local/sbin
	install -m 0755 $(PROG) /usr/local/sbin

