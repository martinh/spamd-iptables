PROG=	obspamdb
SRCS=	spamdb.c
MAN=	spamd.8

CFLAGS+= -Wall -Wstrict-prototypes
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -I../compat -I../obspamd

LDADD+=	-ldb

all: $(PROG)

OBJS=	$(SRCS:.c=.o)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDADD)

clean:
	rm -f $(OBJS) $(PROG)

install: $(PROG)
	install -d /usr/local/sbin
	install -m 0755 $(PROG) /usr/local/sbin


