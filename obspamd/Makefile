PROG=	obspamd
SRCS=	spamd.c sdl.c grey.c sync.c
SRCS+=	../compat/strlcpy.c
SRCS+=	../compat/strlcat.c
SRCS+=	../compat/sha1.c
SRCS+=	../compat/strtonum.c
SRCS+=	../compat/fgetln.c
SRCS+=	../compat/setproctitle.c
SRCS+=	../compat/vis.c
MAN=	spamd.8

CFLAGS+= -Wall -Wstrict-prototypes
CFLAGS+= -I../compat -D_GNU_SOURCE

LDADD+=	-ldb -lcrypto -liptc

all: $(PROG)

OBJS=	$(SRCS:.c=.o)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDADD)

clean:
	rm -f $(OBJS) $(PROG)

install: $(PROG)
	install -d /usr/local/sbin
	install -m 0755 $(PROG) /usr/local/sbin

