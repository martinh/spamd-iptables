PROG=	obspamd-setup
SRCS=	spamd-setup.c
SRCS+=	../compat/getcap.c
SRCS+=	../compat/fgetln.c
MAN=	spamd-setup.8

CFLAGS+= -Wall -Wstrict-prototypes
CFLAGS+= -I../compat -D_GNU_SOURCE

LDADD+=	-ldb -lz -lresolv

all: $(PROG)

OBJS=	$(SRCS:.c=.o)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDADD)

clean:
	rm -f $(OBJS) $(PROG)

install: $(PROG)
	install -d /usr/local/sbin
	install -m 0755 $(PROG) /usr/local/sbin

