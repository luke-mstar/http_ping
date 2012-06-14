# Makefile for http_ping

# CONFIGURE: If you are using a SystemV-based operating system, such as
# Solaris, you will need to uncomment this definition.
#SYSV_LIBS =	-lnsl -lsocket

# CONFIGURE: If you want to compile in support for https, uncomment these
# definitions.  You will need to have already built OpenSSL, available at
# http://www.openssl.org/  Make sure the SSL_TREE definition points to the
# tree with your OpenSSL installation - depending on how you installed it,
# it may be in /usr/local instead of /usr/local/ssl.
#SSL_TREE =	/usr/local/ssl
#SSL_DEFS =	-DUSE_SSL
#SSL_INC =	-I$(SSL_TREE)/include
#SSL_LIBS =	-L$(SSL_TREE)/lib -lssl -lcrypto


BINDIR =	/usr/local/bin
MANDIR =	/usr/local/man/man1
CC =		gcc -Wall
CFLAGS =	-O $(SRANDOM_DEFS) $(SSL_DEFS) $(SSL_INC)
#CFLAGS =	-g $(SRANDOM_DEFS) $(SSL_DEFS) $(SSL_INC)
LDFLAGS =	-s $(SSL_LIBS) $(SYSV_LIBS)
#LDFLAGS =	-g $(SSL_LIBS) $(SYSV_LIBS)

all:		http_ping

http_ping:	http_ping.o
	$(CC) $(CFLAGS) http_ping.o $(LDFLAGS) -o http_ping

http_ping.o:	http_ping.c port.h
	$(CC) $(CFLAGS) -c http_ping.c


install:	all
	rm -f $(BINDIR)/http_ping
	cp http_ping $(BINDIR)
	rm -f $(MANDIR)/http_ping.1
	cp http_ping.1 $(MANDIR)

clean:
	rm -f http_ping *.o core core.* *.core
