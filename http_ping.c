/* http_ping - measure HTTP latency
**
** Copyright © 1998,1999,2001,2002 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#include "port.h"

#define INTERVAL 5
#define TIMEOUT 15

#define max(a,b) ((a)>=(b)?(a):(b))
#define min(a,b) ((a)<=(b)?(a):(b))

static char* url;
static int url_protocol;
static char url_host[5000];
static unsigned short url_port;
static char* url_filename;
static char* request_data_file;
/* static char* request_data; */
static char* method;
static char* vhost;

/* Protocol symbols. */
#define PROTO_HTTP 0
#ifdef USE_SSL
#define PROTO_HTTPS 1
#endif

static unsigned short port;
static int conn_fd;
#ifdef USE_SSL
static SSL* ssl;
#endif
static int conn_state, conn_state;
static int got_response;
static struct timeval started_at, connect_at, response_at, finished_at;
static long content_length;
static long bytes;

#define ST_BOL 0
#define ST_TEXT 1
#define ST_LF 2
#define ST_CR 3
#define ST_CRLF 4
#define ST_CRLFCR 5
#define ST_C 6
#define ST_CO 7
#define ST_CON 8
#define ST_CONT 9
#define ST_CONTE 10
#define ST_CONTEN 11
#define ST_CONTENT 12
#define ST_CONTENT_ 13
#define ST_CONTENT_L 14
#define ST_CONTENT_LE 15
#define ST_CONTENT_LEN 16
#define ST_CONTENT_LENG 17
#define ST_CONTENT_LENGT 18
#define ST_CONTENT_LENGTH 19
#define ST_CONTENT_LENGTH_COLON 20
#define ST_CONTENT_LENGTH_COLON_WHITESPACE 21
#define ST_CONTENT_LENGTH_COLON_WHITESPACE_NUM 22
#define ST_DATA 23

static char* argv0;
static int count;
static int interval;
static int timeout;
static int nagle;
static int quiet;
static int do_keepalive;
static int do_proxy;
static char* proxy_host;
static unsigned short proxy_port;

static int terminate;
static int count_started, count_completed, count_failures, count_timeouts;
static long total_bytes;
static jmp_buf jb;

static float min_total, min_connect, min_response, min_data;
static float max_total, max_connect, max_response, max_data;
static float sum_total, sum_connect, sum_response, sum_data;

#ifdef USE_SSL
static SSL_CTX* ssl_ctx = (SSL_CTX*) 0;
#endif


/* Forwards. */
static void usage( void );
static void parse_url( void );
static void parse_request_file( void );
static void init_net( void );
static int start_connection( void );
static void lookup_address( char* hostname, unsigned short port );
static int open_client_socket( void );
static int handle_read( void );
static void handle_term( int sig );
static void handle_alarm( int sig );
static void close_connection( void );
static long long delta_timeval( struct timeval* start, struct timeval* finish );


int
main( int argc, char** argv )
    {
    int argn;
    float elapsed_total, elapsed_connect, elapsed_response, elapsed_data;

    /* Parse args. */
    argv0 = argv[0];
    argn = 1;
    count = -1;
    interval = INTERVAL;
    quiet = 0;
    nagle=0;
    do_proxy = 0;
    do_keepalive = 0;
    method = 0;
    vhost = 0;
    request_data_file = 0;
    while ( argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0' )
	{
	if ( strncmp( argv[argn], "-count", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    count = atoi( argv[++argn] );
	    if ( count <= 0 )
			{
			(void) fprintf( stderr, "%s: count must be positive\n", argv0 );
			exit( 1 );
			}
	    }
	else if ( strncmp( argv[argn], "-interval", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    interval = atoi( argv[++argn] );
	    if ( interval < 1 && interval )
			{
			(void) fprintf( stderr, "%s: interval will be zero when set to less than one\n", argv0 );
			interval = 0;
			}
	    }
	else if ( strncmp( argv[argn], "-timeout", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    timeout = atoi( argv[++argn] );
	    if ( timeout < 1 )
			{
			(void) fprintf( stderr, "%s: timeout will be one second when set to less than one\n", argv0 );
			timeout = 1;
			}
	    }
	else if ( strncmp( argv[argn], "-quiet", strlen( argv[argn] ) ) == 0 )
	    {
	    quiet = 1;
	    }
	else if ( strncmp( argv[argn], "-nagle", strlen( argv[argn] ) ) == 0 )
	    {
	    nagle = 1;
	    }
	else if ( strncmp( argv[argn], "-proxy", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    char* colon;
	    do_proxy = 1;
	    proxy_host = argv[++argn];
	    colon = strchr( proxy_host, ':' );
	    if ( colon == (char*) 0 )
	    	proxy_port = 80;
	    else
			{
			proxy_port = (unsigned short) atoi( colon + 1 );
			*colon = '\0';
			}
	    }
	else if ( strncmp( argv[argn], "-method", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
    	{
		method = argv[++argn];
		}
	else if ( strncmp( argv[argn], "-vhost", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
    	{
		vhost = argv[++argn];
		}
	else if ( strncmp( argv[argn], "-file", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
    	{
		request_data_file = argv[++argn];
		}
	else
	    usage();
		++argn;
	}
    if (request_data_file)
    	{
        if ( argn != argc )
        	usage();
        parse_request_file();
    	}
    else
    	{
		if ( argn + 1 != argc )
			usage();
		url = argv[argn];
		}

    /* Parse the URL. */
    parse_url();

    /* Initialize the network stuff. */
    init_net();

    /* Initialize the statistics. */
    count_started = count_completed = count_failures = count_timeouts = 0;
    total_bytes = 0;
    min_total = min_connect = min_response = min_data = 1000000000.0;
    max_total = max_connect = max_response = max_data = -1000000000.0;
    sum_total = sum_connect = sum_response = sum_data = 0.0;

    /* Initialize the random number generator. */
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#else
    srandom( (int) time( (time_t*) 0 ) ^ getpid() );
#endif

    /* Initialize the rest. */
#ifdef HAVE_SIGSET
    (void) sigset( SIGTERM, handle_term );
    (void) sigset( SIGINT, handle_term );
    (void) sigset( SIGPIPE, SIG_IGN );
    (void) sigset( SIGALRM, handle_alarm );
#else /* HAVE_SIGSET */
    (void) signal( SIGTERM, handle_term );
    (void) signal( SIGINT, handle_term );
    (void) signal( SIGPIPE, SIG_IGN );
    (void) signal( SIGALRM, handle_alarm );
#endif /* HAVE_SIGSET */

    /* Main loop. */
    terminate = 0;
    for (;;)
	{
	(void) setjmp( jb );
	if ( count == 0 || terminate )
	    break;
	if ( count > 0 )
	    --count;
	++count_started;
	alarm( timeout );
	if ( ! start_connection() )
	    ++count_failures;
	else
	    {
	    if ( ! handle_read() )
		++count_failures;
	    else
		{
		++count_completed;
		elapsed_total =
		    delta_timeval( &started_at, &finished_at ) / 1000.0;
		elapsed_connect =
		    delta_timeval( &started_at, &connect_at ) / 1000.0;
		elapsed_response =
		    delta_timeval( &connect_at, &response_at ) / 1000.0;
		elapsed_data =
		    delta_timeval( &response_at, &finished_at ) / 1000.0;
		if ( ! quiet )
		    (void) printf(
			"%ld bytes from %s: %g ms (%gc/%gr/%gd)\n",
			bytes, url, elapsed_total, elapsed_connect,
			elapsed_response, elapsed_data );
		min_total = min( min_total, elapsed_total );
		min_connect = min( min_connect, elapsed_connect );
		min_response = min( min_response, elapsed_response );
		min_data = min( min_data, elapsed_data );
		max_total = max( max_total, elapsed_total );
		max_connect = max( max_connect, elapsed_connect );
		max_response = max( max_response, elapsed_response );
		max_data = max( max_data, elapsed_data );
		sum_total += elapsed_total;
		sum_connect += elapsed_connect;
		sum_response += elapsed_response;
		sum_data += elapsed_data;
		}
	    }
	alarm( 0 );
	if ( count == 0 || terminate )
	    break;
	if ( interval )
		sleep( interval );
	}

    /* Report statistics. */
    (void) printf( "\n" );
    (void) printf( "--- %s %s %s http_ping statistics ---\n", method, vhost, url );
    (void) printf(
	"%d requests started, %d completed (%d%%), %d failures (%d%%), %d timeouts (%d%%)\n",
	count_started, count_completed, count_completed * 100 / count_started,
	count_failures, count_failures * 100 / count_started,
	count_timeouts, count_timeouts * 100 / count_started );
    if ( count_completed > 0 )
	{
	(void) printf(
	    "total    min/avg/max = %g/%g/%g ms\n",
	    min_total, sum_total / count_completed, max_total );
	(void) printf(
	    "connect  min/avg/max = %g/%g/%g ms\n",
	    min_connect, sum_connect / count_completed, max_connect );
	(void) printf(
	    "response min/avg/max = %g/%g/%g ms\n",
	    min_response, sum_response / count_completed, max_response );
	(void) printf(
	    "data     min/avg/max = %g/%g/%g ms\n",
	    min_data, sum_data / count_completed, max_data );
	}

    /* Done. */
#ifdef USE_SSL
    if ( ssl_ctx != (SSL_CTX*) 0 )
	SSL_CTX_free( ssl_ctx );
#endif
    exit( 0 );
    }


static void
usage( void )
    {
    (void) fprintf( stderr,
    		"usage:  %s [-count n] [-interval n] [-nagle] [-quiet] [-proxy host:port] [-method http_method] [-vhost vhost] url\n", argv0 );
    exit( 1 );
    }

static void
parse_request_file( void )
	{
		/* TODO */
	}

static void
parse_url( void )
    {
    char* http = "http://";
    int http_len = strlen( http );
#ifdef USE_SSL
    char* https = "https://";
    int https_len = strlen( https );
#endif
    int proto_len, host_len;
    char* cp;

    if ( strncmp( http, url, http_len ) == 0 )
	{
	proto_len = http_len;
	url_protocol = PROTO_HTTP;
	}
#ifdef USE_SSL
    else if ( strncmp( https, url, https_len ) == 0 )
	{
	proto_len = https_len;
	url_protocol = PROTO_HTTPS;
	}
#endif
    else
	{
	(void) fprintf( stderr, "%s: unknown protocol - %s\n", argv0, url );
	exit( 1 );
	}
    for ( cp = url + proto_len;
	 *cp != '\0' && *cp != ':' && *cp != '/'; ++cp )
	;
    host_len = cp - url;
    host_len -= proto_len;
    host_len = min( host_len, sizeof(url_host) - 1 );
    strncpy( url_host, url + proto_len, host_len );
    url_host[host_len] = '\0';
    if ( *cp == ':' )
	{
	url_port = (unsigned short) atoi( ++cp );
	while ( *cp != '\0' && *cp != '/' )
	    ++cp;
	}
    else
#ifdef USE_SSL
	if ( url_protocol == PROTO_HTTPS )
	    url_port = 443;
	else
	    url_port = 80;
#else
	url_port = 80;
#endif
    if ( *cp == '\0' )
	url_filename = "/";
    else
	url_filename = cp;
    }


static void
init_net( void )
    {
    char* host;

    if ( do_proxy )
	{
	host = proxy_host;
	port = proxy_port;
	}
    else
	{
	host = url_host;
	port = url_port;
	}
    lookup_address( host, port );
    }


static int
start_connection( void )
    {
    char buf[600];
    int b, r;

    (void) gettimeofday( &started_at, (struct timezone*) 0 );
    got_response = 0;
    content_length = -1;
    bytes = 0;

    conn_fd = open_client_socket();
    if ( conn_fd < 0 )
	return 0;

#ifdef USE_SSL
    if ( url_protocol == PROTO_HTTPS )
	{
	/* Complete the SSL connection. */
	if ( ssl_ctx == (SSL_CTX*) 0 )
	    {
	    SSL_load_error_strings();
	    SSLeay_add_ssl_algorithms();
	    ssl_ctx = SSL_CTX_new( SSLv23_client_method() );
	    }
	if ( ! RAND_status() )
	    {
	    unsigned char rb[1024];
	    int i;
	    for ( i = 0; i < sizeof(rb); ++i )
		rb[i] = random() % 0xff;
	    RAND_seed( rb, sizeof(rb) );
	    }
	ssl = SSL_new( ssl_ctx );
	SSL_set_fd( ssl, conn_fd );
	r = SSL_connect( ssl );
	if ( r <= 0 )
	    {
	    (void) fprintf(
		stderr, "%s: SSL connection failed - %d\n", argv0, r );
	    ERR_print_errors_fp( stderr );
	    close_connection();
	    return 0;
	    }
	}
#endif
    (void) gettimeofday( &connect_at, (struct timezone*) 0 );

    /* Format the request. */
    if ( do_proxy )
	{
#ifdef USE_SSL
	b = snprintf(
	    buf, sizeof(buf), "GET %s://%.500s:%d%.500s HTTP/1.0\r\n",
	    url_protocol == PROTO_HTTPS ? "https" : "http", url_host,
	    (int) url_port, url_filename );
#else
	b = snprintf(
	    buf, sizeof(buf), "GET http://%.500s:%d%.500s HTTP/1.0\r\n",
	    url_host, (int) url_port, url_filename );
#endif
	}
    else
	b = snprintf(
	    buf, sizeof(buf), "%s %.500s HTTP/1.1\r\n", method ? method : "GET", url_filename );
    b += snprintf( &buf[b], sizeof(buf) - b, "Host: %s\r\n", vhost ? vhost : url_host );
    b += snprintf( &buf[b], sizeof(buf) - b, "User-Agent: http_ping\r\n" );
    b += snprintf( &buf[b], sizeof(buf) - b, "Connection: Close\r\n\r\n" );

    /* Send the request. */
#ifdef USE_SSL
    if ( url_protocol == PROTO_HTTPS )
	r = SSL_write( ssl, buf, b );
    else
	r = write( conn_fd, buf, b );
#else
    r = write( conn_fd, buf, b );
#endif
    if ( r < 0 )
	{
	perror( "write" );
	close_connection();
	return 0;
	}
    conn_state = ST_BOL;
    return 1;
    }


#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

#ifdef USE_IPV6
static struct sockaddr_in6 sa;
#else /* USE_IPV6 */
static struct sockaddr_in sa;
#endif /* USE_IPV6 */
static int sa_len, sock_family, sock_type, sock_protocol;


static void
lookup_address( char* hostname, unsigned short port )
    {
#ifdef USE_IPV6
    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
#else /* USE_IPV6 */
    struct hostent *he;
#endif /* USE_IPV6 */

    (void) memset( (void*) &sa, 0, sizeof(sa) );

#ifdef USE_IPV6

    (void) memset( &hints, 0, sizeof(hints) );
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( portstr, sizeof(portstr), "%d", (int) port );
    if ( (gaierr = getaddrinfo( hostname, portstr, &hints, &ai )) != 0 )
	{
	(void) fprintf(
	    stderr, "%s: getaddrinfo %s - %s\n", argv0, hostname,
	    gai_strerror( gaierr ) );
	exit( 1 );
	}

    /* Find the first IPv4 and IPv6 entries. */
    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
	{
	switch ( ai2->ai_family )
	    {
	    case AF_INET: 
	    if ( aiv4 == (struct addrinfo*) 0 )
		aiv4 = ai2;
	    break;
	    case AF_INET6:
	    if ( aiv6 == (struct addrinfo*) 0 )
		aiv6 = ai2;
	    break;
	    }
	}

    /* If there's an IPv4 address, use that, otherwise try IPv6. */
    if ( aiv4 != (struct addrinfo*) 0 )
	{
	if ( sizeof(sa) < aiv4->ai_addrlen )
	    {
	    (void) fprintf(
		stderr, "%s - sockaddr too small (%lu < %lu)\n",
		hostname, (unsigned long) sizeof(sa),
		(unsigned long) aiv4->ai_addrlen );
	    exit( 1 );
	    }
	sock_family = aiv4->ai_family;
	sock_type = aiv4->ai_socktype;
	sock_protocol = aiv4->ai_protocol;
	sa_len = aiv4->ai_addrlen;
	(void) memmove( &sa, aiv4->ai_addr, sa_len );
	freeaddrinfo( ai );
	return;
	}
    if ( aiv6 != (struct addrinfo*) 0 )
	{
	if ( sizeof(sa) < aiv6->ai_addrlen )
	    {
	    (void) fprintf(
		stderr, "%s - sockaddr too small (%lu < %lu)\n",
		hostname, (unsigned long) sizeof(sa),
		(unsigned long) aiv6->ai_addrlen );
	    exit( 1 );
	    }
	sock_family = aiv6->ai_family;
	sock_type = aiv6->ai_socktype;
	sock_protocol = aiv6->ai_protocol;
	sa_len = aiv6->ai_addrlen;
	(void) memmove( &sa, aiv6->ai_addr, sa_len );
	freeaddrinfo( ai );
	return;
	}

    (void) fprintf(
	stderr, "%s: no valid address found for host %s\n", argv0, hostname );
    exit( 1 );

#else /* USE_IPV6 */

    he = gethostbyname( hostname );
    if ( he == (struct hostent*) 0 )
	{
	(void) fprintf( stderr, "%s: unknown host - %s\n", argv0, hostname );
	exit( 1 );
	}
    sock_family = sa.sin_family = he->h_addrtype;
    sock_type = SOCK_STREAM;
    sock_protocol = 0;
    sa_len = sizeof(sa);
    (void) memmove( &sa.sin_addr, he->h_addr, he->h_length );
    sa.sin_port = htons( port );

#endif /* USE_IPV6 */

    }


static int
open_client_socket( void )
    {
    int sockfd;
    int flag = 1;

    sockfd = socket( sock_family, sock_type, sock_protocol );
    if ( sockfd < 0 )
	{
	perror( "socket" );
	return -1;
	}

    if (!nagle)
    	{
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof flag) <0)
			{
			perror( "TCP_NODELAY" );
			return -1;
			}
    	}

    if ( connect( sockfd, (struct sockaddr*) &sa, sa_len ) < 0 )
	{
	perror( "connect" );
	(void) close( sockfd );
	return -1;
	}

    return sockfd;
    }


static int
handle_read( void )
    {
    char buf[5000];
    int bytes_to_read, bytes_read, bytes_handled;

    for (;;)
	{
	bytes_to_read = sizeof(buf);
#ifdef USE_SSL
	if ( url_protocol == PROTO_HTTPS )
	    bytes_read = SSL_read( ssl, buf, bytes_to_read );
	else
	    bytes_read = read( conn_fd, buf, bytes_to_read );
#else
	bytes_read = read( conn_fd, buf, bytes_to_read );
#endif
	if ( bytes_read < 0 )
	    {
	    perror( "read" );
	    close_connection();
	    return 0;
	    }
	if ( ! got_response )
	    {
	    got_response = 1;
	    (void) gettimeofday( &response_at, (struct timezone*) 0 );
	    }
	if ( bytes_read == 0 )
	    {
	    close_connection();
	    (void) gettimeofday( &finished_at, (struct timezone*) 0 );
	    return 1;
	    }

	for ( bytes_handled = 0; bytes_handled < bytes_read; ++bytes_handled )
	    {
	    switch ( conn_state )
		{
		case ST_BOL:
		switch ( buf[bytes_handled] )
		    {
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    case 'C': case 'c':
		    conn_state = ST_C;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_TEXT:
		switch ( buf[bytes_handled] )
		    {
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    break;
		    }
		break;

		case ST_LF:
		switch ( buf[bytes_handled] )
		    {
		    case '\n':
		    conn_state = ST_DATA;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    case 'C': case 'c':
		    conn_state = ST_C;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CR:
		switch ( buf[bytes_handled] )
		    {
		    case '\n':
		    conn_state = ST_CRLF;
		    break;
		    case '\r':
		    conn_state = ST_DATA;
		    break;
		    case 'C': case 'c':
		    conn_state = ST_C;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CRLF:
		switch ( buf[bytes_handled] )
		    {
		    case '\n':
		    conn_state = ST_DATA;
		    break;
		    case '\r':
		    conn_state = ST_CRLFCR;
		    break;
		    case 'C': case 'c':
		    conn_state = ST_C;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CRLFCR:
		switch ( buf[bytes_handled] )
		    {
		    case '\n': case '\r':
		    conn_state = ST_DATA;
		    break;
		    case 'C': case 'c':
		    conn_state = ST_C;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_C:
		switch ( buf[bytes_handled] )
		    {
		    case 'O': case 'o':
		    conn_state = ST_CO;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CO:
		switch ( buf[bytes_handled] )
		    {
		    case 'N': case 'n':
		    conn_state = ST_CON;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CON:
		switch ( buf[bytes_handled] )
		    {
		    case 'T': case 't':
		    conn_state = ST_CONT;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONT:
		switch ( buf[bytes_handled] )
		    {
		    case 'E': case 'e':
		    conn_state = ST_CONTE;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTE:
		switch ( buf[bytes_handled] )
		    {
		    case 'N': case 'n':
		    conn_state = ST_CONTEN;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTEN:
		switch ( buf[bytes_handled] )
		    {
		    case 'T': case 't':
		    conn_state = ST_CONTENT;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT:
		switch ( buf[bytes_handled] )
		    {
		    case '-':
		    conn_state = ST_CONTENT_;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_:
		switch ( buf[bytes_handled] )
		    {
		    case 'L': case 'l':
		    conn_state = ST_CONTENT_L;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_L:
		switch ( buf[bytes_handled] )
		    {
		    case 'E': case 'e':
		    conn_state = ST_CONTENT_LE;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LE:
		switch ( buf[bytes_handled] )
		    {
		    case 'N': case 'n':
		    conn_state = ST_CONTENT_LEN;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LEN:
		switch ( buf[bytes_handled] )
		    {
		    case 'G': case 'g':
		    conn_state = ST_CONTENT_LENG;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENG:
		switch ( buf[bytes_handled] )
		    {
		    case 'T': case 't':
		    conn_state = ST_CONTENT_LENGT;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENGT:
		switch ( buf[bytes_handled] )
		    {
		    case 'H': case 'h':
		    conn_state = ST_CONTENT_LENGTH;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENGTH:
		switch ( buf[bytes_handled] )
		    {
		    case ':':
		    conn_state = ST_CONTENT_LENGTH_COLON;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENGTH_COLON:
		switch ( buf[bytes_handled] )
		    {
		    case ' ': case '\t':
		    conn_state = ST_CONTENT_LENGTH_COLON_WHITESPACE;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENGTH_COLON_WHITESPACE:
		switch ( buf[bytes_handled] )
		    {
		    case ' ': case '\t':
		    break;
		    case '0': case '1': case '2': case '3': case '4':
		    case '5': case '6': case '7': case '8': case '9':
		    content_length = buf[bytes_handled] - '0';
		    conn_state = ST_CONTENT_LENGTH_COLON_WHITESPACE_NUM;
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_CONTENT_LENGTH_COLON_WHITESPACE_NUM:
		switch ( buf[bytes_handled] )
		    {
		    case '0': case '1': case '2': case '3': case '4':
		    case '5': case '6': case '7': case '8': case '9':
		    content_length =
			content_length * 10 + buf[bytes_handled] - '0';
		    break;
		    case '\n':
		    conn_state = ST_LF;
		    break;
		    case '\r':
		    conn_state = ST_CR;
		    break;
		    default:
		    conn_state = ST_TEXT;
		    break;
		    }
		break;

		case ST_DATA:
		bytes += bytes_read - bytes_handled;
		total_bytes += bytes_read - bytes_handled;
		bytes_handled = bytes_read;
		if ( content_length != -1 && bytes >= content_length )
		    {
		    close_connection();
		    (void) gettimeofday( &finished_at, (struct timezone*) 0 );
		    return 1;
		    }
		break;
		}
	    }
	}
    return 1;
    }


static void
handle_term( int sig )
    {
    terminate = 1;
    }


static void
handle_alarm( int sig )
    {
    close_connection();
    (void) fprintf( stderr, "%s: timed out\n", url );
    ++count_timeouts;
    longjmp( jb, 0 );
    }


static void
close_connection( void )
    {
#ifdef USE_SSL
    if ( url_protocol == PROTO_HTTPS )
	SSL_free( ssl );
#endif
    (void) close( conn_fd );
    }


static long long
delta_timeval( struct timeval* start, struct timeval* finish )
    {
    long long delta_secs = finish->tv_sec - start->tv_sec;
    long long delta_usecs = finish->tv_usec - start->tv_usec;
    return delta_secs * (long long) 1000000L + delta_usecs;
    }
