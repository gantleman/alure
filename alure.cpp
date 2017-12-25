/*
Copyright (c) 2009-2011 by shuo sun(dds_sun@hotmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <list>
#include <map>
#include <vector>
#include <assert.h>
#include <set>

#if !defined(_WIN32) || defined(__MINGW32__)
#include <sys/time.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#ifndef _WIN32_WINNT
//#define _WIN32_WINNT 0x0501 /* Windows XP */
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#include <ws2tcpip.h>
#include <windows.h>
#endif
#include "bcode.h"
#include "alure.h"

#ifndef HAVE_MEMMEM
#ifdef __GLIBC__
#define HAVE_MEMMEM
#endif
#endif

#if !defined(_WIN32) || defined(__MINGW32__)
#define dht_gettimeofday(_ts, _tz) gettimeofday((_ts), (_tz))
#else
extern int dht_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#ifdef _WIN32

#undef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT

static int
set_nonblocking(int fd, int nonblocking)
{
	int rc;

	unsigned long mode = !!nonblocking;
	rc = ioctlsocket(fd, FIONBIO, &mode);
	if (rc != 0)
		errno = WSAGetLastError();
	return (rc == 0 ? 0 : -1);
}

static int
random(void)
{
	return rand();
}

/* Windows Vista and later already provide the implementation. */
#if _WIN32_WINNT < 0x0600
extern const char *inet_ntop(int, const void *, char *, socklen_t);
#endif

#ifdef _MSC_VER
/* There is no snprintf in MSVCRT. */
#define snprintf _snprintf
#endif

#else

static int
set_nonblocking(int fd, int nonblocking)
{
	int rc;
	rc = fcntl(fd, F_GETFL, 0);
	if (rc < 0)
		return -1;

	rc = fcntl(fd, F_SETFL, nonblocking ? (rc | O_NONBLOCK) : (rc & ~O_NONBLOCK));
	if (rc < 0)
		return -1;

	return 0;
}

#endif

#ifdef HAVE_MEMMEM

static void *
dht_memmem(const void *haystack, size_t haystacklen,
const void *needle, size_t needlelen)
{
	return memmem(haystack, haystacklen, needle, needlelen);
}

#else

static void *
dht_memmem(const void *haystack, size_t haystacklen,
const void *needle, size_t needlelen)
{
	const char *h = (char *)haystack;
	const char *n = (char *)needle;
	size_t i;

	/* size_t is unsigned */
	if (needlelen > haystacklen)
		return NULL;

	for (i = 0; i <= haystacklen - needlelen; i++) {
		if (memcmp(h + i, n, needlelen) == 0)
			return (void*)(h + i);
	}
	return NULL;
}

#endif

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error You lose
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

#define IDLEN 20
static const unsigned char zeroes[IDLEN] = { 0 };
static const unsigned char ones[IDLEN] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF
};
static const unsigned char v4prefix[16] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};


struct node {
	unsigned char id[IDLEN];
	struct sockaddr ss;
	int sslen;
	time_t pinged_time;
	int pinged;
};

typedef struct _alure {
	int alure_socket;

	unsigned char myid[IDLEN];
	unsigned char v[4];

	std::set<std::vector<char>> blacklist;

	struct timeval now;
	FILE *dht_debug;

	struct sockaddr sin;

	std::map<std::vector<unsigned char>, node> routetable;

	std::map<std::vector<unsigned char>, time_t> gossip;
	time_t gossip_expire_time;

	time_t ping_neighbourhood_time;

	std::map<std::string, std::set<void*>> filter;
}*palure, alure;

static void
debugf(palure A, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	if (A->dht_debug)
		vfprintf(A->dht_debug, format, args);
	va_end(args);
	if (A->dht_debug)
		fflush(A->dht_debug);
}

static void
debug_printable(palure A, const unsigned char *buf, int buflen)
{
	int i;
	if (A->dht_debug) {
		for (i = 0; i < buflen; i++)
			putc(buf[i] >= 32 && buf[i] <= 126 ? buf[i] : '.', A->dht_debug);
	}
}

static
void debugf_hex(palure A, const char* head, const unsigned char *buf, int buflen)
{
	if (!A->dht_debug)
		return;
	fprintf(A->dht_debug, head);

	int i;
	for (i = 0; i < buflen; i++)
		fprintf(A->dht_debug, "%02x", buf[i]);

	fprintf(A->dht_debug, "\n");
	fflush(A->dht_debug);
}

static
void print_hex(FILE *f, const unsigned char *buf, int buflen)
{
	int i;
	for (i = 0; i < buflen; i++)
		fprintf(f, "%02x", buf[i]);
}

static int
id_cmp(const unsigned char *restrict id1, const unsigned char *restrict id2)
{
	/* Memcmp is guaranteed to perform an unsigned comparison. */
	return memcmp(id1, id2, IDLEN);
}

static void
node_pinged(palure A, struct node *n)
{
	n->pinged++;
	n->pinged_time = A->now.tv_sec;
}

static int
tid_match(const unsigned char *tid, const char *prefix,
unsigned short *seqno_return)
{
	if (tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
		if (seqno_return)
			memcpy(seqno_return, tid + 2, 2);
		return 1;
	} else
		return 0;
}

int alure_init(ALURE* OutD, int s, const unsigned char *id,
const unsigned char *v, FILE* df,
struct sockaddr &sin, alure_callback* cb)
{
	int rc;
	palure A = new alure;
	*OutD = A;
	A->dht_debug = df;

	A->ping_neighbourhood_time = 0;

	if (s >= 0) {
		rc = set_nonblocking(s, 1);
		if (rc < 0)
			return 0;
	}
	memcpy(A->myid, id, IDLEN);
	memcpy(A->v, v, 4);
	dht_gettimeofday(&A->now, NULL);

	A->alure_socket = s;
	memcpy(&A->sin, &sin, sizeof(sockaddr_in));

	return 1;
}

void alure_uninit(ALURE iA)
{
	palure A = (palure)iA;
	if (A->alure_socket < 0) {
		errno = EINVAL;
		return;
	}

	A->alure_socket = -1;
	delete A;
}

void alure_ping_node(ALURE A, const struct sockaddr *sa, int salen)
{
}

void alure_broadcast(ALURE A, const char* topic, const char* msg, int msglen)
{
}

///if topic is '*' recive all message
///map<string topic, set<void* closuer>>
void alure_filter_add(ALURE A, const char* topic, void *closure)
{
}

void alure_filter_del(ALURE A, const char* topic, void *closure)
{
}

void alure_filter_list(ALURE A, std::list<std::string>&topic)
{

}

void alure_filter_list(ALURE A, const char* topic, std::list<void*> &closure)
{

}

static int
is_martian(palure A, const struct sockaddr *sa)
{
	if (A->dht_debug != NULL)
		return 0;

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		const unsigned char *address = (const unsigned char*)&sin->sin_addr;
		return sin->sin_port == 0 ||
			(address[0] == 0) ||
			(address[0] == 127) ||
			((address[0] & 0xE0) == 0xE0);
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		const unsigned char *address = (const unsigned char*)&sin6->sin6_addr;
		return sin6->sin6_port == 0 ||
			(address[0] == 0xFF) ||
			(address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
			(memcmp(address, zeroes, 15) == 0 &&
			(address[15] == 0 || address[15] == 1)) ||
			(memcmp(address, v4prefix, 12) == 0);
	}

	default:
		return 0;
	}
}

static struct node *
find_node(palure A, const unsigned char *id, int af)
{
	std::map<std::vector<unsigned char>, node> *r = &A->routetable;
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter != r->end()) {
		return &iter->second;
	}

	return NULL;
}

static void
blacklist_node(palure A, const unsigned char *id, const struct sockaddr *sa, int salen)
{
	debugf(A, "Blacklisting broken node.\n");

	if (id) {
		struct node *n;
		/* Make the node easy to discard. */
		n = find_node(A, id, sa->sa_family);
		if (n) {
			n->pinged = 3;
			node_pinged(A, n);
		}
	}
	std::vector<char> buf;
	buf.resize(sizeof(sockaddr));
	memcpy(&buf[0], sa, sizeof(sockaddr));
	A->blacklist.insert(buf);
}

static int
node_blacklisted(palure A, const struct sockaddr *sa, int salen)
{
	if ((unsigned)salen > sizeof(struct sockaddr))
		abort();
	
	std::vector<char> buf;
	buf.resize(sizeof(sockaddr));
	memcpy(&buf[0], sa, sizeof(sockaddr));

	std::set<std::vector<char>>::iterator iter = A->blacklist.find(buf);
	if (iter != A->blacklist.end())
		return 1;
	else
		return 0;
}

static void
node_ponged(palure A, const unsigned char *id, const struct sockaddr *sa, int salen)
{
	if (id_cmp(id, A->myid) == 0)
		return;

	std::map<std::vector<unsigned char>, node> *r = &A->routetable;
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter != r->end()) {
		struct node *n = &iter->second;
		n->pinged = 0;
		n->pinged_time = 0;
	}
}

static struct node *
new_node(palure A, const unsigned char *id, const struct sockaddr *sa, int salen)
{
	if (id_cmp(id, A->myid) == 0)
		return NULL;

	if (is_martian(A, sa) || node_blacklisted(A, sa, salen))
		return NULL;

	std::map<std::vector<unsigned char>, node> *r = &A->routetable;
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter == r->end()) {
		//new node
		struct node* n = &(*r)[k];
		memcpy(n->id, id, IDLEN);
		memcpy(&n->ss, sa, salen);
		n->sslen = salen;
		n->pinged = 0;
		n->pinged_time = A->now.tv_sec;
		return n;
	} else {
		//pinged
		struct node* n = &iter->second;
		n->pinged = 0;
		n->pinged_time = 0;
	}
	return 0;
}

static int
send_wrap(palure A, const void *buf, size_t len, int flags,
const struct sockaddr *sa, int salen)
{
	if (salen == 0) {
		debugf(A, "error send salen is 0!\n");
		abort();
	}
	if (node_blacklisted(A, sa, salen)) {
		debugf(A, "Attempting to send to blacklisted node.\n");
		errno = EPERM;
		return -1;
	}

	return sendto(A->alure_socket, (char *)buf, len, flags, sa, salen);
}

int
send_pong(palure A, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", A->v, sizeof(A->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", A->myid, IDLEN);
	b_package(&out, so);
	return send_wrap(A, so.c_str(), so.size(), 0, sa, salen);
}

static void
process_message(palure A, const unsigned char *buf, int buflen,
const struct sockaddr *from, int fromlen
)
{
	int cur = 0;
	b_element e;
	b_parse((char*)buf, buflen, cur, e);

	unsigned char *tid, *y_return;
	int tid_len, y_len;
	b_find(&e, "t", &tid, tid_len);
	b_find(&e, "y", &y_return, y_len);

	if (y_return[0] == 'r') {
		b_element* r;
		b_find(&e, "r", &r);
		if (r == 0)
			goto dontread;

		unsigned char *id;
		int id_len;
		b_find(r, "id", &id, id_len);
		if (id_len == 0)
			goto dontread;

		if (tid_len != 4) {
			debugf(A, "Broken node truncates transaction ids: ");
			debug_printable(A, (unsigned char *)buf, buflen);
			debugf(A, "\n");
			/* This is really annoying, as it means that we will
			time-out all our searches that go through this node.
			Kill it. */
			blacklist_node(A, id, from, fromlen);
			return;
		}

		node_ponged(A, id, from, fromlen);
		if (tid_match(tid, "pn", NULL)) {
			debugf(A, "Pong!\n");
		} else {
			debugf(A, "Unexpected reply: ");
			debug_printable(A, (unsigned char *)buf, buflen);
			debugf(A, "\n");
		}
	} else if (y_return[0] == 'q') {
		unsigned char *q_return;
		int q_len;
		b_find(&e, "q", &q_return, q_len);
		b_element* a;
		b_find(&e, "a", &a);
		if (a == 0)
			goto dontread;

		unsigned char *id;
		int id_len;
		b_find(a, "id", &id, id_len);
		if (id_len == 0)
			goto dontread;

		node* nf = new_node(A, id, from, fromlen);
		if (memcmp(q_return, "ping", q_len) == 0) {
			debugf(A, "Ping (%d)!\n", tid_len);
			debugf(A, "Sending pong.\n");
			send_pong(A, from, fromlen, tid, tid_len);
		}
	}

dontread:
	debugf(A, "Unparseable message: ");
	debug_printable(A, (unsigned char *)buf, buflen);
	debugf(A, "\n");
}

int alure_periodic(ALURE iA, const void *buf, size_t buflen,
	const struct sockaddr *from, int fromlen,
	time_t *tosleep)
{
	palure A = (palure)iA;
	///Time first is fixed in one second without considering optimization
	*tosleep = 1;
	dht_gettimeofday(&A->now, NULL);

	if (buflen > 0) {
		if (!is_martian(A, from) || !node_blacklisted(A, from, fromlen)) {
			if (((char*)buf)[buflen] != '\0') {
				debugf(A, "Unterminated message.\n");
				errno = EINVAL;
				return -1;
			}
			process_message(A, (unsigned char*)buf, buflen, from, fromlen);
		}
	}
}
