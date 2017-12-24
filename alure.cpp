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

#ifndef ALURE_MAX_BLACKLISTED
#define ALURE_MAX_BLACKLISTED 10
#endif
#define IDLEN 20

struct node {
	unsigned char id[IDLEN];
	struct sockaddr ss;
	int sslen;
	time_t pinged_time;
	int pinged;
};

typedef struct _alure {
	int dht_socket;

	unsigned char myid[IDLEN];
	unsigned char v[4];

	struct sockaddr blacklist[ALURE_MAX_BLACKLISTED];
	int next_blacklisted;

	struct timeval now;
	FILE *dht_debug;

	struct sockaddr sin;

	std::map<std::vector<unsigned char>, node> routetable;

	std::map<std::vector<unsigned char>, time_t> gossip;
	time_t gossip_expire_time;

	time_t ping_neighbourhood_time;

	std::map<std::string, std::set<void*>> filter;
}*palure, alure;


int alure_init(ALURE* A, int s, const unsigned char *id,
	const unsigned char *v, FILE* df,
struct sockaddr &sin, alure_callback* cb)
{
	return 0;
}

void alure_uninit(ALURE A)
{
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

int alure_periodic(ALURE A, const void *buf, size_t buflen,
	const struct sockaddr *from, int fromlen,
	time_t *tosleep)
{
	return 0;
}
