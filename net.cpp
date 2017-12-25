/*
Copyright (c) 2009-2011 by Juliusz Chroboczek
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <string>
#include "md5.h"
#include "sha1.h"
#include <list>

#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/signal.h>
#include <getopt.h>

#else
#include <ws2tcpip.h>
#include <time.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
#include "getopt.h"
#define sleep(d) Sleep(d*1000)
#define  random rand
#endif

#include "alure.h"

#define CCMD "[control]"
#define SCCMD  sizeof(CCMD) - 1

#if !defined(_WIN32) || defined(__MINGW32__)
#define dht_gettimeofday(_ts, _tz) gettimeofday((_ts), (_tz))
#else

struct timezone
{
	int  tz_minuteswest; // minutes W of Greenwich  
	int  tz_dsttime;     // type of dst correction
};

int dht_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	static int tzflag = 0;

	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tv->tv_sec = (long)clock;
	tv->tv_usec = wtm.wMilliseconds * 1000;

	if (tz){
		if (!tzflag){
#if !TSK_UNDER_WINDOWS_RT
			_tzset();
#endif
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return (0);
}
#endif


#ifdef _WIN32
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


#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

static
void print_hex(FILE *f, const unsigned char *buf, int buflen)
{
	int i;
	for (i = 0; i < buflen; i++)
		fprintf(f, "%02x", buf[i]);
}

/* The call-back function is called by the DHT whenever something
   interesting happens.  Right now, it only happens when we get a new value or
   when a search completes, but this may be extended in future versions. */
static void
msg_callback(ALURE A, const char* topic,
void *closure,
const char* msg, size_t msglen)
{
	std::string value;
	value.append((char*)msg, msglen);
	printf("%s Received %s, %d\n", topic, value.c_str(), msglen);
       
}

static const unsigned char zeroes[20] = { 0 };
static const unsigned char ones[20] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF
};
static const unsigned char v4prefix[16] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

int is_martian(const struct sockaddr *sa)
{
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

static char buf[4096];

int main(int argc, char **argv)
{
	FILE* fd;
    int i, rc;
    int s = -1, port;
    int have_id = 0;
    unsigned char myid[20];
    time_t tosleep = 0;
	char id_file[256] = { "alure.id" };
	char ip_file[256] = { "alure.ip" };
    int opt;
    int quiet = 0, ipv6 = 0, safe = 1;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage from;
    socklen_t fromlen, melen;
	struct sockaddr me;
	FILE* dht_debug = NULL;

#ifdef _WIN32

	// Load Winsock
	int retval;
	WSADATA wsaData;
	if ((retval = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		WSACleanup();
		return 0;
	}
#endif // _WIN32

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;

    while(1) {
        opt = getopt(argc, argv, "sq46b:i:o:p:");
        if(opt < 0)
			break;

        switch(opt) {
        case 'q': quiet = 1; break;
        case '6': ipv6 = 1; break;
		case 's': safe = 0; break;
        case 'b': {
            char buf[16];
            int rc;
            rc = inet_pton(AF_INET, optarg, buf);
			if (!ipv6 && rc == 1) {
				me.sa_family = AF_INET;
                memcpy(&sin.sin_addr, buf, 4);
				memcpy(&me.sa_data, buf, 4);
                break;
            }
            rc = inet_pton(AF_INET6, optarg, buf);
			if (ipv6 && rc == 1) {
				me.sa_family = AF_INET6;
                memcpy(&sin6.sin6_addr, buf, 16);
				memcpy(&me.sa_data, buf, 16);
                break;
            }
            goto usage;
        }
		break;
		case 'i':
			strcpy(id_file, optarg);
            break;
		case 'o':
			strcpy(ip_file, optarg);
			break;
		case 'p':{
			port = atoi(optarg);
		}
		break;
        default:
            goto usage;
        }
    }

    /* Ids need to be distributed evenly, so you cannot just use your
       bittorrent id.  Either generate it randomly, or take the SHA-1 of
       something. */
	fd = fopen(id_file, "r");
	if (fd > 0) {
		rc = fread(myid, 1, 20, fd);
		if (rc == 20)
			have_id = 1;
		fclose(fd);
	}

	if (!have_id) {
		FILE * ofd;

		alure_random_bytes(myid, 20);

		ofd = fopen(id_file, "wb+");
		if (ofd > 0) {
			rc = fwrite(myid, 1, 20, ofd);
			fclose(ofd);
		}
	}

	srand((unsigned)time(NULL));

	fd = fopen(ip_file, "r");
	if (fd > 0) {
		while (1) {
			char fline[128] = { 0 };
			char sip[20] = { 0 };
			char sport[10] = { 0 };
			char* rt = fgets(fline, 128, fd);
			if (rt == 0)
				break;

			sscanf(fline, "%[^:]:%[^:\n]", sip, sport);
			struct addrinfo hints, *info, *infop;
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;

			if (!ipv6)
				hints.ai_family = AF_INET;
			else
				hints.ai_family = AF_INET6;

			rc = getaddrinfo(sip, sport, &hints, &info);
			if (rc != 0) {
				fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
				break;
			}
			infop = info;
			while (infop) {
				memcpy(&bootstrap_nodes[num_bootstrap_nodes],
					infop->ai_addr, infop->ai_addrlen);
				infop = infop->ai_next;
				num_bootstrap_nodes++;
			}
			freeaddrinfo(info);
		}
		fclose(fd);
	}
	else
	{
		perror("can not open ddkv.ip file!");
		exit(0);
	}

	if (0 == num_bootstrap_nodes)
	{
		perror("number bootstrap node is empty!");
		exit(0);
	}

    /* If you set dht_debug to a stream, every action taken by the DHT will
       be logged. */
    if(!quiet)
        dht_debug = stdout;

    /* We need an IPv4 and an IPv6 socket, bound to a stable port.  Rumour
       has it that uTorrent works better when it is the same as your
       Bittorrent port. */

	if (!ipv6) {
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv4)");
        }
    }else {
        s = socket(PF_INET6, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv6)");
        }
    }

    if(s < 0) {
        fprintf(stderr, "Eek!");
        exit(1);
    }


    if(s >= 0 && ipv6 == 0) {
        sin.sin_port = htons(port);
        rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
        if(rc < 0) {
            perror("bind(IPv4)");
            exit(1);
        }
	} else if (s >= 0 && ipv6 != 0) {
        int rc;
        int val = 1;

        rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                        (char *)&val, sizeof(val));
        if(rc < 0) {
            perror("setsockopt(IPV6_V6ONLY)");
            exit(1);
        }

        /* BEP-32 mandates that we should bind this socket to one of our
           global IPv6 addresses.  In this simple example, this only
           happens if the user used the -b flag. */

        sin6.sin6_port = htons(port);
        rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0) {
            perror("bind(IPv6)");
            exit(1);
        }
    }

	if (s >= 0) {
		rc = set_nonblocking(s, 1);
		if (rc < 0)
			return 0;
	}

	ALURE D;
    /* Init the dht.  This sets the socket into non-blocking mode. */
	rc = alure_init(&D, s, myid, (unsigned char*)"JC\0\0", dht_debug, me, msg_callback);
    if(rc < 0) {
        perror("dht_init");
        exit(1);
    }

    /* For bootstrapping, we need an initial list of nodes.  This could be
       hard-wired, but can also be obtained from the nodes key of a torrent
       file, or from the PORT bittorrent message.

       Dht_ping_node is the brutal way of bootstrapping -- it actually
       sends a message to the peer.  If you're going to bootstrap from
       a massive number of nodes (for example because you're restoring from
       a dump) and you already know their ids, it's better to use
       dht_insert_node.  If the ids are incorrect, the DHT will recover. */
    for(i = 0; i < num_bootstrap_nodes; i++) {
		alure_ping_node(D, (struct sockaddr*)&bootstrap_nodes[i],
                      sizeof(bootstrap_nodes[i]));
        sleep(random() % 3);
    }

    while(1) {
        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = (long)tosleep;
        tv.tv_usec = random() % 1000000;

        FD_ZERO(&readfds);
        if(s >= 0)
            FD_SET(s, &readfds);
 
        rc = select(s + 1 , &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select");
                sleep(1);
            }
        }

        if(rc > 0) {
            fromlen = sizeof(from);
            if(s >= 0 && FD_ISSET(s, &readfds))
                rc = recvfrom(s, buf, sizeof(buf) - 1, 0,
                              (struct sockaddr*)&from, &fromlen);
			else 
				abort();
        }

        if(rc > 0) {
			if (strncmp(buf, CCMD, SCCMD) != 0)
			{
				buf[rc] = '\0';
				rc = alure_periodic(D, buf, rc, (struct sockaddr*)&from, fromlen,
					&tosleep);
			}
			else
			{
				///must from local
				if (safe && 1 != is_martian((struct sockaddr*)&from))
					continue;

				/* This is how you trigger a search for a torrent hash.  If port
				(the second argument) is non-zero, it also performs an announce.
				Since peers expire announced data after 30 minutes, it's a good
				idea to reannounce every 28 minutes or so. */
				char* pcmd = buf + SCCMD;
				if (pcmd[0] == 's') {
					char hs[256] = { 0 };
					char sv[256] = { 0 };
					sscanf(&pcmd[2], "%s %s", &hs, &sv);

					SHA1_CONTEXT sc;
					sha1_init(&sc);
					sha1_write(&sc, (unsigned char*)hs, strlen(hs));
					sha1_final(&sc);

					printf("search key:%s value:%s hash:", hs, sv);
					print_hex(stdout, (unsigned char*)buf, 20);
					printf("\n");

					int len = strlen(sv);

				}
			}
        } else {
			rc = alure_periodic(D, NULL, 0, NULL, 0, &tosleep);
        }
        if(rc < 0) {
            if(errno == EINTR) {
                continue;
            } else {
                perror("dht_periodic");
                if(rc == EINVAL || rc == EFAULT)
                    abort();
                tosleep = 1;
            }
        }
    }

	alure_uninit(D);
    return 0;
    
 usage:
    printf("Usage: dht-example [-q] [-4] [-6] [-b address] [-p port] [-i filename] [-o filename]");
    exit(1);
}

void
alure_random_bytes(void *buf, size_t size)
{
	srand((unsigned int)time(0));

	char* pbuf = (char*)buf;
	for (size_t i = 0; i < size; i++) {
		pbuf[i] = rand();
	}
}

void
alure_hash(void *hash_return, int hash_size,
void *v1, int len1,
void *v2, int len2,
void *v3, int len3)
{
	static MD5_CTX ctx;
	unsigned char decrypt[16];
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char*)v1, len1);
	MD5Update(&ctx, (unsigned char*)v2, len2);
	MD5Update(&ctx, (unsigned char*)v3, len3);
	MD5Final(&ctx, decrypt);
	if (hash_size > 16)
		memset((char*)hash_return + 16, 0, hash_size - 16);
	memcpy(hash_return, ctx.buffer, hash_size > 16 ? 16 : hash_size);
}

int alure_send(int s, const void *buf, size_t len, int flags,
	const struct sockaddr *sa, int salen)
{
	return sendto(s, (char*)buf, len, flags, sa, salen);
}