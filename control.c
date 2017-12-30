/* This example code was written by Juliusz Chroboczek.
   You are free to cut'n'paste from it to your heart's content. */

/* For crypt */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "cJSON.h"
#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/signal.h>
#define MY_FILE int
#else
#include <ws2tcpip.h>
#include <time.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
#include "getopt.h"
#endif

static char pbuf[4096];
int
main(int argc, char **argv)
{
    int s = -1, s6 = -1, port = 0;
    int opt;
    int ipv6 = 0;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

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
        opt = getopt(argc, argv, "46b:p:");
        if(opt < 0)
            break;

        switch(opt) {
        case '6': ipv6 = 1; break;
        case 'b': {
            char buf[16];
            int rc;
            rc = inet_pton(AF_INET, optarg, buf);
            if(rc == 1) {
                memcpy(&sin.sin_addr, buf, 4);
                break;
            }
            rc = inet_pton(AF_INET6, optarg, buf);
            if(rc == 1) {
                memcpy(&sin6.sin6_addr, buf, 16);
                break;
            }
        }
		break;
		case 'p':{
			port = atoi(optarg);
		}
		break;
        default:
            goto usage;
        }
    }
	if (!ipv6) {
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv4)");
        }
    }else if(ipv6) {
        s = socket(PF_INET6, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv6)");
        }
    }

    if(s < 0) {
        fprintf(stderr, "Eek!");
        exit(1);
    }


	if (!ipv6) {
        sin.sin_port = htons(port);
	} else if (ipv6) {
        int rc;
        int val = 1;

        rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                        (char *)&val, sizeof(val));
        if(rc < 0) {
            perror("setsockopt(IPV6_V6ONLY)");
            exit(1);
        }
        sin6.sin6_port = htons(port);
    }

	int tid = 0;
	while (1) {
		char in[4096] = { 0 };
		gets(in);
		int len = 0;
		char *out;
		if (in[0] == 'm') {
			char c[2] = {0};
			char topic[512] = {0};
			char msg[512] = {0};
			char stid[256] = {0};
			sscanf(in, "%1s %[^ ] %[^ ]", c, topic, msg);

			cJSON *root_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "cmd", cJSON_CreateString(c));
			sprintf(stid, "%s%d", c, tid++);
			cJSON_AddItemToObject(root_json, "tid", cJSON_CreateString(stid));
			cJSON *data_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "data", data_json);
			cJSON_AddItemToObject(data_json, "topic", cJSON_CreateString(topic));
			cJSON_AddItemToObject(data_json, "msg", cJSON_CreateString(msg));
			out = cJSON_Print(root_json);
		}else if (in[0] == 'r') {
			char c[2] = { 0 };
			char topic[512] = { 0 };
			char msg[512] = { 0 };
			char stid[256] = { 0 };
			sscanf(in, "%1s %[^ ]", c, topic);

			cJSON *root_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "cmd", cJSON_CreateString(c));
			sprintf(stid, "%s%d", c, tid++);
			cJSON_AddItemToObject(root_json, "tid", cJSON_CreateString(stid));
			cJSON *data_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "data", data_json);
			cJSON_AddItemToObject(data_json, "topic", cJSON_CreateString(topic));
			out = cJSON_Print(root_json);
			len = strlen(out);
		} else if (in[0] == 'd') {
			char c[2] = { 0 };
			int id;
			char topic[512] = { 0 };
			char msg[512] = { 0 };
			char stid[256] = { 0 };
			sscanf(in, "%1s %[^ ] %d", c, topic, &id);

			cJSON *root_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "cmd", cJSON_CreateString(c));
			sprintf(stid, "%s%d", c, tid++);
			cJSON_AddItemToObject(root_json, "tid", cJSON_CreateString(stid));
			cJSON *data_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "data", data_json);
			cJSON_AddItemToObject(data_json, "topic", cJSON_CreateString(topic));
			cJSON_AddItemToObject(data_json, "id", cJSON_CreateNumber(id));
			out = cJSON_Print(root_json);
			len = strlen(out);
		} else if (in[0] == 'l') {
			char stid[256] = { 0 };
			cJSON *root_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "cmd", cJSON_CreateString("l"));
			sprintf(stid, "l%d", tid++);
			cJSON_AddItemToObject(root_json, "tid", cJSON_CreateString(stid));
			out = cJSON_Print(root_json);
			len = strlen(out);
		} else if (in[0] == 'p') {
			char stid[256] = { 0 };
			cJSON *root_json = cJSON_CreateObject();
			cJSON_AddItemToObject(root_json, "cmd", cJSON_CreateString("p"));
			sprintf(stid, "l%d", tid++);
			cJSON_AddItemToObject(root_json, "tid", cJSON_CreateString(stid));
			out = cJSON_Print(root_json);
			len = strlen(out);
		} else
			continue;

		if (!ipv6)
		{
			len = strlen(out);
			sendto(s, out, len + 1, 0, (struct sockaddr*)&sin, sizeof(sin));
			free(out);
		} else if (ipv6)
		{
			len = strlen(out);
			sendto(s, out, len + 1, 0, (struct sockaddr*)&sin6, sizeof(sin6));
			free(out);
		}
		
	}
    
 usage:
    printf("Usage: client [-6] [-b address] [-p port]\n");
    exit(1);
}


