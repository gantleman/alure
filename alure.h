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
#define ALURE void*
///revice msg
typedef void
alure_callback(ALURE A, const char* topic,
void *closure,
const char* msg, size_t msglen);

int alure_init(ALURE* A, int s, const unsigned char *id,
const unsigned char *v, FILE* df,
struct sockaddr &sin, alure_callback* cb);
void alure_uninit(ALURE A);

void alure_ping_node(ALURE A, const struct sockaddr *sa, int salen);
void alure_broadcast(ALURE A, const char* topic, const char* msg, int msglen);

///if topic is '*' recive all message
///map<string topic, set<void* closuer>>
void alure_filter_add(ALURE A, const char* topic, void *closure);
void alure_filter_del(ALURE A, const char* topic, void *closure);
void alure_filter_list(ALURE A, std::list<std::string>&topic);
void alure_filter_list(ALURE A, const char* topic, std::list<void*> &closure);

int alure_periodic(ALURE A, const void *buf, size_t buflen,
	const struct sockaddr *from, int fromlen,
	time_t *tosleep);

void alure_random_bytes(void *buf, size_t size);

void alure_hash(void *hash_return, int hash_size,
void *v1, int len1,
void *v2, int len2,
void *v3, int len3);

int alure_send(int s, const void *buf, size_t len, int flags,
const struct sockaddr *sa, int salen);