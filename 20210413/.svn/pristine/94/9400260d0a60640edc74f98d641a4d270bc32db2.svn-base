#ifndef MD5_H
#define MD5_H


/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */

#include <stdio.h>
#include <string.h>

#if 0
#ifdef __alpha
typedef unsigned int uint32;
#else
typedef unsigned long uint32;
#endif
#else
//如上定义与系统冲突 2015-12-22
#include "datatype.h"
#endif

struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    unsigned char in[64];
};

typedef struct MD5Context MD5_CTX;

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32 buf[4], uint32 const in[16]);

int mdfile(FILE *fp, unsigned char *digest);
int md5sum(char *file, unsigned char *digest);

#endif /* !MD5_H */
