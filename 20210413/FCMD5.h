/*******************************************************************************************
*文件:  FCMD5.h
*描述:  md5计算接口
*作者:  王君雷
*日期:  2016-03
*修改:
*     添加对一块内存空间计算md5的功能;计算文件md5时打开方式由r改为rb  ------> 2018-09-19
*******************************************************************************************/
#ifndef __FC_MD5_H__
#define __FC_MD5_H__

typedef unsigned int uint32;

struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32 buf[4], uint32 const in[16]);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#define FOPRTXT "r"
#define FOPRBIN "rb"

int md5sum(const char *file, unsigned char *digest);
int md5sum_str(const char *file, char *digest);
bool md5sum_buff(const char *ch, int chlen, unsigned char *chout16, unsigned char *chout32);

#endif
