/*******************************************************************************************
*文件:  urlcoder.h
*描述:  url编解码
*作者:  王君雷
*日期:  2018-08-20
*参考：https://blog.csdn.net/tennysonsky/article/details/54176877
*修改:
*******************************************************************************************/
#ifndef __URL_CODER_H__
#define __URL_CODER_H__

void urlencode(char url[]);
void urldecode(char url[]);
int u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen);
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen);

#endif
