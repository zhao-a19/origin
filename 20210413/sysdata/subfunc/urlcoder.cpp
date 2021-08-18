/*******************************************************************************************
*文件:  urlcoder.cpp
*描述:  url编解码
*作者:  王君雷
*日期:  2018-08-20
*参考：https://blog.csdn.net/tennysonsky/article/details/54176877
*修改:
*******************************************************************************************/
/*
  字符’a’-‘z’,’A’-‘Z’,’0’-‘9’,’.’,’-‘,’*’和’_’ 都不被编码，维持原值；
  空格’ ‘被转换为加号’+’。
  其他每个字节都被表示成”%XY”的格式，X和Y分别代表一个十六进制位。编码为UTF-8。
*/

#include <stdio.h>
#include <string.h>
#include <iconv.h>
#include "urlcoder.h"

#define BURSIZE 2048

int hex2dec(char c)
{
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

char dec2hex(short int c)
{
    if (0 <= c && c <= 9) {
        return c + '0';
    } else if (10 <= c && c <= 15) {
        return c + 'A' - 10;
    } else {
        return -1;
    }
}

void urlencode(char url[])
{
    int i = 0;
    int len = strlen(url);
    int res_len = 0;
    char res[BURSIZE];
    for (i = 0; i < len; ++i) {
        char c = url[i];
        if (('0' <= c && c <= '9')
            || ('a' <= c && c <= 'z')
            || ('A' <= c && c <= 'Z')
            || (c == '/')
            || (c == '.')) {
            res[res_len++] = c;
        } else {
            int j = (short int)c;
            if (j < 0) {
                j += 256;
            }
            int i1, i0;
            i1 = j / 16;
            i0 = j - i1 * 16;
            res[res_len++] = '%';
            res[res_len++] = dec2hex(i1);
            res[res_len++] = dec2hex(i0);
        }
    }
    res[res_len] = '\0';
    strcpy(url, res);
}

void urldecode(char url[])
{
    int i = 0;
    int len = strlen(url);
    int res_len = 0;
    char res[BURSIZE];
    for (i = 0; i < len; ++i) {
        char c = url[i];
        if (c != '%') {
            res[res_len++] = c;
        } else {
            char c1 = url[++i];
            char c0 = url[++i];
            int num = 0;
            num = hex2dec(c1) * 16 + hex2dec(c0);
            res[res_len++] = num;
        }
    }
    res[res_len] = '\0';
    strcpy(url, res);
}

int code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen,
                 char *outbuf, size_t outlen)
{
    iconv_t cd;
    char **pin = &inbuf;
    char **pout = &outbuf;

    cd = iconv_open(to_charset, from_charset);
    if (cd == 0) {
        perror("iconv_open");
        return -1;
    }
    memset(outbuf, 0, outlen);
    if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t) - 1) {
        perror("iconv");
        return -1;
    }
    iconv_close(cd);
    *pout = '\0';
    return 0;
}

/**
 * [u2g utf8转为gbk编码]
 * @param  inbuf  [输入缓冲区]
 * @param  inlen  [输入长度]
 * @param  outbuf [输出缓冲区]
 * @param  outlen [缓冲区长度]
 * @return        [成功返回0 失败返回负值]
 */
int u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    return code_convert("utf-8", "gbk", inbuf, inlen, outbuf, outlen);
}

/**
 * [u2g gbk转为utf8编码]
 * @param  inbuf  [输入缓冲区]
 * @param  inlen  [输入长度]
 * @param  outbuf [输出缓冲区]
 * @param  outlen [缓冲区长度]
 * @return        [成功返回0 失败返回负值]
 */
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    return code_convert("gbk", "utf-8", inbuf, inlen, outbuf, outlen);
}

int testcoder()
{
    int ret = 0;
    char url[100] = "http://'测试/@mike";
    urlencode(url);
    printf("%s\n", url);

    char testbuf1[100] = "/%E9%A3%92%E9%A3%92%E5%A4%A7%E6%89%80%E5%A4%A7%E9%98%BF%E8%BE%BE.txt";
    urldecode(testbuf1);
    printf("%s\n", testbuf1);

    char testbuf2[100] = "/%E5%8D%95%E5%91%BC.pcap";
    char testbuf3[100] = {0};
    urldecode(testbuf2);
    printf("[%s]\n", testbuf2);
    ret = u2g(testbuf2, strlen(testbuf2), testbuf3, sizeof(testbuf3));
    printf("[%d][%s]\n", ret, testbuf3);
    return 0;
}
