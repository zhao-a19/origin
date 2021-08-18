/*******************************************************************************************
*文件: pdtparser.cpp
*描述: PDT 解析
*作者: 王君雷
*日期: 2018-08-06
*修改:
*
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int string_len(const char *dptr, const char *limit)
{
    int len = 0;

    while ((dptr < limit) && isalpha(*dptr)) {
        dptr++;
        len++;
    }
    return len;
}

void test_string_len()
{
    char ch[128] = "Zabcd1234";
    int ret = string_len(ch, ch + strlen(ch));
    printf("[%s]%d\n", ch, ret);
}

int parse_addr(const char *cp, const char **endp, struct in_addr *addr, const char *limit)
{
    int ret = 0;
    const char *start = cp;
    char ipstr[16] = {0};
    while (isdigit(*start) || ((*start) == '.')) {
        start++;
    }
    if (start - cp >= 16) {
        return 0;
    }
    memcpy(ipstr, cp, start - cp);
    memset(addr, 0, sizeof(*addr));
    ret = inet_aton(ipstr, addr);
    if (ret == 0) {
        return 0;
    }
    if (endp) {
        *endp = start;
    }
    return 1;
}

void test_parse_addr()
{
    char ch[128] = "192.168.1.254:5060";
    struct in_addr addr;
    const char *tmpptr = NULL;
    int ret = parse_addr(ch, &tmpptr, &addr, ch + strlen(ch));
    printf("[%s]%d,%d\n", ch, ret, (int)(tmpptr - ch));
}

int epaddr_len(const char *dptr, const char *limit)
{
    struct in_addr addr;
    const char *aux = dptr;

    if (parse_addr(dptr, &dptr, &addr, limit) == 0) {
        return 0;
    }
    return dptr - aux;
}

void test_epaddr_len()
{
    char ch[128] = "192.168.1.254:5060";
    int ret = epaddr_len(ch, ch + strlen(ch));
    printf("[%s]%d\n", ch, ret);
}

static const char *sip_search(const char *dptr, const char *limit,
                              const char *needle, unsigned int len)
{
    if ((dptr != NULL) && (limit != NULL) && (needle != NULL) && (len > 0)) {
        for (limit -= len; dptr < limit; dptr++) {
            if (strncmp(dptr, needle, len) == 0) {
                return dptr;
            }
        }
    }
    return NULL;
}

/**
 * [ipaddr_len 获取IP地址字符串出现的位置 和 长度]
 * @param  dptr  [字符串]
 * @param  limit [字符串结尾]
 * @param  seach [待查找的串]
 * @param  slen  [待查找的串长度]
 * @param  shift [用于返回出现IP的位置相对偏移量]
 * @return       [成功返回IP字符串长度，失败返回0]
 */
int ipaddr_len(const char *dptr, const char *limit, const char *seach, int slen, int *shift)
{
    const char *ptr = sip_search(dptr, limit, seach, slen);
    if (ptr == NULL) {
        return 0;
    }

    int len = epaddr_len(ptr + slen, limit);
    if (len <= 0) {
        return 0;
    }

    if (shift != NULL) {
        *shift = ptr + slen - dptr;
    }
    return len;
}

void test_ipaddr_len()
{
    char ch[128] = "U s:aa;m=192.168.2.100\r\n";
    int shift = 0;
    int ret = ipaddr_len(ch, ch + strlen(ch), "m=", 2, &shift);
    printf("[%s]ret=[%d] shift=[%d]\n", ch, ret, shift);
}

/**
 * [callid_len 获取callid出现的位置 及 长度]
 * @param  dptr  [字符串]
 * @param  limit [字符串结尾]
 * @param  seach [待查找的串]
 * @param  slen  [待查找的串长度]
 * @param  shift [用于返回出现callid的位置相对偏移量]
 * @return       [成功返回callid字符串长度，失败返回0]
 */
int callid_len(const char *dptr, const char *limit, const char *seach, int slen, int *shift)
{
    int len = 0;
    if ((seach != NULL) && (slen > 0)) {
        if (strncmp(dptr, seach, slen) == 0) {
            if (shift != NULL) {
                *shift = slen;
            }
            dptr += slen;
            while ((dptr < limit) && ((*dptr) != '\r') && ((*dptr) != '\n')) {
                dptr++;
                len++;
            }
        }
    }
    return len;
}

void test_callid_len()
{
    char ch[128] = "i:abcd7788\r\n";
    int shift = 0;
    int ret = callid_len(ch, ch + strlen(ch), "i:", 2, &shift);
    printf("[%s]ret=[%d] shift=[%d]\n", ch, ret, shift);
}

/**
 * [digits_len 获取数字出现的位置 及 长度]
 * @param  dptr  [字符串]
 * @param  limit [字符串结尾]
 * @param  seach [待查找的串]
 * @param  slen  [待查找的串长度]
 * @param  shift [用于返回出现数字的位置相对偏移量]
 * @return       [成功返回数字字符串长度，失败返回0]
 */
int digits_len(const char *dptr, const char *limit, const char *seach, int slen, int *shift)
{
    int len = 0;
    if ((seach != NULL) && (slen > 0)) {
        if (strncmp(dptr, seach, slen) == 0) {
            if (shift != NULL) {
                *shift = slen;
            }
            dptr += slen;
            while ((dptr < limit) && isdigit(*dptr)) {
                dptr++;
                len++;
            }
        }
    }
    return len;
}

void test_digits_len()
{
    char ch[128] = "Content-Length:7788\r\n";
    char digitbuf[16] = {0};
    int shift = 0;
    int ret = digits_len(ch, ch + strlen(ch), "Content-Length:", 15, &shift);
    memcpy(digitbuf, ch + shift, ret);
    printf("[%s]ret=[%d] shift=[%d] digitbuf=[%s]\n", ch, ret, shift, digitbuf);
}
