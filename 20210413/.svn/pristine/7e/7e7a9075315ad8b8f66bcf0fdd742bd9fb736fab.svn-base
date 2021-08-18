
/*******************************************************************************************
*文件:    stringex.cpp
*描述:    扩展字符串功能
*
*作者:    张冬波
*日期:    2014-12-12
*修改:    创建文件                            ------>     2014-12-12
*         增加sql特殊字符串处理               ------>     2014-12-23
*         增加str2int和strdelspace函数        ------>     2015-01-06
*         增加str2long函数                    ------>     2015-01-14
*         增加printbuf函数                    ------>     2015-01-16
*         修改str2long超出2G限制,str2int的bug
*                                             ------>     2015-01-27
*         增加字符集转换                      ------>     2015-01-30
*         增加strrstr函数                     ------>     2015-05-21
*         增加strstr_nocase函数               ------>     2015-05-28
*         增加mac地址函数                     ------>     2015-11-10
*         增加ip:port地址函数                 ------>     2015-11-23
*         扩展ip地址转换函数                  ------>     2015-11-27
*         增加IP地址段相关函数                ------>     2015-12-15
*         扩展ip:port地址函数                 ------>     2015-12-30
*         增加时间处理函数                    ------>     2016-01-20
*         删除字符集转换                      ------>     2016-03-30
*         修改IP地址段处理方式                ------>     2016-05-31
*         str2int支持负数                     ------>     2017-02-10
*         增加UTC时间处理函数                 ------>     2017-05-10
*         增加字符替换处理函数                ------>     2018-01-10
*         添加判断字符集接口                  ------>     2020-08-14
*         添加过滤\'处理                      ------>     2020-08-27
*         修复判断GBK字符集问题               ------>     2021-01-15
*         去除过滤\'处理(回复原来设置)        ------>     2021-03-23
*
*******************************************************************************************/
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#include "datatype.h"
#include "stringex.h"
#include "debugout.h"
//#define ptr_diff(s1,s2) (ptr_t)((s1)-(s2))

/*******************************************************************************************
*功能:    IP地址转换
*参数:    ip           ---->   地址
*         ipstr        ---->   格式化字符串，可为NULL
*         返回值       ---->   字符串首地址
*
*注释:
*******************************************************************************************/
pchar ip2str(const uint32 ip, const pchar ipstr)
{
    struct sockaddr_in addr;

    addr.sin_addr.s_addr = ip;

    if (ipstr != NULL) {
        strcpy(ipstr, inet_ntoa(addr.sin_addr));

        return (pchar)ipstr;
    }

    return inet_ntoa(addr.sin_addr);
}

pchar ipaddr2str(const struct in_addr ip, const pchar ipstr)
{
    if (ipstr != NULL) {
        strcpy(ipstr, inet_ntoa(ip));

        return (pchar)ipstr;
    }

    return inet_ntoa(ip);

}

/*******************************************************************************************
*功能:    IP地址转换
*参数:    ip           ---->   地址
*         ipstr        ---->   格式化字符串
*         返回值       ---->   < 0 失败
*
*注释:
*******************************************************************************************/
int32 ipstr2int(const pchar ipstr, puint32 ip)
{

    struct sockaddr_in addr;

    if ((ipstr == NULL) || (ip == NULL)) return -1;

    if (inet_aton(ipstr, &addr.sin_addr) == 0)  return -1;

    *ip = addr.sin_addr.s_addr;
    return 0;
}

int32 ipstr2addr(const pchar ipstr, struct in_addr *ip)
{
    if ((ipstr == NULL) || (ip == NULL)) return -1;

    return (inet_aton(ipstr, ip) == 0) ? -1 : 0;
}

/*******************************************************************************************
*功能:    字符串大小写转化
*参数:    str         ---->   源字符串
*         返回值      ---->   首指针
*
*注释:
*******************************************************************************************/

pchar strlower(const pchar str)
{
    if (str != NULL) {
        pchar p = str;

        while (*p != 0) {
            if (((*p) >= 'A') && ((*p) <= 'Z')) {
                *p = (*p - 'A') + 'a';
            }
            p++;
        }

    }

    return str;

}

pchar strupper(pchar str)
{
    if (str != NULL) {
        pchar p = str;

        while (*p != 0) {
            if (((*p) >= 'a') && ((*p) <= 'z')) {
                *p = (*p - 'a') + 'A';
            }
            p++;
        }

    }

    return str;

}

/*******************************************************************************************
*功能:    字符串比较函数
*参数:    src         ---->   源字符串1
*         dst         ---->   源字符串2
*         返回值      ---->   src < dst : -1
*                             src = dst : 0
*                             src > dst : 1
*注释:
*******************************************************************************************/

int32 strcmp_nocase(const pchar src, const pchar dst)
{
    pchar t_src, t_dst;

    if (src == dst)  return 0;

    if ((src == NULL) || (dst == NULL)) {
        return (ptr_diff(src, dst)) > 0 ? 1 : -1;
    }

    t_src = src;
    t_dst = dst;

    while ((tolower(*t_src) != 0) || (tolower(*t_dst) != 0)) {

        if (tolower(*t_src) != tolower(*t_dst))  break;

        t_src++;
        t_dst++;

    }

    if (tolower(*t_src) == tolower(*t_dst))  return 0;

    return (((uint8)(tolower(*t_src)) - (uint8)(tolower(*t_dst))) > 0) ? 1 : -1;

}


/*******************************************************************************************
*功能:    字符串拷贝
*参数:    src         ---->   源字符串
*         dst         ---->   目的字符串
*         返回值      ---->   新字符串首地址
*
*注释:    支持地址重叠
*
*******************************************************************************************/
pchar strcpy2(pchar dst, pchar src)
{
    if (dst == src)  return dst;

    if ((src == NULL) && (dst != NULL)) {
        *dst = 0;
    } else if ((src != NULL) && (dst != NULL)) {

        pchar p = dst;

        //开始拷贝
        if (dst < src) {
            while (*src != 0) {
                *p = *src;
                p++;
                src++;
            }
            *p = 0;
        } else {
            uint32 l = strlen(src) + 1;
            src += l;
            p += l;

            while (l--) {
                p--;
                src--;
                *p = *src;
            }

        }

    }

    return dst;
}

/*******************************************************************************************
*功能:    sql语句特殊字符处理
*参数:    src         ---->   源字符串
*         dst         ---->   目的字符串
*         返回值      ---->   新字符串首地址
*
*注释:    用户确保可能插入转义符引起的空间扩大问题
*         dst为NULL，则在源字符串中直接插入
*******************************************************************************************/
pchar strsqlcheck(pchar src, pchar dst)
{
    const pchar sqlbrk = "'";   //需要转义的sql字符

    if (src == NULL) return NULL;

    if (dst == NULL) {
        dst = src;
    } else {
        strcpy2(dst, src);
        src = dst;
    }

    while ((dst = strpbrk(dst, sqlbrk)) != NULL) {

        //插入转义符
        strcpy2(dst + 1, dst);
        *dst = '\\';
        dst += 2;
    }

    return src;
}

/*******************************************************************************************
*功能:    字符串转换整数
*参数:    src             ---->   源字符串
*         ival            ---->   转换整数指针
*         返回值          ---->   true 成功
*
*注释:    支持负数
*
*******************************************************************************************/
bool str2int(const pchar src, puint32 ival)
{
    bool bret = str2intex(src, (pint32)ival);
    if (bret) {
        //无符号数错误判断
        bret = ((int32)(*ival) >= 0);
    }

    return bret;
}

bool str2intex(const pchar src, pint32 ival)
{
    bool bret = true;
    if (is_strempty(src) || (ival == NULL)) return false;

    if ((src[0] == '0') && tolower(src[1]) == 'x') {
        //16进制转换
        if (strlen(src) < 3) bret = false;

        for (int i = 2; i < (int)strlen(src); ++i) {
            if (!isxdigit(src[i])) {
                bret = false;
                break;
            }
        }

        if (bret) *ival = (uint32)strtoul(&src[2], NULL, 16);

    } else {

        //负数判断
        bool bnegative = (src[0] == '-');
        for (int i = (bnegative ? 1 : 0); i < (int)strlen(src); ++i) {
            if (!isdigit(src[i])) {
                bret = false;
                break;
            }
        }

        if (bret) {
            if (bnegative) {
                *ival = (uint32)strtoul(src + 1, NULL, 10);
                *ival *= -1;
            } else
                *ival = (uint32)strtoul(src, NULL, 10);
        }
    }


    return bret;
}

bool str2long(const pchar src, puint64 ival)
{
    bool bret = true;
    if (is_strempty(src) || (ival == NULL)) return false;

    if ((src[0] == '0') && tolower(src[1]) == 'x') {
        //16进制转换
        if (strlen(src) < 3) bret = false;

        for (int i = 2; i < (int)strlen(src); ++i) {
            if (!isxdigit(src[i])) {
                bret = false;
                break;
            }
        }

        if (bret) *ival = (uint64)strtoull(&src[2], NULL, 16);
        // if (bret) {
        //     *ival = isdigit(src[2]) ? (src[2] - '0') : (tolower(src[2]) - 'a' + 10);
        //     for (int i = 3; i < strlen(src); ++i) {
        //         *ival = *ival * 16 + (isdigit(src[i]) ? (src[i] - '0') : (tolower(src[i]) - 'a' + 10));
        //     }
        // }


    } else {

        for (int i = 0; i < (int)strlen(src); ++i) {
            if (!isdigit(src[i])) {
                bret = false;
                break;
            }
        }

        if (bret) *ival = (uint64)strtoull(src, NULL, 10);
        // if (bret) {
        //     *ival = (src[0] - '0');
        //     for (int i = 1; i < strlen(src); ++i) {
        //         *ival = *ival * 10 + (src[i] - '0');
        //     }
        // }
    }


    return bret;
}

/*******************************************************************************************
*功能:    删除首位空白字符
*参数:    src             ---->   源字符串
*         返回值          ---->   ture 发现并处理
*
*注释:    包括\t, \r, \n
*
*******************************************************************************************/
bool strdelspace(pchar src)
{
#if 0
    if (src == NULL) return false;

    pchar d1, d2;
    const pchar blank = " \t\r\n";
    bool bret = false;
    d1 = src;
    d2 = src + strlen(src);

    while (d1 != d2) {
        if (strchr(blank, *d1) != NULL) {
            d1++;
            bret = true;
        } else if (strchr(blank, *(--d2)) != NULL) {
            bret = true;
        } else {
            break;
        }

    }

    if (bret) {
        *(d2 + 1) = 0;
        strcpy2(src, d1);
    }
    return bret;
#else
    strstrip_(src);
    return true;
#endif

}

/*******************************************************************************************
*功能:    打印缓冲区内容
*参数:    buf             ---->   源数据
*         bufsize         ---->   数据长度
*         返回值          ---->   打印字符地址
*
*注释:    仅支持250个数，格式为16进制
*
*******************************************************************************************/
const pchar printbuf(const void *buf, uint16 bufsize)
{
    static char pfbuf[512];

    memset(pfbuf, 0, sizeof(pfbuf));
    if (bufsize > 250)   bufsize = 250;

    if ((buf != NULL) && (bufsize > 0)) {
        for (uint8 i = 0; i < bufsize; i++) {
            sprintf(&pfbuf[i * 2], "%02x", ((puint8)buf)[i]);
        }
    }
    return (const pchar)pfbuf;
}

/*******************************************************************************************
*功能:    字符集格式转换
*参数:    src_charset     ---->   源字符集
*         src             ---->   源数据
*         dst_charset     ---->   目的字符集
*         dst             ---->   目的数据
*         返回值          ---->   转换后的数据指针，NULL失败
*
*注释:    注意转换可能导致的空间扩充，用户确保安全，目的长度最好为源长度的2倍以上
*         dst为NULL时，内部使用默认缓冲
*
*         iconv -l 查看支持字符集
*
*******************************************************************************************/
#if 1
#include <iconv.h>
pchar strconv(const char *src_charset, const char *src, const char *dst_charset, char *dst)
{
    if ((src_charset == NULL) || (src == NULL) || (dst_charset == NULL)) return NULL;
    static char data[TMPBUFFMAX] = {0};       //支持的最大空间
    iconv_t cd;

    if (dst == NULL) dst = data;
    *dst = 0;
    PRINT_DBG_HEAD;
    print_dbg("CHARSET %s:%s, %s", src_charset, dst_charset, src);

    if ((cd = iconv_open(dst_charset, src_charset)) != (iconv_t)(-1)) {
        size_t srclen = strlen(src), dstlen = MIN(srclen * 2, TMPBUFFMAX);  //注意外部调用空间
        pchar tmp1, tmp2;
        tmp1 = (pchar)src;
        tmp2 = dst;

        iconv(cd, &tmp1, (size_t *)&srclen, &tmp2, (size_t *)&dstlen);
        iconv_close(cd);
        *tmp2 = 0;
    } else {
        dst = NULL;     //错误返回
        PRINT_ERR_HEAD;
        print_err("CHARSET %s:%s, %s", src_charset, dst_charset, src);
    }

    return dst;
}
#else
pchar strconv(const char *src_charset, const char *src, const char *dst_charset, char *dst)
{
    if (dst == NULL) return src;
    if (dst == src) return src;
    return strcpy(dst, src);
}
#endif

/*******************************************************************************************
*功能:    删除开头和结尾的特殊字符
*参数:    src             ---->   源数据
*参数:    rm              ---->   删除字符集
*         dst             ---->   目的数据
*         返回值          ---->   转换后的数据指针
*
*注释:
*
*******************************************************************************************/
pchar strstrip_(const pchar src, const pchar rm, pchar dst)
{
    if (dst == NULL) dst = src;
    if (is_strempty(src)) {
        return strcpy2(dst, src);
    }

    static const pchar _rm_ = " \t\r\n";
    bool usr = true;

    if ((rm == NULL) || (strlen(rm) == 0)) {
        usr = false;
    }


    pchar h, t;
    h = src;
    t = src + strlen(src);

    while (strchr((usr ? rm : _rm_), *h) != NULL) {
        h++;
        if (*h == 0) break;
    }

    while (h != t) {
        if (strchr((usr ? rm : _rm_), *(t - 1)) == NULL) break;
        t--;
    }

    *t = 0;
    strcpy2(dst, h);

    return dst;
}

/*******************************************************************************************
*功能:    反向查找字符串
*参数:    s1              ---->   源数据
*参数:    s2              ---->   查找字符串
*         返回值          ---->   最后一个字符串指针地址，NULL 失败
*
*注释:
*
*******************************************************************************************/
pchar strrstr(const pchar s1, const pchar s2)
{
    if (is_strempty(s1) || is_strempty(s2))    return NULL;
    int32 s1_l, s2_l;
    pchar p = NULL;

    s1_l = strlen(s1);
    s2_l = strlen(s2);
    if (s1_l >= s2_l) {
        p = s1 + s1_l - s2_l;
        while (memcmp(p, s2, s2_l) != 0) {
            if (p == s1) {
                p = NULL;
                break;
            }
            p--;
        }
    }

    return p;
}

/*******************************************************************************************
*功能:    字符串查找
*参数:    s1              ---->   源数据
*参数:    s2              ---->   查找字符串
*         返回值          ---->   第一字符串指针地址，NULL 失败
*
*注释:    不区分大小写
*
*******************************************************************************************/
pchar strstr_nocase(const pchar s1, const pchar s2)
{
    if (is_strempty(s1) || is_strempty(s2))    return NULL;
    int32 s1_l, s2_l;
    pchar p = NULL;

    s1_l = strlen(s1);
    s2_l = strlen(s2);
    if (s1_l >= s2_l) {
        p = s1;
        while (strncasecmp(p, s2, s2_l) != 0) {
            p++;
            if (*p == 0) {
                p = NULL;
                break;
            }
        }
    }

    return p;

}

/*******************************************************************************************
*功能:    MAC地址转换
*参数:    mac          ---->   地址
*         macstr       ---->   格式化字符串，可为NULL
*         返回值       ---->   字符串首地址
*
*注释:    little ending
*******************************************************************************************/
pchar mac2str(const uint64 mac, const pchar macstr)
{
    static char mactmp[20] = {0};
    uint8 tmp;
    int32 i = 0;
    for (; i < 6; i++) {
        tmp = (uint8)(mac >> (i * 8));
        sprintf(&mactmp[i * 3], "%02x:", tmp);

    }
    mactmp[i * 3 - 1] = 0; //去除尾:

    if (macstr != NULL) {
        strcpy(macstr, mactmp);
        return macstr;
    }

    return mactmp;
}

/*******************************************************************************************
*功能:    MAC地址转换
*参数:    mac          ---->   地址
*         macstr       ---->   格式化字符串
*         返回值       ---->   < 0 失败
*
*注释:    必须为xx:xx:xx:xx:xx:xx格式
********************************************************************************************/
int32 macstr2long(const pchar macstr, puint64 mac)
{
    if (is_strempty(macstr) || (mac == NULL)) return -1;

    //检查格式
    if ((macstr[2] == ':') && (macstr[5] == ':') &&
        (macstr[8] == ':') && (macstr[11] == ':') &&
        (macstr[14] == ':') && (macstr[17] == 0)) {

        char tmp[4] = {0};
        uint64 l = 0;
        for (int32 i = 5; i >= 0; i--) {
            tmp[0] = macstr[i * 3];
            tmp[1] = macstr[i * 3 + 1];
            l <<= 8;
            l |= (0xFFull & strtoull(tmp, NULL, 16));
        }

        *mac = l;
        return 0;

    }

    return -1;
}


/*******************************************************************************************
*功能:    ip:port格式字符解析
*参数:    src          ---->   地址串
*         ip           ---->   ip地址
*         port         ---->   端口地址
*         返回值       ---->   true成功
*
*注释:
*******************************************************************************************/
bool str2ipport(const pchar src, uint32 &ip, uint16 &port)
{
    if (is_strempty(src)) return false;

    char tmp[20] = {0};
    pchar s;
    uint32 t;

    if ((s = strchr(src, ':')) != NULL) {
        strncpy(tmp, src, MIN(sizeof(tmp) - 1, ptr_diff(s, src)));
        if ((ipstr2int(tmp, &ip) == 0) &&
            str2int(s + 1, &t)) {
            port = (uint16)t;
            return true;
        }
    } else {
        //无":"分隔，通过有无"."判断IP，否则为PORT
        if ((s = strchr(src, '.')) != NULL) {
            return (ipstr2int(src, &ip) == 0);
        } else {

            if (str2int(src, &t)) {
                port = (uint16)t;
                return true;
            }
        }
    }

    return false;
}

/*******************************************************************************************
*功能:    ip:port格式化
*参数:    ip           ---->   ip地址
*         port         ---->   端口地址
*         strout       ---->   字符串地址，可为NULL
*         返回值       ---->   字符串指针
*
*注释:
*******************************************************************************************/
pchar ipport2str(uint32 ip, uint16 port, pchar strout)
{
    static char strtmp[40] = {0};

    ip2str(ip, strtmp);
    return ipport2str_3(strtmp, port, strout);
}


/*******************************************************************************************
*功能:    ip:port格式字符解析
*参数:    src          ---->   地址串
*         addr         ---->   地址结构
*         返回值       ---->   true成功
*
*注释:
*******************************************************************************************/
bool str2ipport_1(const pchar src, struct sockaddr_in *addr)
{
    if (is_strempty(src) || (addr == NULL)) return false;

    uint32 ip = 0;
    uint16 port = 0;

    memset(addr, 0, sizeof(struct sockaddr_in));
    if (str2ipport(src, ip, port)) {
        addr->sin_addr.s_addr = ip;
        addr->sin_port = htons(port);
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    ip:port格式化
*参数:    addr         ---->   地址结构
*         strout       ---->   字符串地址，可为NULL
*         返回值       ---->   字符串指针
*
*注释:
*******************************************************************************************/
pchar ipport2str_1(struct sockaddr_in *addr, pchar strout)
{
    if (addr == NULL) return strout;
    return (ipport2str(addr->sin_addr.s_addr, ntohs(addr->sin_port)));
}


/*******************************************************************************************
*功能:    ip:port格式字符解析
*参数:    src          ---->   地址串
*         ip           ---->   ip地址
*         port         ---->   端口地址
*         返回值       ---->   true成功
*
*注释:
*******************************************************************************************/
bool str2ipport_2(const pchar src, struct in_addr *ip, uint16 &port)
{
    if (ip == NULL) return false;
    return str2ipport(src, (uint32 &)(ip->s_addr), port);
}

/*******************************************************************************************
*功能:    ip:port格式化
*参数:    ip           ---->   ip地址
*         port         ---->   端口地址
*         strout       ---->   字符串地址，可为NULL
*         返回值       ---->   字符串指针
*
*注释:
*******************************************************************************************/
pchar ipport2str_2(const struct in_addr *ip, uint16 port, pchar strout)
{
    if (ip == NULL) return strout;
    return (ipport2str(ip->s_addr, port, strout));
}

/*******************************************************************************************
*功能:    ip:port格式化
*参数:    ip           ---->   ip地址字符串
*         port         ---->   端口地址
*         strout       ---->   字符串地址，可为NULL
*         返回值       ---->   字符串指针
*
*注释:
*******************************************************************************************/
pchar ipport2str_3(const pchar ip, uint16 port, pchar strout)
{
    static char strtmp[40];
    if (is_strempty(ip)) {
        sprintf(strtmp, ":%d",  port);
    } else {
        sprintf(strtmp, "%s:%d", ip, port);
    }

    if (strout != NULL) {
        strcpy(strout, strtmp);
        return strout;
    }

    return strtmp;
}

/*******************************************************************************************
*功能:    获取IP地址范围段，转换为网络字节序
*参数:    ipstr        ---->   ip格式化字符
*         ipr          ---->   ip地址段
*         返回值       ---->   true成功
*
*注释:    支持格式x.x.x.x-x, x.x.x.x-x.x.x.x, x.x.x.x/x
*
*******************************************************************************************/
bool iprset(const pchar ipstr, PIPRANGE ipr)
{
    if (is_strempty(ipstr) || (ipr == NULL)) return false;

    PRINT_DBG_HEAD;
    print_dbg("IPRANGE = %s", ipstr);

    pchar brk;
    char tmp[20] = {0};
    if (((brk = strchr(ipstr, '-')) != ipstr) && (brk != NULL)) {
        strncpy(tmp, ipstr, MIN(sizeof(tmp) - 1, ptr_diff(brk, ipstr)));
        ipstr2int(tmp, &ipr->ipl);
        if (strchr(brk + 1, '.') == NULL) {     //格式x.x.x.x-x.x.x.x
            uint32 i = 0;
            str2int(brk + 1, &i);       //格式x.x.x.x-x
            PRINT_DBG_HEAD;
            print_dbg("IPRANGE - = %d", i);
            if (i < 256) {
#if 0
                //最后x表示个数
                if (i != 0) i--;
                i = (i + ((ipr->ipl >> 24) & 0x000000FF)) & 0x000000FF;
                ipr->iph = ipr->ipl;
                ipr->iph = (ipr->iph & 0x00FFFFFF) | (i << 24);
#else
                //最后x表示结束值
                ipr->iph = ipr->ipl;
                ipr->iph = (ipr->iph & 0x00FFFFFF) | (i << 24);
#endif

            } else {
                PRINT_ERR_HEAD;
                print_err("IPRANGE - = %d", i);
            }
        } else {
            ipstr2int(brk + 1, &ipr->iph);
        }

    } else if (((brk = strchr(ipstr, '/')) != ipstr) && (brk != NULL))  {       //格式x.x.x.x/x
        uint32 i = 0;
        strncpy(tmp, ipstr, MIN(sizeof(tmp) - 1, ptr_diff(brk, ipstr)));
        ipstr2int(tmp, &ipr->ipl);

        str2int(brk + 1, &i);
        PRINT_DBG_HEAD;
        print_dbg("IPRANGE / = %d", i);
        if (i > 0) {
            //NETMASK
            uint32 mask = ~0;
            i = (mask << (32 - i));
            ipr->iph = ntohl(ipr->ipl) &i;
            ipr->iph |= (~i);
            ipr->iph = htonl(ipr->iph);
        } else {
            ipr->ipl = 0;
            ipr->iph = ~0;
            PRINT_DBG_HEAD;
            print_dbg("IPRANGE ANY");
        }

    } else if (strcmp(ipstr, "0.0.0.0") == 0) {
        ipr->ipl = 0;
        ipr->iph = ~0;
        PRINT_DBG_HEAD;
        print_dbg("IPRANGE ANY");
    } else {
        ipstr2int(ipstr, &ipr->ipl);
        ipr->iph = ipr->ipl;
    }

    //比较IP大小
    if (ipcmp(ipr->ipl, ipr->iph) > 0)  SWAP(ipr->ipl, ipr->iph);

    PRINT_DBG_HEAD;
    print_dbg("IPRANGE = 0x%08x-0x%08x", ipr->ipl, ipr->iph);
#if __DEBUG_MORE__
    char tmp1[20], tmp2[20];
    PRINT_DBG_HEAD;
    print_dbg("IPRANGE = 0x%08x(%s)-0x%08x(%s)", ipr->ipl, ip2str(ipr->ipl, tmp1), ipr->iph, ip2str(ipr->iph, tmp2));
#endif
    return isiprvalid(*ipr);
}

/*******************************************************************************************
*功能:    判断IP是否在地址段范围内
*参数:    ip           ---->   IP地址
*         ipr          ---->   ip地址段
*         返回值       ---->   true在地址段范围
*
*注释:
*******************************************************************************************/
bool is_inipr(uint32 ip, PIPRANGE ipr)
{
    if (ipr == NULL) return false;

    PRINT_DBG_HEAD;
    print_dbg("IPRANGE = 0x%08x-0x%08x, 0x%08x", ipr->ipl, ipr->iph, ip);

    //转换为LITTLE ENDING
    uint32 ip1, ip2, ip3;
    ip1 = ntohl(ipr->ipl);
    ip2 = ntohl(ipr->iph);
    ip3 = ntohl(ip);

    PRINT_DBG_HEAD;
    print_dbg("IPRANGE = 0x%08x-0x%08x, 0x%08x", ip1, ip2, ip3);

    return ((ip3 >= ip1) && (ip3 <= ip2));
}

/*******************************************************************************************
*功能:    比较IP大小(ip1 - ip2)
*参数:    ip1          ---->   IP地址
*         ip2          ---->   IP地址
*         返回值       ---->   <=>
*
*注释:    网络字节序
*
*******************************************************************************************/
int ipcmp(uint32 ip1, uint32 ip2)
{
    //转换为LITTLE ENDING
    ip1 = ntohl(ip1);
    ip2 = ntohl(ip2);

    if (ip1 > ip2) return 1;
    else if (ip1 == ip2) return 0;
    else return -1;

    return 0;
    //return (int)(ip1 - ip2);
}

#include <time.h>
/*******************************************************************************************
*功能:    时间转换整数
*参数:    times        ---->   本地时间格式串
*         format       ---->   格式化，默认YYYY-MM-DD HH:MM:SS
*         返回值       ---->   本地时间，-1失败
*
*注释:
*
*******************************************************************************************/
time_t  str2time(const pchar times, const pchar format)
{
    if (is_strempty(times)) return (time_t)(-1);

#ifndef __CYGWIN__
    struct tm tms;
    memset(&tms, 0, sizeof(tms));

    if (is_strempty(format)) {
        if (strptime(times, "%Y-%m-%d %H:%M:%S", &tms) == (strlen(times) + times)) {

            return mktime(&tms);
        }
    } else {
        if (strptime(times, format, &tms) == (strlen(times) + times)) {

            return mktime(&tms);
        }
    }
#endif

    return (time_t)(-1);
}

/*******************************************************************************************
*功能:    时间转换字符串
*参数:    times        ---->   本地时间，-1表示函数自动获取本地时间
*         timebuf      ---->   用户指定输出
*         timesize     ---->   timebuf大小
*         format       ---->   格式化，默认YYYY-MM-DD HH:MM:SS
*         返回值       ---->   字符串指针, NULL失败
*
*注释:    时区问题，UTC 1970-01-01 00:00:00 北京GMT(+8)
*
*******************************************************************************************/
const pchar time2str(time_t times, pchar timebuf, int32 timesize, const pchar format)
{
    static char timetmp[100];
    struct tm s_tm;

    if (timebuf == NULL)    {timebuf = timetmp; timesize = sizeof(timetmp);}
    if (timesize <= 0) return NULL;
    memset(timebuf, 0, timesize);

    if (times == (time_t)(-1)) times = time(NULL);
    localtime_r(&times, &s_tm);

    if (is_strempty(format))
        strftime(timebuf, timesize, "%Y-%m-%d %H:%M:%S", &s_tm);
    else
        strftime(timebuf, timesize, format, &s_tm);

    return (const pchar)timebuf;
}

const pchar time2str_utc(time_t times, pchar timebuf, int32 timesize, const pchar format)
{
    static char timetmp[100];
    struct tm s_tm;

    if (timebuf == NULL)    {timebuf = timetmp; timesize = sizeof(timetmp);}
    if (timesize <= 0) return NULL;
    memset(timebuf, 0, timesize);

    if (times == (time_t)(-1)) times = time(NULL);
    gmtime_r(&times, &s_tm);

    if (is_strempty(format))
        strftime(timebuf, timesize, "%Y-%m-%d %H:%M:%S", &s_tm);
    else
        strftime(timebuf, timesize, format, &s_tm);

    return (const pchar)timebuf;
}

/*******************************************************************************************
*功能:    通过系统命令获取信息
*参数:    cmd          ---->   系统命令
*         out          ---->   输出信息
*         size         ---->   信息长度
*         返回值       ---->   NULL 失败
*
*注释:
*
*******************************************************************************************/
const pchar sysinfo(const pchar cmd, pchar out, int32 size)
{
    PRINT_DBG_HEAD;
    print_dbg("%s", cmd);

    if (!is_strempty(cmd) && (out != NULL)) {

        FILE *pp;
        memset(out, 0, size);
        if ((pp = popen(cmd, "r")) != NULL) {
            if (fgets(out, size, pp) != NULL) {
                strstrip_(out);
                if (is_strempty(out) || (strstr(out, "No such file or directory") != NULL)) out = NULL;

            } else {
                out = NULL;
            }
            pclose(pp);

        } else {
            PRINT_ERR_HEAD;
            print_err(cmd);
            out = NULL;
        }

        PRINT_DBG_HEAD;
        print_dbg("%s --> %s", cmd, out);

        return out;
    }

    return NULL;
}


/*******************************************************************************************
*功能:    字符替换函数
*参数:    src          ---->   源地址
*         csrc         ---->   待替换字符
*         cdst         ---->   替换字符
*         dst          ---->   目标地址，可为NULL
*         返回值       ---->   目的地址
*
*注释:
*
*******************************************************************************************/
const pchar strreplace(pchar src, char csrc, char cdst, pchar dst)
{
    if (dst == NULL) dst = src;

    if (!is_strempty(src) && (csrc != 0)) {

        int32 i = 0;
        while (src[i] != 0) {

            if (src[i] == csrc) dst[i] = cdst;
            else dst[i] = src[i];
            i++;
        }

        dst[i] = 0;
    }

    return (const pchar)dst;
}
/**
 *[is_utf8 判断utf8字符集]
 *@Author   张冬波
 *@DateTime 2019-06-20
 *@param    data       [字符数据]
 *@return              [>0 true]
 */
static int is_utf8(pchar data)
{
    uint8 c = (uint8)data[0];
    int following = 0;

    if ((c & 0xC0) == 0xC0) {          /* 11xxxxxx begins UTF-8 */
        if ((c & 0x20) == 0) {
            /* 110xxxxx */
            following = 1;
        } else if ((c & 0x10) == 0) {
            /* 1110xxxx */
            following = 2;
        } else if ((c & 0x08) == 0) {
            /* 11110xxx */
            following = 3;
        } else if ((c & 0x04) == 0) {
            /* 111110xx */
            following = 4;
        } else if ((c & 0x02) == 0) {
            /* 1111110x */
            following = 5;
        }

        for (int i = 1, n = 0; n < following; i++, n++) {
            if (!(c = (uint8)data[i])) {following = 0; break;}
            if ((c & 0xC0) != 0x80) {following = 0; break;}
        }
    }

    if (following != 0) following++;
    
    if (following < 3)  following = 0;
    return following;
}

/**
 *[get_sucharset 判断字符集]
 *@Author   张冬波
 *@DateTime 2019-06-20
 *@param    data       [数据]
 *@return              [字符集，默认CHARSET_ASCII]
 */
en_char get_sucharset(pchar data)
{
    if (is_strempty(data)) return CHARSET_UN;

    int32 i = 0;
    do {
        int nbyte = 0;
        if (isascii(data[i])) i++;
        else if ((nbyte = is_utf8((pchar)data + i)) > 0) {  //必须在GBK前
            PRINT_DBG_HEAD;
            print_dbg("CHARSET_UTF8");
            return CHARSET_UTF8;
        } else if (is_gbk(data + i)) {
            PRINT_DBG_HEAD;
            print_dbg("CHARSET_GBK");
            return CHARSET_GBK;
        } else {
            PRINT_DBG_HEAD;
            print_dbg("CHAR UNKNOWN %d=%x", i, data[i]);
            i++;
        }
    } while (data[i] != 0);

    PRINT_DBG_HEAD;
    print_dbg("CHARSET_ASCII");
    return CHARSET_ASCII;
}
