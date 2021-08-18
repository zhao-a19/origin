/*******************************************************************************************
*文件:    ip6str.cpp
*描述:    处理IPv6相关地址转换
*作者:    张冬波
*日期:    2018-12-18
*修改:    创建文件                            ------>     2018-12-18
*
*
*******************************************************************************************/
#include "debugout.h"
#include "stringex.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

/**
 * [is_ipaddr 判断IP地址合法性，兼容4和6]
 * @param  ipstr [description]
 * @return       [true 有效]
 */
bool is_ipaddr(const pchar ipstr)
{
    bool bret = false;
    if (!is_strempty(ipstr)) {
        bool _6 = false;    //预判为IPv6
        bool _4 = false;
        bool _v = false;    //有效数据
        pchar tmp = ipstr;

        for (; *tmp != 0; tmp++) {
            if ((*tmp >= '0') && (*tmp <= '9')) {
                _v = true;
                continue;
            }

            if (((*tmp >= 'a') && (*tmp <= 'f')) ||
                ((*tmp >= 'A') && (*tmp <= 'F'))) {
                //_6 = true;  //??
                _v = true;
                _4 = false;
                continue;
            }

            if (*tmp == '.') {
                if (tmp == ipstr) break;
                _4 = !_6;
                continue;
            }

            if (*tmp == ':') {
                _6 = true;
                continue;
            }

            //无效退出
            _v = false;
            break;
        }

        if (_4) {
            bret = (_v && (ptr_diff(tmp, ipstr) >= 7));
        } else if (_6) {
            bret = (_v && (ptr_diff(tmp, ipstr) >= 2));
        }

    }

    if (!bret) {
        PRINT_ERR_HEAD;
        print_err("IP INVALID %s", ipstr);
    }

    return bret;
}

/**
 * [str2ip6 转换数字格式]
 * @param  ip6str  [description]
 * @param  ip6addr [description]
 * @return         [true 成功]
 */
static bool _str2ip6(const pchar ip6str, ip6addr_t *ip6addr)
{
    if (is_strempty(ip6str) || (ip6addr == NULL)) return false;

    //暂时不考虑IPV4
    for (uint i = 0, gap = 0; i < sizeof(ip6addr->s6_addr); i += 2, gap++) {
        uint16 j = strtoul(&ip6str[i * 2 + gap], NULL, 16);
        ip6addr->s6_addr[i] = (uint8_t)((j & 0xff00) >> 8);
        ip6addr->s6_addr[i + 1] = (uint8_t)(j & 0xff);
    }

#ifdef __DEBUG_MORE__
    char buf[SSADDR_MAX] = {0};
    memset(buf, 0, sizeof(buf));
    PRINT_DBG_HEAD;
    print_dbg(printbuf(ip6addr->s6_addr, sizeof(ip6addr->s6_addr)));
    ip62str(ip6addr, buf);
#endif

    return true;
}

bool str2ip6(const pchar ip6str, ip6addr_t *ip6addr)
{
#ifndef IP6_SYSCALL
    char _ip6str[SSADDR_MAX] = {0};
    if (str2ip6_std(ip6str, _ip6str) != NULL) {

        return _str2ip6(_ip6str, ip6addr);
    }
#else
    if (inet_pton(AF_INET6, ip6str, ip6addr) > 0) {
        return true;
    }
    PRINT_ERR_HEAD;
    print_err("BAD ADDR6 %s, errno[%d] %s", ip6str, errno, strerror(errno));
#endif

    return false;
}

#ifndef IP6_SYSCALL
#define IP6_ZERO "0000:"
#define err_break(ip6) { \
    PRINT_ERR_HEAD; \
    print_err("BAD ADDR6 %s", ip6); \
    return NULL; \
}
/**
 * [str2ip6_std 转为标准格式xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]
 * @param  ip6str [输入地址]
 * @param  ip6std [输出地址]
 * @return        [NULL 失败；字符首地址]
 */
pchar str2ip6_std(const pchar ip6str, pchar ip6std)
{
    if (!is_ip6addr(ip6str)) return NULL;

    static char _ip6std[SSADDR_MAX] = {0};
    pchar tmp1, tmp2;
    uint cnt = 0, cnt_max = 7;

    if (ip6std == NULL) {
        ip6std = _ip6std;
        memset(_ip6std, 0, SSADDR_MAX);
    }
    strcpy(ip6std, ip6str);

    if ((tmp1 = strstr(ip6std, IP6_SHORT_TAG)) != NULL) {
        //严格检查合法合法性
        if (strstr(tmp1 + 2, IP6_SHORT_TAG) != NULL) err_break(ip6std);

        //补全0
        if (tmp1 == ip6std) {
            *tmp1 = '0';
            tmp2 = tmp1 + 2;
        } else {
            strcpy2(tmp1, tmp1 + 1);
            tmp2 = tmp1 + 1;
        }

        if (strchr(tmp2, '.') != NULL) {
            //兼容4
            uint j = 0;
            cnt_max = 6;
            for (uint i = 0; tmp2[i] != 0; i++) {
                if (tmp2[i] == '.') j++;
            }

            if (j != 3) err_break(ip6std);
        }

        for (uint i = 0; ip6std[i] != 0; i++) {
            if (ip6std[i] == ':') cnt++;
        }

        if (cnt > cnt_max) {
            err_break(ip6std);
        } else if (cnt < cnt_max) {
            strcpy2(tmp2 + (cnt_max - cnt) * (sizeof(IP6_ZERO) - 1), tmp2);
            while (cnt < cnt_max) {
                memcpy(tmp2, IP6_ZERO, sizeof(IP6_ZERO) - 1);
                tmp2 += (sizeof(IP6_ZERO) - 1);
                cnt++;
            }

            //临时补丁
            if (*tmp2  == 0) {
                *tmp2 = '0';
                *(tmp2 + 1) = 0;
            }
        }

    } else {

        if ((tmp2 = strchr(ip6std, '.')) != NULL) {
            //兼容4
            uint j = 0;
            cnt_max = 6;
            for (uint i = 0; tmp2[i] != 0; i++) {
                if (tmp2[i] == '.') j++;
            }

            if (j != 3) err_break(ip6std);

        }

        for (uint i = 0; ip6std[i] != 0; i++) {
            if (ip6std[i] == ':') cnt++;
        }

        if (cnt != cnt_max) err_break(ip6std);
    }

    PRINT_DBG_HEAD;
    print_dbg("STD ADDR6_1 %s", ip6std);

    //补0格式化
    tmp1 = tmp2 = ip6std;
    char bufswap[SSADDR_MAX] = {0};
    size_t len;
    uint i = 0;
    uint v4cnt = 0;
    while (true) {
        if ((*tmp2 == ':') || (*tmp2 == 0)) {
            if ((v4cnt == 3) && (*tmp2 == 0)) {
                //兼容4
                i += snprintf(bufswap + i, SSADDR_MAX - i, "%02x", atoi(tmp1));
            } else {
                if ((len = ptr_diff(tmp2, tmp1)) < 4) {
                    memset(bufswap + i, '0', 4 - len);
                    i += 4 - len;
                }

                memcpy(bufswap + i, tmp1, len + 1);
                tmp1 = tmp2 = tmp2 + 1;
                i += len + 1;
            }

            if (*tmp2 == 0) break;

        } else if (*tmp2 == '.') {
            //兼容4
            i += snprintf(bufswap + i, SSADDR_MAX - i, (v4cnt & 1) ? "%02x:" : "%02x", atoi(tmp1));
            tmp1 = tmp2 = tmp2 + 1;
            v4cnt += 1;
        } else {
            tmp2++;
        }
    }

    strcpy(ip6std, bufswap);
    PRINT_DBG_HEAD;
    print_dbg("STD ADDR6_2 %s", ip6std);
    return ip6std;
}
#endif

/**
 * [ip62str 转为标准格式xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]
 * @param  ip6addr [description]
 * @param  ip6str  [description]
 * @return         [NULL 失败；字符首地址]
 */
pchar ip62str(ip6addr_t *ip6addr, pchar ip6str)
{
    if ((ip6addr == NULL) || (ip6str == NULL)) return NULL;

#ifndef IP6_SYSCALL
    sprintf(ip6str, "%02x", ip6addr->s6_addr[0]);
    for (uint i = 1, n = 2; i < sizeof(ip6addr->s6_addr); i++) {
        if ((i & 1) == 0) {
            ip6str[n] = ':';
            n += 1;
        }
        n += snprintf(&ip6str[n], SSADDR_MAX - n, "%02x", ip6addr->s6_addr[i]);
    }
#else
    if (inet_ntop(AF_INET6, ip6addr, ip6str, -1) == NULL) {
        PRINT_ERR_HEAD;
        print_err("BAD ADDR6 errno[%d] %s", errno, strerror(errno));
        return NULL;
    }
#endif

    PRINT_DBG_HEAD;
    print_dbg("ADDR6 = %s", ip6str);
    return ip6str;
}


/**
 * [str2ip6port 转换地址和端口[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:yyyy]
 * @param  strin   [description]
 * @param  ip6addr [description]
 * @param  port    [description]
 * @return         [true 成功]
 */
bool str2ip6port(const pchar strin, ip6addr_t *ip6addr, uint16 &port)
{
    if (is_strempty(strin) || (ip6addr == NULL)) return false;

    pchar pport;
    char buf[SSADDR_MAX] = {0};
    strncpy(buf, strin, SSADDR_MAX - 1);

    if ((buf[0] == '[') && ((pport = strstr(&buf[1], "]:")) != NULL)) {

        bool bret = false;
        *pport = 0;

        bret = str2ip6(&buf[1], ip6addr);
        port = atoi(pport + sizeof("]:") - 1);

        if (bret && (port != 0)) return true;
    }

    PRINT_ERR_HEAD; \
    print_err("BAD ADDR6 %s", strin);
    return false;
}

/**
 * [ip6port2str 转换地址和端口[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:yyyy]
 * @param  ip6addr [description]
 * @param  port    [description]
 * @param  strout  [description]
 * @return         [NULL 失败；字符首地址]
 */
pchar ip6port2str(ip6addr_t *ip6addr, uint16 port, pchar strout)
{
    if (strout == NULL) return NULL;

    *strout = '[';
    if (ip62str(ip6addr, strout + 1) != NULL) {
        char portstr[20];
        sprintf(portstr, "]:%u", port);
        strcat(strout, portstr);

        PRINT_DBG_HEAD;
        print_dbg("ADDR6 = %s", strout);

    } else {
        *strout = 0;
    }

    return strout;
}

/**
 * [ip6rset 地址段处理，分隔符/]
 * @param  ip6str [description]
 * @param  ip6r   [description]
 * @return        [true 成功]
 */
bool ip6rset(const pchar ip6str, ip6range_t *ip6r)
{
    if (!is_ip6addr(ip6str) || (ip6r == NULL)) return false;

    char buf[SSADDR_MAX] = {0};
    pchar flag;

    strcpy(buf, ip6str);
    flag = strrchr(buf, '/');
    if ((flag != NULL) && (isdigit(*(flag + 1)) || (*(flag + 1) == 0))) {

        uint mask = 64; //默认
        ip6addr_t maskaddr;
        memset(&maskaddr, 0xff, sizeof(maskaddr));

        *flag = 0;
        str2ip6(buf, &ip6r->ip6l);

        if (*(flag + 1) != 0) {
            mask = atoi(flag + 1);
        }
        if (mask > 128) {
            PRINT_ERR_HEAD;
            print_err("BAD ADDR6 MASK %s, %d", ip6str, mask);
            mask = 128;
        }

        //计算掩码位
        static const uint8_t bytemask[] = {0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80};
        memset(&maskaddr.s6_addr[sizeof(maskaddr) - mask / 8], 0, mask / 8);
        if ((mask % 8) != 0) {
            maskaddr.s6_addr[sizeof(maskaddr) - (mask / 8)] = bytemask[mask % 8];
        }

        for (uint i = 0, j = sizeof(ip6addr_t) / sizeof(uint32_t); i < j; i++) {
            ip6r->ip6l.s6_addr32[i] &= maskaddr.s6_addr32[i];
            ip6r->ip6h.s6_addr32[i] = ip6r->ip6l.s6_addr32[i] | (~maskaddr.s6_addr32[i]);
        }

#ifdef __DEBUG_MORE__
        char _ip6str[2][SSADDR_MAX] = {{0}, {0}};
        PRINT_DBG_HEAD;
        print_dbg("ADDR6 SET %s, %s", ip62str(&ip6r->ip6l, _ip6str[0]), ip62str(&ip6r->ip6h, _ip6str[1]));
#endif
        return true;
    }

    PRINT_ERR_HEAD;
    print_err("BAD ADDR6 %s", ip6str);
    return false;
}

/**
 * [is_inip6r 判断闭区间范围]
 * @param  ip6addr [description]
 * @param  ip6r    [description]
 * @return         [true 成功]
 */
bool is_inip6r(ip6addr_t *ip6addr, ip6range_t *ip6r)
{
    if ((ip6cmp(ip6addr, &ip6r->ip6l) >= 0) && (ip6cmp(ip6addr, &ip6r->ip6h) <= 0)) {
        char ip6str[SSADDR_MAX] = {0};
        PRINT_DBG_HEAD;
        print_dbg("ADDR6 HIT %s", ip62str(ip6addr, ip6str));
        return true;
    }

    return false;
}

/**
 * [ip6cmp  比较大小，功能同memcmp]
 * @param  ip6addr1 [description]
 * @param  ip6addr2 [description]
 * @return          [description]
 */

#define _tohost(d,s) { \
    *((uint8_t *)(d))= *((uint8_t*)(s)+3);  \
    *((uint8_t *)(d)+1)= *((uint8_t*)(s)+2);  \
    *((uint8_t *)(d)+2)= *((uint8_t*)(s)+1);  \
    *((uint8_t *)(d)+3)= *((uint8_t*)(s));  \
}

int ip6cmp(ip6addr_t *ip6addr1, ip6addr_t *ip6addr2)
{
#ifdef __DEBUG_MORE__
    char ip6str[2][SSADDR_MAX] = {{0}, {0}};
    PRINT_DBG_HEAD;
    print_dbg("ADDR6 CMP %s, %s", ip62str(ip6addr1, ip6str[0]), ip62str(ip6addr2, ip6str[1]));
#endif

    for (uint i = 0; i < sizeof(ip6addr_t) / sizeof(uint32_t);  i++) {
        if (ip6addr1->s6_addr32[i] == ip6addr2->s6_addr32[i]) continue;

        //转换字节序
        uint32_t m, n;
        _tohost(&m, &ip6addr1->s6_addr32[i]);
        _tohost(&n, &ip6addr2->s6_addr32[i]);

        if (m > n) {
            PRINT_DBG_HEAD;
            print_dbg("ADDR6 CMP GT");
            return 1;
        } else {
            PRINT_DBG_HEAD;
            print_dbg("ADDR6 CMP LT");
            return -1;
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("ADDR6 CMP EQ");
    return 0;
}

int ip6strcmp(const pchar ip6addr1, const pchar ip6addr2)
{
    PRINT_DBG_HEAD;
    print_dbg("ADDR6 CMP %s, %s", ip6addr1, ip6addr2);

    ip6addr_t _ip6addr1, _ip6addr2;

    if (str2ip6(ip6addr1, &_ip6addr1) && str2ip6(ip6addr2, &_ip6addr2)) {
        return ip6cmp(&_ip6addr1, &_ip6addr2);
    }

    PRINT_ERR_HEAD;
    print_err("ADDR6 CMP INVALID %s, %s", ip6addr1, ip6addr2);
    return 0;
}

/**
 * [str2ip6_short 删除多余0]
 * @param  ip6str [description]
 * @param  strout [可为NULL]
 * @return        [缩写后首地址，NULL：失败]
 */
pchar str2ip6_short(pchar ip6str, pchar strout)
{
    if (!is_ip6addr(ip6str)) return NULL;

    char tmp[SSADDR_MAX] = {0};
    char _z = 0;
    int nlen = 0;

    //处理前导0
    for (int i = 0; ip6str[i] != 0; i++) {
        if (ip6str[i] == '0') {
            if (_z == 0) continue;
        }

        if ((_z = ip6str[i]) == ':') _z = 0;
        tmp[nlen++] = ip6str[i];
    }

    //合并::
    pchar p1 = strstr(tmp, IP6_SHORT_TAG);
    if (strout == NULL) strout = ip6str;

    if (p1 != NULL) {
        pchar p2 = p1 + 2;

        while (*p2 != 0) {
            if (*p2 != ':') break;  //跳过多余字符
            p2++;
        }

        //多个::
        if (strstr(p2, IP6_SHORT_TAG) == NULL) {
            *p1 = 0;
            sprintf(strout, "%s"IP6_SHORT_TAG"%s", tmp, p2);
        } else {
            PRINT_ERR_HEAD;
            print_err("ADDR6 short %s --> %s", ip6str, tmp);
            return NULL;
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("ADDR6 short %s", strout);
    return strout;
}

