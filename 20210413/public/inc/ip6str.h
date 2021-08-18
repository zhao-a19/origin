/*******************************************************************************************
*文件:    ip6str.h
*描述:    处理IPv6相关地址转换
*作者:    张冬波
*日期:    2018-12-18
*修改:    创建文件                            ------>     2018-12-18
*
*
*******************************************************************************************/
#ifndef __IP6STR_H__
#define __IP6STR_H__

#include "datatype.h"
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP6_SHORT_TAG "::"
#define  IP6_SYSCALL
typedef struct in6_addr ip6addr_t;
#define SSADDR_MAX 128

typedef struct _ip6range {
    ip6addr_t ip6l;  //低地址
    ip6addr_t ip6h;  //高地址
} ip6range_t;

//简单判断合法性
#define is_ip6addr(s) (!is_strempty(s) && (strchr(s, ':') != NULL))

/**
 * [is_ipaddr 判断IP地址合法性，兼容4和6]
 * @param  ipstr [description]
 * @return       [true 有效]
 */
bool is_ipaddr(const pchar ipstr);

/**
 * [str2ip6 转换数字格式]
 * @param  ip6str  [description]
 * @param  ip6addr [description]
 * @return         [true 成功]
 */
bool str2ip6(const pchar ip6str, ip6addr_t *ip6addr);

/**
 * [str2ip6_std 转为标准格式xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]
 * @param  ip6str [输入地址]
 * @param  ip6std [输出地址]
 * @return        [NULL 失败；字符首地址]
 */
#ifndef IP6_SYSCALL
pchar str2ip6_std(const pchar ip6str, pchar ip6std = NULL);
#endif

/**
 * [ip62str 转为标准格式xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]
 * @param  ip6addr [description]
 * @param  ip6str  [description]
 * @return         [NULL 失败；字符首地址]
 */
pchar ip62str(ip6addr_t *ip6addr, pchar ip6str);

/**
 * [str2ip6port 转换地址和端口[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:yyyy]
 * @param  strin   [description]
 * @param  ip6addr [description]
 * @param  port    [description]
 * @return         [true 成功]
 */
bool str2ip6port(const pchar strin, ip6addr_t *ip6addr, uint16 &port);

/**
 * [ip6port2str 转换地址和端口[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:yyyy]
 * @param  ip6addr [description]
 * @param  port    [description]
 * @param  strout  [description]
 * @return         [NULL 失败；字符首地址]
 */
pchar ip6port2str(ip6addr_t *ip6addr, uint16 port, pchar strout);

/**
 * [ip6rset 地址段处理，分隔符/]
 * @param  ip6str [description]
 * @param  ip6r   [description]
 * @return        [true 成功]
 */
bool ip6rset(const pchar ip6str, ip6range_t *ip6r);

/**
 * [is_inip6r 判断闭区间范围]
 * @param  ip6addr [description]
 * @param  ip6r    [description]
 * @return         [true 成功]
 */
bool is_inip6r(ip6addr_t *ip6addr, ip6range_t *ip6r);

/**
 * [ip6cmp  比较大小，功能同memcmp]
 * @param  ip6addr1 [description]
 * @param  ip6addr2 [description]
 * @return          [description]
 */
int ip6cmp(ip6addr_t *ip6addr1, ip6addr_t *ip6addr2);

int ip6strcmp(const pchar ip6addr1, const pchar ip6addr2);

/**
 * [str2ip6_short 删除多余0,缩写::]
 * @param  ip6str [description]
 * @param  strout [可为NULL]
 * @return        [缩写后首地址，NULL：失败]
 */
pchar str2ip6_short(pchar ip6str, pchar strout = NULL);

#ifdef __cplusplus
}
#endif


#endif
