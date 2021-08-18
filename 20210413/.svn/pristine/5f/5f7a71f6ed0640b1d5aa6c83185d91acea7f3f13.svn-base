/*******************************************************************************************
*文件:  str_oper.h
*描述:  字符串操作相关宏定义
*
*作者:  王君雷
*日期:  2019-06-25
*修改:
*******************************************************************************************/
#ifndef __STR_OPER_H__
#define __STR_OPER_H__

#include "gap_config.h"

#define IS_STR_EMPTY(str) (strcmp((str), "") == 0)
#define IS_RANGE_PORTS(port) (strchr(port, '-') != NULL)

#define MAKE_TABLESTRING(chcmd, format, v6, args...) \
if (v6) { \
    if (SUPPORT_IPV6 == 1){ \
        sprintf(chcmd, "%s "format, IP6TABLES, ##args); \
    } else{\
        memset(chcmd, 0, sizeof(chcmd)); \
        PRINT_ERR_HEAD \
        print_err("not support ipv6"); \
    }\
}else{ \
    sprintf(chcmd, "%s "format, IPTABLES, ##args);\
}

#endif
