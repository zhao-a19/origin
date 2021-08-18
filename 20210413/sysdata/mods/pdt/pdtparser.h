/*******************************************************************************************
*文件: pdtparser.h
*描述: PDT 解析
*作者: 王君雷
*日期: 2018-08-06
*修改:
*      修改Via字段查找IP时的解析错误                                      ------> 2018-08-17
*      添加东方通信厂商                                                   ------> 2018-08-21
*      修改错误，OPTIONS错写为了OPTION                                    ------> 2018-08-23
*******************************************************************************************/
#ifndef __PDT_PARSER_H__
#define __PDT_PARSER_H__

#include <string.h>

//PDT brand
#define PDT_BRAND_ZTE      101 //中兴
#define PDT_BRAND_HUAWEI   102 //华为
#define PDT_BRAND_HYTERA   103 //海能达
#define PDT_BRAND_SEPURA   104 //赛普乐
#define PDT_BRAND_EASTCOM  105 //东方通信
#define PDT_BRAND_OTHER    199 //其他

#define PDT_STD_CALL_ID_LEN 8  //标准中规定的callid最大长度
#define METHOD_MAX_LEN     16

struct sip_handler {
    const char *name;
    unsigned int len;
    const char *cname;
    unsigned int clen;
    const char *seach1;
    unsigned int slen1;
    const char *seach2;
    unsigned int slen2;
    const char *seach3;
    unsigned int slen3;
    const char *seach4;
    unsigned int slen4;
    int (*process)(const char *dptr, const char *limit, const char *seach, int slen, int *shift);
};

#define SIP_HANDLER1(__name, __cname, __process)  \
{                                   \
    (__name),sizeof(__name) - 1, \
    (__cname),sizeof(__cname) - 1, \
    NULL, 0, \
    NULL, 0, \
    NULL, 0, \
    NULL, 0, \
    (__process) \
}

#define SIP_HANDLER2(__name, __cname, __seach1, __seach2, __process)  \
{                                   \
    (__name),sizeof(__name) - 1, \
    (__cname),sizeof(__cname) - 1, \
    (__seach1),sizeof(__seach1) - 1, \
    (__seach2),sizeof(__seach2) - 1, \
    NULL, 0, \
    NULL, 0, \
    (__process) \
}

#define SIP_HANDLER3(__name, __cname, __seach1, __seach2, __seach3, __seach4,__process)  \
{                                   \
    (__name),sizeof(__name) - 1, \
    (__cname),sizeof(__cname) - 1, \
    (__seach1),sizeof(__seach1) - 1, \
    (__seach2),sizeof(__seach2) - 1, \
    (__seach3),sizeof(__seach3) - 1, \
    (__seach4),sizeof(__seach4) - 1, \
    (__process) \
}

int ipaddr_len(const char *dptr, const char *limit, const char *seach, int slen,  int *shift);
int digits_len(const char *dptr, const char *limit, const char *seach, int slen, int *shift);
int callid_len(const char *dptr, const char *limit, const char *seach, int slen, int *shift);
int string_len(const char *dptr, const char *limit);

const struct sip_handler sip_methods[] = {
    SIP_HANDLER3("INVITE", "I", "sip:", "s:", "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("ACK", "A", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("OPTIONS", "O", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("INFO", "T", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("BYE", "B", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("CANCEL", "C", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("RIGISTER", "R", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("SUBSCRIBE", "Q", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("UPDATE", "U", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("MESSAGE", "M", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("PUBLISH", "P", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("NOTIFY", "N", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("REFER", "F", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("PREPARE", "H", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
    SIP_HANDLER3("RESTORE", "E", "sip:", "s:",  "m=", "maddr=", ipaddr_len),
};

enum method_type {
    ERR_MTYPE = -1,
    INVITE_TYPE = 0,
    ACK_TYPE,
    OPTION_TYPE,
    INFO_TYPE,
    BYE_TYPE,
    CANCEL_TYPE,
    RIGISTER_TYPE,
    SUBSCRIBE_TYPE,
    UPDATE_TYPE,
    MESSAGE_TYPE,
    PUBLISH_TYPE,
    NOTIFY_TYPE,
    REFER_TYPE,
    PREPARE_TYPE,
    RESTORE_TYPE
};

const struct sip_handler sip_headers[] = {
    SIP_HANDLER2("Via:", "v:", ":", "U ", ipaddr_len), //对于请求 发出者地址. 响应不用替换
    SIP_HANDLER1("Call-ID:", "i:", callid_len),        //记录会话唯一性ID
    SIP_HANDLER3("Contact:", "m:", "sip:", "s:", "m=", "maddr=", ipaddr_len), //发出者地址
    SIP_HANDLER1("Content-Length:", "l:", digits_len),  //需要替换长度
    SIP_HANDLER1("o=", NULL, ipaddr_len),
    SIP_HANDLER1("m=", NULL, digits_len),
};

enum header_type {
    ERR_HTYPE = -1,
    VIA_TYPE = 0,
    CALLID_TYPE,
    CONTACT_TYPE,
    CONTENT_LENGTH_TYPE,
    ORIGIN_TYPE,
    MEDIA_TYPE,
};

#endif
