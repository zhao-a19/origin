/*******************************************************************************************
*文件: rfc3261.h
*描述: RFC3261平台互联
*作者: 王君雷
*日期: 2020-08-18
*修改:
*      OPTIONS和INFO，替换信令行IP                                   ------> 2020-09-14
*******************************************************************************************/
#ifndef __RFC_3261_H__
#define __RFC_3261_H__

#include "base.h"

#define HEADER_TYPE_CHECK(n, line) ((strncasecmp(line, n, strlen(n)) == 0) \
    && ((line[strlen(n)] == ' ') || (line[strlen(n)] == ':')))
#define HEADER_TYPE(name, cname, line) \
    (HEADER_TYPE_CHECK(name, line) || HEADER_TYPE_CHECK(cname, line))
#define _HEADER_HANDLE(n, cn) {n, sizeof(n) - 1, cn, sizeof(cn) - 1}

typedef struct _rfc3261_header {
    const char *name;
    unsigned int len;
    const char *cname;
    unsigned int clen;
} RFC3261_HEADER, *PRFC3261_HEADER;

/**
 * 头域及其缩写格式
 */
const struct _rfc3261_header rfc3261_headers[] = {
    _HEADER_HANDLE("Call-ID", "i"),
    _HEADER_HANDLE("Contact", "m"),
    _HEADER_HANDLE("Content-Encoding", "e"),
    _HEADER_HANDLE("Content-Length", "l"),
    _HEADER_HANDLE("Content-Type", "c"),
    _HEADER_HANDLE("From", "f"),
    _HEADER_HANDLE("Subject", "s"),
    _HEADER_HANDLE("Supported", "k"),
    _HEADER_HANDLE("To", "t"),
    _HEADER_HANDLE("Via", "v"),
};

enum {
    HEADER_UNKNOWN = -1,
    HEADER_CALLID,
    HEADER_CONTACT,
    HEADER_CONTENT_ENCODING,
    HEADER_CONTENT_LENGTH,
    HEADER_CONTENT_TYPE,
    HEADER_FROM,
    HEADER_SUBJECT,
    HEADER_SUPPORTED,
    HEADER_TO,
    HEADER_VIA,
};

/**
 * 信令名
 */
typedef struct _method_type {
    const char *name;
    unsigned int len;
    bool breplaceip; //是否替换IP
} METHOD_TYPE, *PMETHOD_TYPE;

#define SIP_HANDLER(__name, __process)  \
{ \
    (__name), sizeof(__name) - 1, (__process) \
}

const struct _method_type rfc3261_methods[] = {
    SIP_HANDLER("INVITE", true),
    SIP_HANDLER("BYE", true),
    SIP_HANDLER("ACK", true),
    SIP_HANDLER("UPDATE", true),
    SIP_HANDLER("PRACK", true),
    SIP_HANDLER("CANCEL", true),
    SIP_HANDLER("NOTIFY", true),
    SIP_HANDLER("OPTIONS", true),
    SIP_HANDLER("INFO", true),
    SIP_HANDLER("RIGISTER", false),
    SIP_HANDLER("SUBSCRIBE", false),
    SIP_HANDLER("MESSAGE", false),
    SIP_HANDLER("PUBLISH", false),
    SIP_HANDLER("REFER", false),
    SIP_HANDLER("PREPARE", false),
    SIP_HANDLER("RESTORE", false),
};

class RFC3261SIP : public base
{
private:
    int getHeaderType(const char *line);
    virtual bool doMethodLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec);
    virtual bool doHeaderLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec);
    virtual bool doBodyLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec);

public:
    RFC3261SIP(int taskid);
    virtual ~RFC3261SIP(void);
    virtual bool loadConf(const char *filename);
    virtual bool checkProto(void);
};

#endif
