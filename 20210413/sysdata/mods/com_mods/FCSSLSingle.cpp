/*******************************************************************************************
*文件:  FCSSLSingle.cpp
*描述:  SSL模块
*作者:  王君雷
*日期:  2014-07
*修改:
*       SSL模块添加对TLSV1.2 TLSV1.3版本的支持                          ------> 2018-08-17
*       SSL模块考虑版本为sslv2时头部不同的情况，180817引入的问题        ------> 2018-08-20
*******************************************************************************************/
#include "FCSSLSingle.h"
#include "debugout.h"
#include "define.h"

CSSLSINGLE::CSSLSINGLE()
{

}

CSSLSINGLE::~CSSLSINGLE()
{

}

bool CSSLSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    return (bFromSrc == 1) ? DoSrcMsg(sdata, slen, cherror) : DoDstMsg(sdata, slen, cherror);
}

bool CSSLSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    return DecodeRequest(sdata, slen, cherror);
}

bool CSSLSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return DecodeReply(sdata, slen, cherror);
}

/**
 * [CSSLSINGLE::IfHandshakeType handshaketype是否合法]
 * @param  ct [description]
 * @return    [合法返回true]
 */
bool CSSLSINGLE::IfHandshakeType(unsigned char ct)
{
    for (int i = 0; i < (int)ARRAY_SIZE(HandshakeType); i++) {
        if (ct == HandshakeType[i]) {
            return true;
        }
    }
    return false;
}

/**
 * [CSSLSINGLE::IfSSLVerInfo SSL协议是否合法]
 * @param  ct1 [description]
 * @param  ct2 [description]
 * @return     [合法返回true]
 */
bool CSSLSINGLE::IfSSLVerInfo(unsigned char ct1, unsigned char ct2)
{
    for (int i = 0; i < (int)ARRAY_SIZE(ssl_versions); i++) {
        if (ssl_versions[i][0] == ct1 && ssl_versions[i][1] == ct2) {
            return true;
        }
    }
    return false;
}

/**
 * [CSSLSINGLE::IfContentType contenttype是否合法]
 * @param  ct [description]
 * @return    [合法返回true]
 */
bool CSSLSINGLE::IfContentType(unsigned char ct)
{
    for (int i = 0; i < (int)ARRAY_SIZE(ContentType); i++) {
        if (ct == ContentType[i]) {
            return true;
        }
    }
    return false;
}

/**
 * [CSSLSINGLE::DecodeRequest 解析请求信息]
 * @param  sdata   [IP数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSSLSINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    PRINT_DBG_HEAD
    print_dbg("begin decode request");

    char tmpstring[64] = {0};
    SSL_STATUS status = SSL_UNKNOWN;
    bool find = false;
    bool proto_ok = false;
    CLIENT_HELLO_HEADER helloheader;
    CLIENT_HELLO_HEADER_SSLV2 helloheadersslv2;
    BZERO(helloheader);
    BZERO(helloheadersslv2);

    //组成字符串,能代表这个链接 sip_sport_dip_dport如:192.168.100.100_8080_192.168.200.200_8090
    unsigned char *p_ip = sdata + 12;
    unsigned char *p_port = sdata + (sdata[0] & 0x0F) * 4;

    sprintf(tmpstring, "%d.%d.%d.%d_%d_%d.%d.%d.%d_%d",
            p_ip[0], p_ip[1], p_ip[2], p_ip[3], p_port[0] * 256 + p_port[1],
            p_ip[4], p_ip[5], p_ip[6], p_ip[7], p_port[2] * 256 + p_port[3]);
    string str = tmpstring;

    if (IsSYN(sdata)) {
        PRINT_DBG_HEAD
        print_dbg("is syn data[%s]", tmpstring);
        m_status_map[str] = SSL_UNKNOWN;
        return true;
    }

    if (IsFIN(sdata) || IsRST(sdata)) {
        m_status_map.erase(str);
        return true;
    }

    if (GetHeadLen(sdata) == slen) {
        PRINT_DBG_HEAD
        print_dbg("is ack data");
        return true;
    }

    map<string, SSL_STATUS>::iterator beg = m_status_map.begin();
    while (beg != m_status_map.end()) {
        if (str == beg->first) {
            find = true;
            status = beg->second;
            break;
        }
        beg++;
    }

    if (!find) {
        PRINT_ERR_HEAD
        print_err("not in map[%s]", tmpstring);
        return true;
    }

    switch (status) {
    case SSL_OK:

        proto_ok = true;
        break;
    case SSL_FAIL:

        PRINT_ERR_HEAD
        print_err("not allowd to pass through[%s]", tmpstring);
        break;
    default: //应用层的第一个数据包

        int hdlen = GetHeadLen(sdata);
        if ((slen - hdlen) < (int)sizeof(helloheader)) {
            PRINT_ERR_HEAD
            print_err("packet too short[%d]", slen - hdlen);
        } else {
            memcpy(&helloheadersslv2, sdata + hdlen, sizeof(helloheadersslv2));
            memcpy(&helloheader, sdata + hdlen, sizeof(helloheader));

            if ((helloheadersslv2.length[0] & 0x80) > 0) {
                if (((helloheadersslv2.length[0] & 0x7F) * 256 + helloheadersslv2.length[1] + 2 == slen - hdlen)
                    && IfHandshakeType(helloheadersslv2.type)
                    && IfSSLVerInfo(helloheadersslv2.version[0], helloheadersslv2.version[1])) {
                    proto_ok = true;
                }
            } else {
                if (IfContentType(helloheader.content_type)
                    && IfSSLVerInfo(helloheader.version[0], helloheader.version[2])
                    && IfHandshakeType(helloheader.handheader.type)
                    && IfSSLVerInfo(helloheader.handheader.version[0], helloheader.handheader.version[1])) {
                    proto_ok = true;
                }
            }
        }

        if (proto_ok) {
            RecordCallLog(sdata, "Client Hello", "", "", proto_ok);
            m_status_map[str] = SSL_OK;
        } else {
            RecordCallLog(sdata, "", "", SSL_PERM_FORBID, proto_ok);
            m_status_map[str] = SSL_FAIL;
        }
        break;
    }

    PRINT_DBG_HEAD
    print_dbg("decode request over [%s]", proto_ok ? "true" : "false");
    return proto_ok;
}

/**
 * [CSSLSINGLE::DecodeReply 解析响应信息]
 * @param  sdata   [IP数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSSLSINGLE::DecodeReply(unsigned char *sdata, int slen, char *cherror)
{
    char tmpstring[64] = {0};
    unsigned char *p_ip = sdata + 12;
    unsigned char *p_port = sdata + (sdata[0] & 0x0F) * 4;

    if (IsRST(sdata)) {
        sprintf(tmpstring, "%d.%d.%d.%d_%d_%d.%d.%d.%d_%d",
                p_ip[4], p_ip[5], p_ip[6], p_ip[7], p_port[2] * 256 + p_port[3],
                p_ip[0], p_ip[1], p_ip[2], p_ip[3], p_port[0] * 256 + p_port[1]);
        string str = tmpstring;

        PRINT_DBG_HEAD
        print_dbg("erase map[%s]", tmpstring);
        m_status_map.erase(str);
    }

    return true;
}
