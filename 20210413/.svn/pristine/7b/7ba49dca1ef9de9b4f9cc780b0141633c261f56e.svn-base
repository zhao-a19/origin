/*******************************************************************************************
*文件:  FCSSLSingle.h
*描述:  SSL模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       SSL模块添加对TLSV1.2 TLSV1.3版本的支持                          ------> 2018-08-17
*       SSL模块考虑版本为sslv2时头部不同的情况，180817引入的问题        ------> 2018-08-20
*******************************************************************************************/
#ifndef __FC_SSL_SINGLE_H__
#define __FC_SSL_SINGLE_H__

#include "FCSingle.h"
#include <map>
using namespace std;

const unsigned char HandshakeType[] = {0, 1, 2, 11, 12, 13, 14, 15, 16, 20, 255};
const unsigned char ContentType[] = {20, 21, 22, 23, 255};

const char ssl_versions[][2] = {
    {0x03, 0x01}, //TLSV1_0
    {0x03, 0x02}, //TLSV1_1
    {0x03, 0x03}, //TLSV1_2
    {0x03, 0x04}, //TLSV1_3
    {0x03, 0x00}, //SSL3
    {0x00, 0x02}, //SSL2
};

enum SSL_STATUS {
    SSL_FAIL = -1,
    SSL_UNKNOWN = 0,
    SSL_OK = 1
};

#pragma pack(push, 1)
typedef struct HANDSHAKE_HEADER {
    char type;
    char length[3];
    char version[2];
} HANDSHAKE_HEADER, *PHANDSHAKE_HEADER;

typedef struct CLIENT_HELLO_HEADER {
    char content_type;
    char version[2];
    char length[2];
    HANDSHAKE_HEADER handheader;
} CLIENT_HELLO_HEADER, *PCLIENT_HELLO_HEADER;

typedef struct CLIENT_HELLO_HEADER_SSLV2 {
    char length[2];
    char type;
    char version[2];
    char cipher_spec_len[2];
    char session_id_len[2];
    char challenge_len[2];
} CLIENT_HELLO_HEADER_SSLV2, *PCLIENT_HELLO_HEADER_SSLV2;
#pragma pack(pop)

class CSSLSINGLE : public CSINGLE
{
public:
    CSSLSINGLE();
    ~CSSLSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);

    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeReply(unsigned char *sdata, int slen, char *cherror);

    bool IfHandshakeType(unsigned char ct);
    bool IfSSLVerInfo(unsigned char ct1, unsigned char ct2);
    bool IfContentType(unsigned char ct);

    map<string, SSL_STATUS> m_status_map;
};

#endif
