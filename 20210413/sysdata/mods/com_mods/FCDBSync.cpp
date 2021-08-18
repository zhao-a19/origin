/*******************************************************************************************
*文件:  FCDBSync.cpp
*描述:  DBSYNC模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       使用zlog                                                     ------> 2019-03-18
*       长度为19的 24的包，都可能是需要匹配替换信息的包              ------> 2019-06-14
*******************************************************************************************/
#include "FCDBSync.h"
#include "debugout.h"

#define DBSYNC_FIRST_PAK_LEN 19
#define DBSYNC_FIRST_PAK_LEN2 24

CDBSYNCSINGLE::CDBSYNCSINGLE(void)
{
    dbsyncflag[0] = 0x20;
    dbsyncflag[1] = 0x05;
    dbsyncflag[2] = 0xEA;
    dbsyncflag[3] = 0xEB;
    dbsyncflag[4] = 0xEC;
    dbsyncflag[5] = 0x00;
    dbsyncflag[6] = 0x00;
}

CDBSYNCSINGLE::~CDBSYNCSINGLE(void)
{
}

/**
 * [CDBSYNCSINGLE::DoMsg 处理应用信息]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @param  bFromSrc  [是否来自客户端]
 * @return           [允许通过返回true]
 */
bool CDBSYNCSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror, pktchange);
    } else {
        return DoDstMsg(sdata, slen, cherror, pktchange);
    }
}

/**
 * [CDBSYNCSINGLE::DoSrcMsg 处理应用信息 来自客户端的请求]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @return           [允许通过返回true]
 */
bool CDBSYNCSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange)
{
    int hdflag = GetHeadLen(sdata);
    int applayerlen = slen - hdflag;

    //不是第一个包的长度
    if ((applayerlen != DBSYNC_FIRST_PAK_LEN) && (applayerlen != DBSYNC_FIRST_PAK_LEN2)) {
        return true;
    }

    //不是dbsyncflag
    if (memcmp(sdata + hdflag, dbsyncflag, 7) != 0) {
        PRINT_INFO_HEAD
        print_info("not dbsync flag");
        return true;
    }

    bool flag = DecodeRequest(sdata + hdflag, slen - hdflag, cherror, pktchange);
    RecordCallLog(sdata, "Checking", "DBSYNC", cherror, flag);
    PRINT_DBG_HEAD
    print_dbg("record dbsync calllog: %s", flag ? "true" : "false");
    return flag;
}

/**
 * [CDBSYNCSINGLE::DoSrcMsg 处理应用信息 来自服务器的响应]
 * @param  sdata     [IP头开始的数据]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @return           [允许通过返回true]
 */
bool CDBSYNCSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange)
{
    return true;
}

/**
 * [CDBSYNCSINGLE::DecodeRequest 解析请求 修改数据内容]
 * @param  sdata     [应用层开始的数据]
 * @param  slen      [数据长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [数据包是否改变了]
 * @return           [成功返回true]
 */
bool CDBSYNCSINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror, int *pktchange)
{
    int r1 = 0, r2 = 0, r3 = 0;
    memcpy(&r1, sdata + 7, 4);
    memcpy(&r2, sdata + 11, 4);
    r3 = r1 ^ r2;
    memcpy(sdata + 15, &r3, 4);
    *pktchange = PACKET_CHANGED;

    PRINT_DBG_HEAD
    print_dbg("packet changed");
    return true;
}
