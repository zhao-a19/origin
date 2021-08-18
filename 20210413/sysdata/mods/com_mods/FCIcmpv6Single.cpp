/*******************************************************************************************
*文件:  FCIcmpv6Single.cpp
*描述:  ICMP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       本模块可以过滤命令                                         ------> 2019-01-16
*******************************************************************************************/
#include "FCIcmpv6Single.h"
#include "debugout.h"
#include "network.h"

CICMPV6SINGLE::CICMPV6SINGLE(void)
{
}

CICMPV6SINGLE::~CICMPV6SINGLE(void)
{
}

/**
 * [CICMPV6SINGLE::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [在此处不使用 是为了保持和基类一致而留下的]
 * @return           [允许通过返回true]
 */
bool CICMPV6SINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    ICMPV6_HEADER header;

    //判断是请求还是响应
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag < (int)sizeof(header)) {
        PRINT_ERR_HEAD
        print_err("slen[%d] too short", slen);
        return true;
    }
    memcpy(&header, sdata + hdflag, sizeof(header));

    switch (header.type) {
    case 128:          //PING 请求
        return DoSrcMsg(sdata, slen, cherror);
        break;
    case 129:          //PING 响应
        return DoDstMsg(sdata, slen, cherror);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown icmpv6 type[%d]", header.type);
        return false;
        break;
    }
}

/**
 * [CICMPV6SINGLE::DoSrcMsg 处理源端请求]
 * @param  sdata   [数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CICMPV6SINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    char chcmd[] = "Request";
    bool bflag = AnalyseCmdRule(chcmd, "", cherror);
    RecordCallLog(sdata, chcmd, "", cherror, bflag);
    return bflag;
}

/**
 * [CICMPV6SINGLE::DoDstMsg 处理目的响应]
 * @param  sdata   [数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CICMPV6SINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    char chcmd[] = "Reply";
    bool bflag = AnalyseCmdRule(chcmd, "", cherror);
    RecordCallLog(sdata, chcmd, "", cherror, bflag);
    return bflag;
}

/**
 * [CICMPV6SINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CICMPV6SINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    bool bflag = m_service->m_IfExec;
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            bflag = m_service->m_cmd[i]->m_action;
            break;
        }
    }

    if (!bflag) {
        sprintf(cherror, "%s", ICMP_PERM_FORBID);
    }
    return bflag;
}
