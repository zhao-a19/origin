/*******************************************************************************************
*文件:  FCIcmpSingle.cpp
*描述:  ICMP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       本模块可以过滤命令                                         ------> 2019-01-16
*******************************************************************************************/
#include "FCIcmpSingle.h"
#include "debugout.h"

CICMPSINGLE::CICMPSINGLE(void)
{
}

CICMPSINGLE::~CICMPSINGLE(void)
{
}

/**
 * [CICMPSINGLE::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [在此处不可以使用 是为了保持和基类一致而留下的]
 * @return           [允许通过返回true]
 */
bool CICMPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    //判断是请求还是响应
    int hdflag = GetHeadLen(sdata);
    int type = sdata[hdflag];
    switch (type) {
    case 8:
    case 10:
    case 13:
    case 15:
    case 17:
        return DoSrcMsg(sdata, slen, cherror);
        break;
    case 0:
    case 9:
    case 14:
    case 16:
    case 18:
        return DoDstMsg(sdata, slen, cherror);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown icmp type[%d]", type);
        return false;
        break;
    }
}

/**
 * [CICMPSINGLE::DoSrcMsg 处理源端请求]
 * @param  sdata   [数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CICMPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    char chcmd[] = "Request";
    bool bflag = AnalyseCmdRule(chcmd, "", cherror);
    RecordCallLog(sdata, chcmd, "", cherror, bflag);
    return bflag;
}

/**
 * [CICMPSINGLE::DoDstMsg 处理目的响应]
 * @param  sdata   [数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CICMPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    char chcmd[] = "Reply";
    bool bflag = AnalyseCmdRule(chcmd, "", cherror);
    RecordCallLog(sdata, chcmd, "", cherror, bflag);
    return bflag;
}

/**
 * [CICMPSINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [description]
 * @param  chpara  [description]
 * @param  cherror [description]
 * @return         [description]
 */
bool CICMPSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
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
