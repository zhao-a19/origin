/*******************************************************************************************
*文件:  FCDnsSingle.cpp
*描述:  DNS模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       协议解析使用结构体 代替立即数                           ------> 2019-01-19
*       修改DNS模块解析中越界拷贝                               ------> 2019-09-12
*******************************************************************************************/
#include "FCDnsSingle.h"
#include "network.h"
#include "debugout.h"

static const int E_DNS_FALSE = -10;
static const int E_DNS_OK = -11;

CDNSSINGLE::CDNSSINGLE()
{
}

CDNSSINGLE::~CDNSSINGLE()
{
}

/**
 * [CDNSSINGLE::DoMsg 处理IP包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [内容是否改变了]
 * @param  bFromSrc  [是否来自客户端对象]
 * @return           [允许通过返回true]
 */
bool CDNSSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

/**
 * [CDNSSINGLE::DoSrcMsg 处理客户端对象发来的IP包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @return           [允许通过返回true]
 */
bool CDNSSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    BZERO(m_cmd);
    BZERO(m_param);

    if (AnalyseDns(sdata + hdflag, slen - hdflag, cherror) == E_DNS_OK) {
        RecordCallLog(sdata, m_cmd, m_param, cherror, true);
        return true;
    } else {
        RecordCallLog(sdata, m_cmd, m_param, cherror, false);
        return false;
    }
}

/**
 * [CDNSSINGLE::DoDstMsg 处理目的对象发来的IP包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @return           [允许通过返回true]
 */
bool CDNSSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [CDNSSINGLE::DecodeDnsUrl 从网络数据包中解析出DNS查询的url]
 * @param  ucdata     [dns查询包 dns头部已经偏移过去了]
 * @param  ilen       [ 长度]
 * @param  chhostname [url 出参]
 * @return            [返回解析出的长度 失败返回E_DNS_FALSE]
 */
int CDNSSINGLE::DecodeDnsUrl(unsigned char *ucdata, int ilen, char *chhostname)
{
    PRINT_DBG_HEAD
    print_dbg("total len %d", ilen);

    int tmplen = 0, inamelen = 0;
    for (int i = 0; i < ilen; i++) {
        tmplen = ucdata[i];
        if ((i + 1 + tmplen > ilen) || (tmplen == 0)) {
            PRINT_DBG_HEAD
            print_dbg("tmplen %d", tmplen);
            break;
        }

        PRINT_DBG_HEAD
        print_dbg("tmplen %d", tmplen);

        memcpy((unsigned char *)chhostname + inamelen, ucdata + inamelen + 1, tmplen);
        inamelen += tmplen;
        i = inamelen;
        chhostname[inamelen] = 0x2e;
        inamelen++;
    }

    PRINT_DBG_HEAD
    print_dbg("inamelen %d", inamelen);

    if (inamelen > 1) {
        chhostname[inamelen - 1] = 0x00;
        PRINT_DBG_HEAD
        print_dbg("hostname: %s", chhostname);
        return inamelen - 1;
    }
    return E_DNS_FALSE;
}

/**
 * [CDNSSINGLE::AnalyseDns 分析过滤DNS]
 * @param  sdata     [应用层数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @return           [允许通过返回true]
 */
int CDNSSINGLE::AnalyseDns(unsigned char *sdata, int slen, char *cherror)
{
    int ret = 0;
    DNS_HEADER header;

    if (slen < (int)sizeof(header)) {
        sprintf(cherror, "%s", DNS_PROTO_ERROR);
        PRINT_ERR_HEAD
        print_err("dns request too short[%d]", slen);
        return false;
    }
    memcpy(&header, sdata, sizeof(header));
    if ((header.flags[0] & 0x80) == 0) {

        strcpy(m_cmd, "REQUEST");

        //获取DNS查询的主机名
        int ihostlen = slen - sizeof(header);
        if (ihostlen <= 0) {
            strcpy(cherror, DNS_DOMAINNAME_ERROR);
            PRINT_ERR_HEAD
            print_err("hostlen too short[%d]", ihostlen);
            return E_DNS_FALSE;
        }

        char *chhostname = new char[ihostlen];
        if (chhostname == NULL) {
            strcpy(cherror, DNS_DOMAINNAME_ERROR);
            PRINT_ERR_HEAD
            print_err("new hostname buff fail");
            return E_DNS_FALSE;
        }
        memset(chhostname, 0, ihostlen);

        ret = DecodeDnsUrl(sdata + sizeof(header), ihostlen, chhostname);
        if (ret == E_DNS_FALSE) {
            strcpy(cherror, DNS_DOMAINNAME_ERROR);
            DELETE(chhostname);
        } else {
            if (strlen(chhostname) >= sizeof(m_param)) {
                memcpy(m_param, chhostname, sizeof(m_param) - 1);
                PRINT_INFO_HEAD
                print_info("hostname too long. cut it[%s]", chhostname);
            } else {
                strcpy(m_param, chhostname);
            }
            DELETE(chhostname);
            if (AnalyseUrlRule(m_cmd, m_param, cherror)) {
                return E_DNS_OK;
            }
        }
    } else {
        sprintf(cherror, "%s", DNS_NOT_REQUEST);
    }
    return E_DNS_FALSE;
}

/**
 * [CDNSSINGLE::AnalyseUrlRule DNS过滤命令参数]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CDNSSINGLE::AnalyseUrlRule(char *chcmd, char *chpara, char *cherror)
{
    if ((chcmd == NULL) || (chpara == NULL) || (cherror == NULL)) {
        PRINT_ERR_HEAD
        print_err("dns analyse rule para is null[%s:%s]", chcmd, chpara);
        return false;
    }

    bool bflag = m_service->m_IfExec;

    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                bflag = m_service->m_cmd[i]->m_action;
            }
        }
    }

    if (!bflag) {
        sprintf(cherror, "%s", DNS_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("dns analyse rule fail.cmd[%s] para[%s]", chcmd, chpara);
    }
    return bflag;
}
