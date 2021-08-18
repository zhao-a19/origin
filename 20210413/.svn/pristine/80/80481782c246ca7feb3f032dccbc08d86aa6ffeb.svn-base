/*******************************************************************************************
*文件:  FCTcpNull.cpp
*描述:  TCP自定义模块
*作者:  王君雷
*日期:  2015
*
*修改:
*        支持十六进制命令的定制和过滤                             ------> 2018-01-30
*        日志用中文                                               ------> 2019-01-30
*******************************************************************************************/
#include "FCTcpNull.h"
#include <string.h>

CTCPNULL::CTCPNULL()
{
}

CTCPNULL::~CTCPNULL()
{

}

bool CTCPNULL::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CTCPNULL::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0) {
        return true;
    }

    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (m_service->m_cmd[i]->m_start > datalen) {
            continue;
        }

        if (strcmp(m_service->m_cmd[i]->m_parameter, HEX_FLAG) != 0) {
            //比对命令,只要找到，则立刻终止命令查找
            if (m_service->m_cmd[i]->m_start < 0) {
                if (m_common.casestrstr(sdata + hdlen,
                                        (const unsigned char *)m_service->m_cmd[i]->m_cmd, 0, datalen) == E_COMM_OK) {
                    RecordCallLog(sdata, m_service->m_cmd[i]->m_cmd,
                                  "", SEARCH_AND_FOUND_CMD, m_service->m_cmd[i]->m_action);
                    return m_service->m_cmd[i]->m_action;
                }
            } else {
                if (strncasecmp((const char *)sdata + hdlen + m_service->m_cmd[i]->m_start,
                                m_service->m_cmd[i]->m_cmd, strlen(m_service->m_cmd[i]->m_cmd)) == 0) { //找到
                    RecordCallLog(sdata, m_service->m_cmd[i]->m_cmd,
                                  "", LOCATE_AND_FOUND_CMD, m_service->m_cmd[i]->m_action);
                    return m_service->m_cmd[i]->m_action;
                }
            }
        } else {
            //处理十六进制命令
            if (m_service->m_cmd[i]->HexToStr(m_service->m_cmd[i]->m_cmd, strlen(m_service->m_cmd[i]->m_cmd))) {
                if (m_service->m_cmd[i]->m_start < 0) {
                    if (m_common.Binstrstr(sdata + hdlen, (const unsigned char *)m_service->m_cmd[i]->m_str,
                                           0, datalen, m_service->m_cmd[i]->m_strlen) == E_COMM_OK) {
                        RecordCallLog(sdata, m_service->m_cmd[i]->m_cmd,
                                      "", SEARCH_AND_FOUND_CMD, m_service->m_cmd[i]->m_action);
                        return m_service->m_cmd[i]->m_action;
                    }
                } else {
                    if (memcmp((const char *)sdata + hdlen + m_service->m_cmd[i]->m_start,
                               m_service->m_cmd[i]->m_str, m_service->m_cmd[i]->m_strlen) == 0) { //找到
                        RecordCallLog(sdata, m_service->m_cmd[i]->m_cmd,
                                      "", LOCATE_AND_FOUND_CMD, m_service->m_cmd[i]->m_action);
                        return m_service->m_cmd[i]->m_action;
                    }
                }
            }

        }
    }
    //RecordCallLog(sdata,"","","",m_service->m_IfExec);
    return m_service->m_IfExec;//
}

bool CTCPNULL::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}
