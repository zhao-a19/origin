/*******************************************************************************************
*文件:  FCPop3Single.cpp
*描述:  pop3模块
*作者:  王君雷
*日期:  2016-08
*修改:
*       添加对邮件附件进行过滤                                       2016-08-02
*       可以过滤中文邮件主题                                         2020-08-31
*******************************************************************************************/
#include "FCPop3Single.h"
#include "debugout.h"

#define POP3_ATTACH "ATTACH"

CPOP3SINGLE::CPOP3SINGLE()
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));
}

CPOP3SINGLE::~CPOP3SINGLE()
{

}

bool CPOP3SINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CPOP3SINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {

        if (AnalyseCmdRule(ch_cmd, ch_param, cherror)) {
            PRINT_DBG_HEAD
            print_dbg("record call log[%s][%s]", ch_cmd, ch_param);
            RecordCallLog(sdata, ch_cmd, ch_param, cherror, true);
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("record call log[%s][%s]", ch_cmd, ch_param);
            RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
            return false;
        }
    } else {
        return m_service->m_IfExec;
    }
}

bool CPOP3SINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (!CheckSubject((const char *)sdata + hdflag, slen - hdflag, cherror)) {
        RecordFilterLog(sdata, cherror, KEY_WORD_FORBID);
        return false;
    }

    if (GetAttachInfo((const char *)sdata + hdflag, slen - hdflag, ch_param, sizeof(ch_param))) {
        strcpy(ch_cmd, POP3_ATTACH);

        if (AnalyseCmdRule(ch_cmd, ch_param, cherror)) {
            if (FilterFileType(ch_param, cherror)) {
                PRINT_DBG_HEAD
                print_dbg("record call log[%s][%s]", ch_cmd, ch_param);
                RecordCallLog(sdata, ch_cmd, ch_param, cherror, true);
                return true;
            } else {
                PRINT_ERR_HEAD
                print_err("record call log[%s][%s]", ch_cmd, ch_param);
                RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
                RecordFilterLog(sdata, rindex((char *)ch_param, '.'), cherror);
                return false;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("record call log[%s][%s]", ch_cmd, ch_param);
            RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
            return false;
        }
    }

    return true;
}

bool CPOP3SINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                if (!(m_service->m_cmd[i]->m_action)) {
                    sprintf(cherror, "%s", POP3_PERM_FORBID);
                }
                return m_service->m_cmd[i]->m_action;
            }
        }
    }

    if (!(m_service->m_IfExec)) {
        sprintf(cherror, "%s", POP3_PERM_FORBID);
    }
    return m_service->m_IfExec;
}

bool CPOP3SINGLE::DecodeRequest(unsigned char *data, int datasize, char *error_reason)
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));

    if (memcmp(data, "USER", 4) == 0) {
        sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        return true;
    } else if (memcmp(data, "PASS", 4) == 0) {
        sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        return true;
    } else if (memcmp(data, "QUIT", 4) == 0) {
        sscanf((const char *)data, "%s", ch_cmd);
        return true;
    } else if (memcmp(data, "STAT", 4) == 0) {
        sscanf((const char *)data, "%s", ch_cmd);
        return true;
    } else if (memcmp(data, "LIST", 4) == 0) {
        //printf("data[LIST:%s] datasize:%d,%d\n",data,datasize,strlen((const char*)data));
        if (datasize <= 6) { //为6时说明没带参数
            sscanf((const char *)data, "%s", ch_cmd);
        } else {
            sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        }
        return true;
    } else if (memcmp(data, "RETR", 4) == 0) {
        if (datasize <= 6) { //为6时说明没带参数
            sscanf((const char *)data, "%s", ch_cmd);
        } else {
            sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        }
        return true;
    } else if (memcmp(data, "DELE", 4) == 0) {
        if (datasize <= 6) { //为6时说明没带参数
            sscanf((const char *)data, "%s", ch_cmd);
        } else {
            sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        }
        return true;
    } else if (memcmp(data, "NOOP", 4) == 0) {
        sscanf((const char *)data, "%s", ch_cmd);
        return true;
    } else if (memcmp(data, "RSET", 4) == 0) {
        sscanf((const char *)data, "%s", ch_cmd);
        return true;
    } else if (memcmp(data, "APOP", 4) == 0) {
        char name[60] = {0};
        char md5[60] = {0};
        sscanf((const char *)data, "%s%s%s", ch_cmd, name, md5);
        sprintf(ch_param, "%s %s", name, md5);
        return true;
    } else if (memcmp(data, "TOP", 3) == 0) {
        char msg[20] = {0};
        char n[20] = {0};
        sscanf((const char *)data, "%s%s%s", ch_cmd, msg, n);
        sprintf(ch_param, "%s %s", msg, n);
        return true;
    } else if (memcmp(data, "UIDL", 4) == 0) {
        if (datasize <= 6) { //为6时说明没带参数
            sscanf((const char *)data, "%s", ch_cmd);
        } else {
            sscanf((const char *)data, "%s%s", ch_cmd, ch_param);
        }
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("unknown pop3 cmd");
        sprintf(error_reason, "%s", POP3_UNKNOWN_CMD);
        return false;
    }
}

bool CPOP3SINGLE::DecodeReply(unsigned char *sdata, int slen)
{
    return false;
}
