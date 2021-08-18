/*******************************************************************************************
*文件:  FCSmtpSingle.cpp
*描述:  smtp模块
*作者:  王君雷
*日期:  2016-05
*修改:
*       管理界面配置的命令MAIL，对应协议命令MAIL FROM
*       管理界面配置的命令AUTH，对应协议命令AUTH LOGIN
*       管理界面配置的命令RCPT，对应协议命令RCPT TO           2016-05-12
*       添加对邮件附件进行过滤                                2016-08-02
*       修改命令匹配中的错误                                  2017-10-30 王君雷

*       添加zlog信息，添加函数说明，增加smtp协议命令           2019-06-13 宋宇
*       可以过滤中文邮件主题                                         2020-08-31 王君雷
*******************************************************************************************/
#include "FCSmtpSingle.h"

#define SMTP_ATTACH "ATTACH"

CSMTPSINGLE::CSMTPSINGLE()
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));
}

CSMTPSINGLE::~CSMTPSINGLE()
{

}
/**
 * [CSMTPSINGLE::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [1为来自源对象 否则来自目的对象]
 * @return           [允许通过返回true]
 */
bool CSMTPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}
/**
 * [CSMTPSINGLE::DoSrcMsg 处理来自源对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSMTPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    PRINT_DBG_HEAD;
    print_dbg("headflag = %d", hdflag);

    if (slen - hdflag <= 0) {
        return true;
    }

    if (!CheckSubject((const char *)sdata + hdflag, slen - hdflag, cherror)) {
        RecordFilterLog(sdata, cherror, KEY_WORD_FORBID);
        return false;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        //printf("ch_cmd:[%s] ch_param[%s]\n",ch_cmd,ch_param);
        if (AnalyseCmdRule(ch_cmd, ch_param, cherror)) {
            if (strcmp(ch_cmd, SMTP_ATTACH) == 0) {
                if (FilterFileType(ch_param, cherror)) {
                } else {

                    PRINT_DBG_HEAD;
                    print_dbg("RecordCallLog false!");

                    RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
                    RecordFilterLog(sdata, rindex((char *)ch_param, '.'), cherror);
                    return false;
                }
            }


            PRINT_DBG_HEAD;
            print_dbg("RecordCallLog true!");

            RecordCallLog(sdata, ch_cmd, ch_param, cherror, true);
            return true;
        } else {

            PRINT_DBG_HEAD;
            print_dbg("RecordCallLog false!");

            RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
            return false;
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("CSMTPSINGLE:DecodeRequest error!");
        //可能是编码后的用户名和密码，或邮件内容  所以应该让通过
        return true;
    }
}
/**
 * [CSMTPSINGLE::DoDstMsg 处理来自目的对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSMTPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}
/**
 * [CSMTPSINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CSMTPSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                //printf("%s[%d]chpara:%s, paramiter:%s\n",
                //    __FUNCTION__, __LINE__,
                //    chpara, m_service->m_cmd[i]->m_parameter);

                if (!(m_service->m_cmd[i]->m_action)) {
                    PRINT_ERR_HEAD;
                    print_err("SMTP_PERM_FORBID");
                    sprintf(cherror, "%s", SMTP_PERM_FORBID);
                }


                PRINT_DBG_HEAD;
                print_dbg("exec Specify action!");

                return m_service->m_cmd[i]->m_action;
            }
        }
    }

    if (!(m_service->m_IfExec)) {
        PRINT_ERR_HEAD;
        print_err("SMTP_PERM_FORBID");
        sprintf(cherror, "%s", SMTP_PERM_FORBID);
    }

    PRINT_DBG_HEAD;
    print_dbg("exec default action!");

    return m_service->m_IfExec;
}
/**
 * [CSMTPSINGLE::DecodeRequest 解析FTP请求命令 参数信息]
 * @param  sdata   [应用层内容开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [解析成功返回true]
 */
bool CSMTPSINGLE::DecodeRequest(unsigned char *data, int datasize, char *error_reason)
{
    bool bret = true;
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));

    if (strncasecmp((const char *)data, "HELO", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "EHLO", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "AUTH LOGIN", 10) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "MAIL FROM", 9) == 0) {
        memcpy(ch_cmd, data, 4);
        char *p = (char *)strchr((const char *)data, '<');
        char *q = (char *)strchr((const char *)data, '>');
        if ((p != NULL) && (q != NULL) && (p < q)) {
            memcpy(ch_param, p + 1, q - p - 1);
        } else {
            strcpy(error_reason, SMTP_PROTO_ERROR);
        }
    } else if (strncasecmp((const char *)data, "RCPT TO", 7) == 0) {
        memcpy(ch_cmd, data, 4);
        char *p = (char *)strchr((const char *)data, '<');
        char *q = (char *)strchr((const char *)data, '>');
        if ((p != NULL) && (q != NULL) && (p < q)) {
            memcpy(ch_param, p + 1, q - p - 1);
        } else {
            strcpy(error_reason, SMTP_PROTO_ERROR);
        }
    } else if (strncasecmp((const char *)data, "QUIT", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "DATA", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "RSET", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "VRFY", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "NOOP", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "ATRN", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "SIZE", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (strncasecmp((const char *)data, "HELP", 4) == 0) {
        memcpy(ch_cmd, data, 4);
    } else if (GetAttachInfo((const char *)data, datasize, ch_param, sizeof(ch_param))) {
        strcpy(ch_cmd, SMTP_ATTACH);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("unknown smtp ch_cmd:%s", data);
        //sprintf(error_reason,SMTP_UNKNOWN_CMD);
        bret = false;
    }

    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("Command = %s", ch_cmd);
    }
    return bret;
}
/**
 * [CSMTPSINGLE::DecodeReply 解析响应信息]
 * @param  sdata [网络层开始的数据包]
 * @param  slen  [数据包长度]
 * @return       [允许通过返回true]
 */
bool CSMTPSINGLE::DecodeReply(unsigned char *sdata, int slen)
{
    return false;
}
