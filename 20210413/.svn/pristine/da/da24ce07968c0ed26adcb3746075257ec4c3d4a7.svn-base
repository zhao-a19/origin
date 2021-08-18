/*******************************************************************************************
*文件:  FCXMPP.cpp
*描述:  XMPP模块
*作者:  王君雷
*日期:  2020-08-17
*修改:          添加xmpp过滤逻辑             2020-09-14
*******************************************************************************************/
#include "FCXMPP.h"
#include <string.h>

static const struct _filter {
    char *cmd;
    char *param[XMPP_PLATFORM];
    uint type;
} filtermode[] = {
    {"presence", {"status", NULL}, FCXMPP_STATUS},
    {"presence", {"type=\"", NULL}, FCXMPP_TYPE},
    {"message", {"<body", "<name>MsgText</name><value", NULL}, FCXMPP_MESSAGE},
    {"iq", {NULL}, 0}
};
static char *xmpp_get_param(pchar param, uint32 type, pchar buff, pchar type_str);
static int xmpp_check_file(pchar buff, bool f_t, int32 len);

CXMPP::CXMPP(void)
{
    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));
}

CXMPP::~CXMPP(void)
{
}

/**
 * [CXMPP::DoMsg 处理请求数据]
 * @param  sdata     [网络层开头的数据包]
 * @param  slen      [数据包长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [是否改变包内容了]
 * @param  bFromSrc  [是否来自客户端]
 * @return           [允许通过返回true]
 */
bool CXMPP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

/**
 * [CXMPP::DoSrcMsg 处理客户端请求信息]
 * @param  sdata   [网络层开头的数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CXMPP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    int datalen = slen - hdflag;
    if (datalen <= 0) {
        return true;
    }

    memset(ch_cmd, 0, sizeof(ch_cmd));
    memset(ch_param, 0, sizeof(ch_param));

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        if (!AnalyseCmdRule(ch_cmd, ch_param, cherror)) {

            RecordCallLog(sdata, ch_cmd, ch_param, cherror, false);
            PRINT_INFO_HEAD
            print_info("xmpp filter info faild :%s", cherror);
            return false;
        }
        if (ch_param[0] != '\0')
            RecordCallLog(sdata, ch_cmd, "", cherror, true);
    } else {
        return m_service->m_IfExec;
    }
    return true;
}

/**
 * [CXMPP::DoDstMsg 处理服务器响应信息]
 * @param  sdata   [网络层开头的数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CXMPP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    int datalen = slen - hdflag;
    if (datalen <= 0) {
        return true;
    }

    int is_xmpp_file = xmpp_check_file((char *)sdata + hdflag, false, slen - hdflag);
    if (is_xmpp_file == XMPP_FILE_SUCCESS) {
        RecordCallLog(sdata, "", "", "", true);
    } else if (is_xmpp_file == XMPP_FILE_FAILD) {
        RecordCallLog(sdata, "", "", "", false);
    }

    return true;
}
/**
 * [DecodeRequest 过滤信息解析]
 * @param  sdata   [网络层开头的数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [出错信息 出参]
 * @return        [有过滤参数返回true]
 */
bool CXMPP::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    bool status = false;
    if (sdata[0] == '<') {//报文开头

        for (int i = 0; i < sizeof(filtermode) / sizeof(struct _filter); i++) { //获取命令值
            char *tmp_s = NULL;
            tmp_s = strstr((pchar)sdata, filtermode[i].cmd);
            if (tmp_s != NULL) {
                memcpy(ch_cmd, filtermode[i].cmd, strlen(filtermode[i].cmd));
                int j = 0;
                while (filtermode[i].param[j] != NULL && (j < XMPP_PLATFORM)) {
                    tmp_s = strstr((pchar)sdata, filtermode[i].param[j]);
                    PRINT_DBG_HEAD
                    print_dbg("xmpp DecodeRequest param :%s", filtermode[i].param[j]);
                    if (tmp_s != NULL) {
                        xmpp_get_param(ch_param, filtermode[i].type, tmp_s, filtermode[i].param[j]);
                    }
                    j++;
                }
                status = true;
                break;
            }
        }
    }
    PRINT_DBG_HEAD
    print_dbg("xmpp DecodeRequest param:cmd[%s:%s]", ch_param, ch_cmd);
    return status;
}
/**
 * [AnalyseCmdRule 过滤命令参数]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CXMPP::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    PRINT_DBG_HEAD
    print_dbg("xmpp AnalyseCmdRule cmd[%s] para[%s]", chcmd, chpara);

    bool bflag = m_service->m_IfExec;

    for (int i = 0; i < m_service->m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0) {
            if (m_common.casestrstr((const unsigned char *)chpara,
                                    (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                    strlen(chpara)) == E_COMM_OK) {
                bflag = m_service->m_cmd[i]->m_action;
                break;
            }
        }

        PRINT_DBG_HEAD
        print_dbg("xmpp AnalyseCmdRule analyse cmd[%s] para[%s] para2[%s]", m_service->m_cmd[i]->m_cmd, m_service->m_cmd[i]->m_parameter, m_service->m_cmd[i]->m_sign);
    }
    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("xmpp AnalyseCmdRule analyse cmd result, forbid[%s:%s]", chcmd, chpara);
        sprintf(cherror, "%s", XMPP_PERM_FORBID);
    }
    return bflag;
}
/**
 * [xmpp_get_param 写过滤参数]
 * @param  param   [过滤参数]
 * @param  type    [解析参数类型]
 * @param  buff    [报文信息]
 * @param  type_str [参数类型字符串]
 */
static char *xmpp_get_param(pchar param, uint32 type, pchar buff, pchar type_str)
{
    pchar tmp_s = NULL, tmp_e = NULL;
    uint32 len = 0;
    switch (type) {
    case FCXMPP_STATUS:
        memcpy(param, type_str, strlen(type_str));
        break;
    case FCXMPP_TYPE:
        if (buff != NULL) {
            tmp_s = strstr(buff +  strlen(type_str), "\"");
            if (tmp_s != NULL) {
                len = tmp_s - buff - strlen(type_str);
                if (len > MAX_PARA_NAME_LEN) {
                    len = MAX_PARA_NAME_LEN - 1;
                }
                memcpy(param, buff + strlen(type_str), len);
            }
        }
        break;
    case FCXMPP_MESSAGE:
        if (buff != NULL) {
            tmp_s = strstr(buff +  strlen(type_str), ">");

            if (tmp_s != NULL) {
                tmp_e = strstr(tmp_s, "</");
                if (tmp_e != NULL) {
                    len = tmp_e - tmp_s - strlen(">");
                    if (len > MAX_PARA_NAME_LEN) {
                        len = MAX_PARA_NAME_LEN - 1;
                    }
                    memcpy(param, tmp_s + strlen(">"), len);
                }
            }
        }
        break;

    default:
        break;
    }
    return param;
}
/**
 * [xmpp_check_file 读取传输文件参数]
 * @param  buff [数据报文]
 * @param  f_t [源/目的]
 * @param  len [接受数据包长度，判断是否为验证文件唯一标识长度]
 * 返回值 1失败 0 成功 -1不做处理
 */
static int xmpp_check_file(pchar buff, bool f_t, int32 len)
{
    int is_xmpp_file = XMPP_NOT_FILE;
    if (len != 47)
        return is_xmpp_file;
    if (f_t) {
        if (buff[0] == 0x05 && buff[1] == 0x01 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
            is_xmpp_file = XMPP_FILE_SUCCESS;
        }
        PRINT_DBG_HEAD
        print_dbg("xmpp xmpp_check_file from success");
    } else {
        if (buff[0] == 0x05 && buff[1] == 0x00 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
            is_xmpp_file = XMPP_FILE_SUCCESS;
        } else if (buff[0] == 0x05 && buff[1] != 0x00 && buff[2] == 0x00 && buff[3] == 0x03 && buff[4] == 0x28) {
            is_xmpp_file = XMPP_FILE_FAILD;
        }
        PRINT_DBG_HEAD
        print_dbg("xmpp xmpp_check_file to success");
    }
    return is_xmpp_file;
}