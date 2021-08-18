/*******************************************************************************************
*文件:  FCFtpSingle.cpp
*描述:  FTP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       后台不再枚举命令                                        ------> 2019-01-16
*       命令兼容大小写                                          ------> 2019-01-21
*       把ftp命令放入容器,获取命令后需要校验（宋宇）               ------> 2019-05-20
*       解析失败时不记录访问日志,防止乱码                          ------> 2020-07-22 wjl
*       ftp命令解析存入哈希表，不再使用轮询方式（宋宇）            ------> 2020-07-27
*******************************************************************************************/
#include "FCFtpSingle.h"
#include "debugout.h"
#include "datatype.h" //for MIN
#include <sys/socket.h>
#include <string>
#include <iostream>

using namespace std;
CFTPSINGLE::CFTPSINGLE(void)
{
    cmd_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
    g_hash_table_insert(cmd_hash_table, strdup("ABOR"), strdup("ABOR"));
    g_hash_table_insert(cmd_hash_table, strdup("NOOP"), strdup("NOOP"));
    g_hash_table_insert(cmd_hash_table, strdup("FEAT"), strdup("FEAT"));
    g_hash_table_insert(cmd_hash_table, strdup("PASV"), strdup("PASV"));
    g_hash_table_insert(cmd_hash_table, strdup("EPSV"), strdup("EPSV"));
    g_hash_table_insert(cmd_hash_table, strdup("PWD"), strdup("PWD"));
    g_hash_table_insert(cmd_hash_table, strdup("XPWD"), strdup("XPWD"));
    g_hash_table_insert(cmd_hash_table, strdup("QUIT"), strdup("QUIT"));
    g_hash_table_insert(cmd_hash_table, strdup("REIN"), strdup("REIN"));
    g_hash_table_insert(cmd_hash_table, strdup("SYST"), strdup("SYST"));
    g_hash_table_insert(cmd_hash_table, strdup("ACCT"), strdup("ACCT"));
    g_hash_table_insert(cmd_hash_table, strdup("ALLO"), strdup("ALLO"));
    g_hash_table_insert(cmd_hash_table, strdup("APPE"), strdup("APPE"));
    g_hash_table_insert(cmd_hash_table, strdup("CDUP"), strdup("CDUP"));
    g_hash_table_insert(cmd_hash_table, strdup("XCUP"), strdup("XCUP"));
    g_hash_table_insert(cmd_hash_table, strdup("CWD"), strdup("CWD"));
    g_hash_table_insert(cmd_hash_table, strdup("XCWD"), strdup("XCWD"));
    g_hash_table_insert(cmd_hash_table, strdup("DELE"), strdup("DELE"));
    g_hash_table_insert(cmd_hash_table, strdup("HELP"), strdup("HELP"));
    g_hash_table_insert(cmd_hash_table, strdup("LIST"), strdup("LIST"));
    g_hash_table_insert(cmd_hash_table, strdup("MODE"), strdup("MODE"));
    g_hash_table_insert(cmd_hash_table, strdup("MKD"), strdup("MKD"));
    g_hash_table_insert(cmd_hash_table, strdup("MDTM"), strdup("MDTM"));
    g_hash_table_insert(cmd_hash_table, strdup("XMKD"), strdup("XMKD"));
    g_hash_table_insert(cmd_hash_table, strdup("NLST"), strdup("NLST"));
    g_hash_table_insert(cmd_hash_table, strdup("PASS"), strdup("PASS"));
    g_hash_table_insert(cmd_hash_table, strdup("PORT"), strdup("PORT"));
    g_hash_table_insert(cmd_hash_table, strdup("PORT"), strdup("PORT"));
    g_hash_table_insert(cmd_hash_table, strdup("REST"), strdup("REST"));
    g_hash_table_insert(cmd_hash_table, strdup("RETR"), strdup("RETR"));
    g_hash_table_insert(cmd_hash_table, strdup("RMD"), strdup("RMD"));
    g_hash_table_insert(cmd_hash_table, strdup("XRMD"), strdup("XRMD"));
    g_hash_table_insert(cmd_hash_table, strdup("RNFR"), strdup("RNFR"));
    g_hash_table_insert(cmd_hash_table, strdup("RNTO"), strdup("RNTO"));
    g_hash_table_insert(cmd_hash_table, strdup("SITE"), strdup("SITE"));
    g_hash_table_insert(cmd_hash_table, strdup("SIZE"), strdup("SIZE"));
    g_hash_table_insert(cmd_hash_table, strdup("SMNT"), strdup("SMNT"));
    g_hash_table_insert(cmd_hash_table, strdup("STAT"), strdup("STAT"));
    g_hash_table_insert(cmd_hash_table, strdup("STOR"), strdup("STOR"));
    g_hash_table_insert(cmd_hash_table, strdup("STOU"), strdup("STOU"));
    g_hash_table_insert(cmd_hash_table, strdup("STRU"), strdup("STRU"));
    g_hash_table_insert(cmd_hash_table, strdup("TYPE"), strdup("TYPE"));
    g_hash_table_insert(cmd_hash_table, strdup("USER"), strdup("USER"));
    g_hash_table_insert(cmd_hash_table, strdup("OPTS"), strdup("OPTS"));
    g_hash_table_insert(cmd_hash_table, strdup("CLNT"), strdup("CLNT"));
    


}

CFTPSINGLE::~CFTPSINGLE(void)
{
    g_hash_table_destroy(cmd_hash_table);
}

/**
 * [CFTPSINGLE::DoMsg 处理数据包]
 * @param  sdata     [IP开头的数据包]
 * @param  slen      [长度]
 * @param  cherror   [出错信息 出参]
 * @param  pktchange [包是否发送改变]
 * @param  bFromSrc  [1为来自源对象 否则来自目的对象]
 * @return           [允许通过返回true]
 */
bool CFTPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

/**
 * [CFTPSINGLE::DoSrcMsg 处理来自源对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CFTPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        if (AnalyseCmdRule(m_cmd, m_para, cherror)) {
            //文件类型过滤
            if ((strcasecmp(m_cmd, "STOR") == 0)
                || (strcasecmp(m_cmd, "APPE") == 0)
                || (strcasecmp(m_cmd, "RETR") == 0)) {

                if (!FilterFileType(m_para, cherror)) {
                    PRINT_ERR_HEAD
                    print_err("ftp filter file type fail.[%s:%s]", m_cmd, m_para);
                    RecordCallLog(sdata, m_cmd, m_para, cherror, false);
                    RecordFilterLog(sdata, rindex((char *)m_para, '.'), cherror);
                    return false;
                }
            }
            RecordCallLog(sdata, m_cmd, m_para, cherror, true);
            return true;
        } else {
            RecordCallLog(sdata, m_cmd, m_para, cherror, false);
            PRINT_ERR_HEAD
            print_err("ftp cmd forbid[%s:%s]", m_cmd, m_para);
            return false;
        }
    } else {
        PRINT_INFO_HEAD
        print_info("ftp decode request fail. exec default action");
        //RecordCallLog(sdata, m_cmd, m_para, cherror, m_service->m_IfExec);
        return m_service->m_IfExec; //解码失败 执行默认动作
    }
}

/**
 * [CFTPSINGLE::DoDstMsg 处理来自目的对象的请求]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CFTPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [CFTPSINGLE::DecodeRequest 解析FTP请求命令 参数信息]
 * @param  sdata   [应用层内容开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [解析成功返回true]
 */
bool CFTPSINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    BZERO(m_cmd);
    BZERO(m_para);
    sdata[slen] = '\0';

    const char *p1 = strstr((const char *)sdata + slen - 2, (const char *)"\r\n");
    if (p1 != NULL) {
        const char *p2 = strchr((const char *)sdata, ' ');
        if (p2 != NULL) {
            int cmdlen = MIN(p2 - (const char *)sdata, (int)sizeof(m_cmd) - 1);
            int paralen = MIN(p1 - p2 - 1, (int)sizeof(m_para) - 1);
            memcpy(m_cmd, sdata, cmdlen);
            memcpy(m_para, p2 + 1, paralen);
        } else {
            int cmdlen = MIN(p1 - (const char *)sdata, (int)sizeof(m_cmd) - 1);
            memcpy(m_cmd, sdata, cmdlen);
        }

        if(g_hash_table_lookup(cmd_hash_table,m_cmd) != NULL){
            return true;
        }

        
        PRINT_ERR_HEAD
        print_err("can not find cmd [%s] ",m_cmd);
        return false;
    } else {
        sscanf((const char *)sdata, "%8s", m_cmd);
        sprintf(cherror, "%s", FTP_0D0A_NOT_FIND);

        PRINT_ERR_HEAD
        print_err("p1 == NULL (%s)", FTP_0D0A_NOT_FIND);
        return false;
    }
#if 0
    if (memcmp(sdata, "ABOR", 4) == 0 ||
        memcmp(sdata, "NOOP", 4) == 0 ||
        memcmp(sdata, "FEAT", 4) == 0 ||
        memcmp(sdata, "PASV", 4) == 0 ||
        memcmp(sdata, "EPSV", 4) == 0 ||
        memcmp(sdata, "PWD", 3) == 0 ||
        memcmp(sdata, "XPWD", 4) == 0 ||
        memcmp(sdata, "QUIT", 4) == 0 ||
        memcmp(sdata, "REIN", 4) == 0 ||
        memcmp(sdata, "SYST", 4) == 0 ||
        memcmp(sdata, "ACCT", 4) == 0 ||
        memcmp(sdata, "ALLO", 4) == 0 ||
        memcmp(sdata, "APPE", 4) == 0 ||
        memcmp(sdata, "CDUP", 4) == 0 ||
        memcmp(sdata, "XCUP", 4) == 0 ||
        memcmp(sdata, "CWD", 3) == 0 ||
        memcmp(sdata, "XCWD", 4) == 0 ||
        memcmp(sdata, "DELE", 4) == 0 ||
        memcmp(sdata, "HELP", 4) == 0 ||
        memcmp(sdata, "LIST", 4) == 0 ||
        memcmp(sdata, "MODE", 4) == 0 ||
        memcmp(sdata, "MKD", 3) == 0 ||
        memcmp(sdata, "MDTM", 4) == 0 ||
        memcmp(sdata, "XMKD", 4) == 0 ||
        memcmp(sdata, "NLST", 4) == 0 ||
        memcmp(sdata, "PASS", 4) == 0 ||
        memcmp(sdata, "PORT", 4) == 0 ||
        memcmp(sdata, "EPRT", 4) == 0 ||
        memcmp(sdata, "REST", 4) == 0 ||
        memcmp(sdata, "RETR", 4) == 0 ||
        memcmp(sdata, "RMD", 3) == 0 ||
        memcmp(sdata, "XRMD", 4) == 0 ||
        memcmp(sdata, "RNFR", 4) == 0 ||
        memcmp(sdata, "RNTO", 4) == 0 ||
        memcmp(sdata, "SITE", 4) == 0 ||
        memcmp(sdata, "SIZE", 4) == 0 ||
        memcmp(sdata, "SMNT", 4) == 0 ||
        memcmp(sdata, "STAT", 4) == 0 ||
        memcmp(sdata, "STOR", 4) == 0 ||
        memcmp(sdata, "STOU", 4) == 0 ||
        memcmp(sdata, "STRU", 4) == 0 ||
        memcmp(sdata, "TYPE", 4) == 0 ||
        memcmp(sdata, "USER", 4) == 0 ||
        memcmp(sdata, "OPTS", 4) == 0 ||
        memcmp(sdata, "CLNT", 4) == 0) {
        const char *p1 = strstr((const char *)sdata, (const char *)"\r\n");
        if (p1 != NULL) {
            const char *p2 = strchr((const char *)sdata, ' ');
            if (p2 != NULL) {
                int cmdlen = (p2 - (const char *)sdata) < (int)sizeof(m_cmd) ? (p2 - (const char *)sdata) : (int)sizeof(m_cmd) - 1;
                int paralen = (p1 - p2 - 1) < (int)sizeof(m_para) ? (p1 - p2 - 1) : (int)sizeof(m_para) - 1;
                memcpy(m_cmd, sdata, cmdlen);
                memcpy(m_para, p2 + 1, paralen);
            } else {
                int cmdlen = (p1 - (const char *)sdata) < (int)sizeof(m_cmd) ? (p1 - (const char *)sdata) : (int)sizeof(m_cmd) - 1;
                memcpy(m_cmd, sdata, cmdlen);
            }
            return true;
        } else {
            sscanf((const char *)sdata, "%s", m_cmd);
            sprintf(cherror, "%s", FTP_0D0A_NOT_FIND);
            return false;
        }
    } else {
        //未识别的命令
        sscanf((const char *)sdata, "%s", m_cmd);
        sprintf(cherror, "%s", FTP_UNKNOWN_CMD);
        printf("FTP**[%s]**\n", sdata);
        return false;
    }
#endif
}

/**
 * [CFTPSINGLE::AnalyseCmdRule 过滤命令]
 * @param  chcmd   [命令]
 * @param  chpara  [参数]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool CFTPSINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
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
        sprintf(cherror, "%s", FTP_PERM_FORBID);
        PRINT_ERR_HEAD
        print_err("ftp cmd forbid[%s:%s]", chcmd, chpara);
    }

    return bflag;
}
