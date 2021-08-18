/*******************************************************************************************
 *文件:  FCOracleSingle.cpp
 *描述:  ORACLE模块
 *作者:  王君雷
 *日期:  2016-03
 *修改:
 *       使用IPTABLES宏                                                 ------> 2018-08-13
 *       优化一些函数                                                   ------> 2020-10
 ******************************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "FCOracleSingle.h"
#include "FCPeerExecuteCMD.h"
#include "debugout.h"

/* 请求语句首字符串最大查找距离 */
#define MAX_LOOKUP_LEN_REQ            0x200

/* 返回内容首字符串最大查找距离 */
#define MAX_LOOKUP_LEN_RESP           0x80

/* 重定向包最小长度 */
#define MIN_REDIRECT_LEN              0x20

/* tns 头长度 */
#define TNS_HEADER_LEN                8

CORACLESINGLE::CORACLESINGLE()
{
    for (int i = 0; i < C_MAX_SQLOPER; i++) {
        m_DefSqlOper[i] = new char[10];
        memset(m_DefSqlOper[i], 0, 10);
    }
    strcpy(m_DefSqlOper[0], "SELECT");
    strcpy(m_DefSqlOper[1], "INSERT");
    strcpy(m_DefSqlOper[2], "DELETE");
    strcpy(m_DefSqlOper[3], "UPDATE");

    strcpy(m_DefSqlOper[4], "DROP");
    strcpy(m_DefSqlOper[5], "CREATE");
    strcpy(m_DefSqlOper[6], "ALTER");
    strcpy(m_DefSqlOper[7], "GRANT");
    strcpy(m_DefSqlOper[8], "REVOKE");

    strcpy(m_DefSqlOper[9], "COMMIT");
    strcpy(m_DefSqlOper[10], "ROLLBACK");

    m_redirect = false;
}

CORACLESINGLE::~CORACLESINGLE()
{
    DELETE_N(m_DefSqlOper, C_MAX_SQLOPER);
}

/* sdata是包括ip头部的数据包 */
bool CORACLESINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    return (bFromSrc == 1) ? DoSrcMsg(sdata, slen, cherror) : DoDstMsg(sdata, slen, cherror);
}

bool CORACLESINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    bool bflag = true;
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror)) {
        bflag = AnalyseCmdRule(m_SqlOperName, m_TableName, cherror);
        RecordCallLog(sdata, m_SqlOperName, m_TableName, cherror, bflag);
        return bflag;
    } else
        /* 解码失败也让通过 因为可能是用户名密码登陆等 */
        return bflag;
}

/**
 * [is_valid_char  判断是否为合法 sql 字符]
 * @param   data   [待判定字符]
 * @return         [成功返回0, 失败-1]
 */
static int is_valid_char(const unsigned char data)
{
    return isprint(data) || (data == '\r') || (data == '\n') || (data == '\t');
}

/**
 * [DoDstMsg       重定向包处理]
 * @param  sdata   [数据包]
 * @param  slen    [数据包长度]
 * @param  cherror [用于返回出错信息]
 * @return         [解析成功返回true]
 */
bool CORACLESINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    char ip[IP_STR_LEN] = {0};
    char port[PORT_STR_LEN] = {0};
    char chcmd[CMD_BUF_LEN] = {0};
    char cliip[IP_STR_LEN] = {0};

    const char key1[7] = "(host=";
    const char key2[7] = "(port=";
    char *p_beg = NULL;
    char *p_end = NULL;

    int offset = 0;                /* 应用层payload偏移 */
    int len = 0;

    const char *fmt1 = "%s -I FORWARD -s %s -d %s -p tcp "
                       "--dport %s -j NFQUEUE --queue-num %d";

    const char *fmt2 = "%s -I FORWARD -s %s -d %s -p tcp "
                       "--dport %s -j ACCEPT";

    if (g_workflag == WORK_MODE_PROXY) {
        /* 代理模式下这里不处理 */
        return true;
    }

    /* tcp层, ip层头部长度 */
    len = GetHeadLen(sdata);
    if (slen - len <= TNS_HEADER_LEN) {
        /* 解析失败也通过 */
        return true;
    }

    /* ip 层的源ip */
    snprintf(cliip, IP_STR_LEN, "%d.%d.%d.%d", sdata[16], sdata[17], sdata[18], sdata[19]);

    /* 应用层payload */
    sdata += len;
    /* 应用层长度 */
    slen -= len;

    if (!m_redirect) {
        if (sdata[4] == 5) {
            m_redirect = true;

            PRINT_DBG_HEAD
            print_dbg("Redirect pkt is coming!");
        } else {
            /* 重定向的包还没来 */
            return true;
        }
    }

    /* 包类型不是 DATA or Redirect 不处理 */
    if (sdata[4] != 0x05 && sdata[4] != 0x06)
        /* 解析失败也通过 */
        return true;

    /* 跳过tns 头 */
    offset = TNS_HEADER_LEN;

    /*
     * 重定向包很有规律，一长串字符串，但起始偏移位置不好确定，
     * 这里查找3个连续合法字符，作为结束条件。
     */

    /* 最大检索长度 */
    len = slen < MAX_LOOKUP_LEN_RESP ? slen : MAX_LOOKUP_LEN_RESP;
    p_beg = NULL;
    while (offset + 2 < len) {
        if (is_valid_char(sdata[offset])
            && is_valid_char(sdata[offset + 1])
            && is_valid_char(sdata[offset + 2])) {
            p_beg = (char *)sdata + offset;
            break;
        }
        offset += 1;
    }

    if (NULL == p_beg)
        /* 解析失败也通过 */
        return true;

    len = strnlen(p_beg, slen - offset);
    /* 太短 */
    if (len < MIN_REDIRECT_LEN)
        /* 解析失败也通过 */
        return true;

    /* 取重定向服务器ip */
    p_beg = strcasestr(p_beg, key1);
    if (NULL == p_beg)
        /* 解析失败也通过 */
        return true;
    p_beg += 6;
    p_end = strstr(p_beg, ")");
    if (NULL == p_end)
        /* 解析失败也通过 */
        return true;

    len = (p_end - p_beg + 1) < IP_STR_LEN ? (p_end - p_beg + 1) : IP_STR_LEN;
    snprintf(ip, len, "%s", p_beg);

    /* 取重定向服务器port */
    p_beg = p_end + 1;
    p_beg = strcasestr(p_beg, key2);
    if (NULL == p_beg)
        /* 解析失败也通过 */
        return true;
    p_beg += 6;
    p_end = strstr(p_beg, ")");
    if (NULL == p_end)
        /* 解析失败也通过 */
        return true;

    len = (p_end - p_beg + 1) < PORT_STR_LEN ? (p_end - p_beg + 1) : PORT_STR_LEN;
    snprintf(port, len, "%s", p_beg);

    //对于非代理模式，不用改变数据包内容，源端加QUEUE，目的端ACCEPT
    snprintf(chcmd, CMD_BUF_LEN, fmt1, IPTABLES, cliip, ip, port, m_service->GetQueueNum());
    system(chcmd);

    PRINT_DBG_HEAD
    print_dbg("execute cmd : %s", chcmd);

    //要求网闸另一端修改iptables, 放行重定向服务器ip, port
    snprintf(chcmd, CMD_BUF_LEN, fmt2, IPTABLES, cliip, ip, port);
    PeerExecuteCMD(chcmd);

    PRINT_DBG_HEAD
    print_dbg("peer execute cmd : %s", chcmd);

    return true;
}

bool CORACLESINGLE::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    if (slen <= 40) {
        //printf("DecodeRequest:==slen <= 40[%d]\n",slen);
        return false;
    }

    if (sdata[4] != 06)
        //|| sdata[10] != 0x11
        //|| sdata[11] != 0x69
        //|| sdata[18] != 0x03
        //|| sdata[19] != 0x5e) //request
    {
        printf("%s[%d] not request!!!\n", __FUNCTION__, __LINE__);
        return false;
    }

    memset(m_SqlOperName, 0, C_MAX_SQLOPERNAMELEN);
    memset(m_TableName, 0, C_MAX_TABLENAMELEN);
    memset(m_Sql, 0, C_MAX_SQLLEN);

    int sqllen = 0;
    if (!FindSql(sdata, slen, m_Sql, sqllen)) {
        if (g_debug) {
            printf("==FindSql error!\n");
        }
        return false;
    }

    DecodeOper(m_Sql, sqllen, m_SqlOperName, m_TableName);
    //printf("[%s][%s]\n",m_SqlOperName,m_TableName);

    if (strlen(m_SqlOperName) == 0) {
        printf("==m_SqlOperName is null!\n");
        return false;
    }

    if (strcmp(m_SqlOperName, "COMMIT") == 0
        || strcmp(m_SqlOperName, "ROLLBACK") == 0) {
        return true;
    }

    if (strlen(m_TableName) == 0) {
        printf("==m_TableName is null!\n");
        if (strcmp(m_SqlOperName, "CREATE") == 0 ||
            strcmp(m_SqlOperName, "SELECT") == 0) {
            return false;
        }
    }
    return true;
}

/**
 * [FindSql            提取请求语句]
 * @param  sdata       [应用层payload]
 * @param  slen        [payload 长度]
 * @param  sql_comm    [用于返回sql语句]
 * @param  sqllen      [用于返回sql语句长度]
 * @return             [解析成功返回true, 失败false]
 */
bool CORACLESINGLE::FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen)
{
    int offset = 0;
    char *p = NULL;
    int len = 0;
    int i = 0;

    /* 最大检索长度 */
    len = slen < MAX_LOOKUP_LEN_REQ ? slen : MAX_LOOKUP_LEN_REQ;
    p = NULL;
    while (offset + 3 < len) {
        if (isalpha(sdata[offset])
            && isalpha(sdata[offset + 1])
            && isalpha(sdata[offset + 2])
            && isalpha(sdata[offset + 3])) {
            /* 连续4个可显示字符，作为检索结束条件. */
            p = (char *)sdata + offset;
            break;
        }
        offset += 1;
    }

    if (NULL == p)
        return false;

    for (i = 0; i < C_MAX_SQLOPER; i++) {
        if (strncasecmp(p, m_DefSqlOper[i], strlen(m_DefSqlOper[i])) == 0) {
            len = strnlen(p, slen - offset);
            sqllen = len < C_MAX_SQLLEN ? len : (C_MAX_SQLLEN - 1);
            snprintf(sql_com, sqllen + 1, "%s", p);

            PRINT_DBG_HEAD
            print_dbg("offset:[%d], sqllen:[%d], sql:[%s]", offset, sqllen, sql_com);
            return true;
        }
    }

    return false;
}

bool CORACLESINGLE::DecodeOper(char *csql, int sqllen, char *coper, char *cpara)
{
    if (sqllen < 6) {
        return false;
    }

    int tablepos = 0, ppos = 0;
    if (strncasecmp(csql, "select ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n'
            && csql[6] != '*' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "SELECT"); //copy oper

        //
        //SELECT DATABASE()
        //如果有DATABASE()子串
        //
        if (m_common.casestrstr((const unsigned char *)csql,
                                (const unsigned char *)"DATABASE()", 0, sqllen) == E_COMM_OK) {
            strcpy(cpara, "DATABASE()");
            return true;
        }
        for (int j = 7; j < sqllen - 5; j++) {
            if (!strncasecmp(csql + j, "from", 4)) { //search from
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n'
                    && csql[j + 4] != '\t' && csql[j + 4] != '(') {
                    j += 4;
                    continue;
                }
                int k;
                tablepos = j + 4;
                for (k = j + 4; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }

                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "insert ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }

        strcpy(coper, "INSERT"); //copy oper
        for (int j = 7; j < sqllen; j++) {
            if (strncasecmp(csql + j, "into ", 4) == 0) { //search INTO
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r'
                    && csql[j + 4] != '\n' && csql[j + 4] != '\t') {
                    continue;
                }
                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "update ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "UPDATE"); //copy oper

        //把回车换行偏移过去
        int k;
        for (k = 7; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            tablepos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }
        return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
    } else if (strncasecmp(csql, "delete ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "DELETE"); //copy oper
        for (int j = 7; j < sqllen; j++) {
            if (strncasecmp(csql + j, "from ", 4) == 0) { //search from
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r'
                    && csql[j + 4] != '\n' && csql[j + 4] != '\t') {
                    continue;
                }

                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++) {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen) {
                    return false;
                }
                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    } else if (strncasecmp(csql, "create ", 6) == 0) { //e.g. create table tablename(id int);
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "CREATE"); //copy oper

        //跳过table之前的空格回车换行
        tablepos = 7;
        int k;
        for (k = 7; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r'
            && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            //没找到tablename开始的位置
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "drop ", 4) == 0) {
        if (csql[4] != ' ' && csql[4] != '\r' && csql[4] != '\n' && csql[4] != '\t') {
            return false;
        }
        strcpy(coper, "DROP"); //copy oper

        //找table开始的位置
        int k;
        tablepos = 5;
        for (k = 5; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r'
            && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "alter ", 5) == 0) {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t') {
            return false;
        }
        strcpy(coper, "ALTER"); //copy oper

        //找table开始的位置
        tablepos = 6;
        int k;
        for (k = 6; k < sqllen; k++) {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_') {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到table开始的位置
            return false;
        }

        //
        //alter session set PLSQL_DEBUG=true;
        //alter system set log_buffer =655360 scope=both;
        //如果有alter session/system
        //
        if (strncasecmp(csql + tablepos, "session", 7) == 0) {
            strcpy(cpara, "session");
            return true;
        }

        if (strncasecmp(csql + tablepos, "system", 6) == 0) {
            strcpy(cpara, "system");
            return true;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0) {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r'
            && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t') {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "grant ", 5) == 0) {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t') {
            return false;
        }
        strcpy(coper, "GRANT"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++) {
            if (strncasecmp(csql + k, "on", 2) == 0) {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r'
            && csql[tablepos + 2] != '\n' && csql[tablepos + 2] != '\t') {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }
        //grant update on [table] v1 to root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0) {
            ppos += 6;
        }
        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "revoke ", 6) == 0) {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t') {
            return false;
        }
        strcpy(coper, "REVOKE"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++) {
            if (strncasecmp(csql + k, "on", 2) == 0) {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen) {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r'
            && csql[tablepos + 2] != '\n' && csql[tablepos + 2] != '\t') {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++) {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t') {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen) {
            return false;
        }

        //revoke update on [table] v1 from root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0) {
            ppos += 6;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    } else if (strncasecmp(csql, "commit", 6) == 0) {
        strcpy(coper, "COMMIT"); //copy oper
        return true;
    } else if (strncasecmp(csql, "rollback", 8) == 0) {
        strcpy(coper, "ROLLBACK"); //copy oper
        return true;
    }

    return false;
}

bool CORACLESINGLE::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    bool bflag = m_service->m_IfExec;

    PRINT_DBG_HEAD
    print_dbg("begin analyse cmd");

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
        sprintf(cherror, "%s", ORACLE_PERM_FORBID);
    }

    return bflag;
}


