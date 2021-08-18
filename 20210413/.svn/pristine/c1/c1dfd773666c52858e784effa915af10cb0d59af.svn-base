#include "FCDB2.h"

CDB2::CDB2()
{
    for (int i = 0; i < C_MAX_SQLOPER; i++)
    {
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
}

CDB2::~CDB2()
{
    for (int i = 0; i < C_MAX_SQLOPER; i++)
    {
        delete m_DefSqlOper[i];
        m_DefSqlOper[i] = NULL;
    }
}

//sdata是包括ip头部的数据包
bool CDB2::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CDB2::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    //printf("==hdflag=%d,slen:%d\n",hdflag,slen);

    if (slen - hdflag <= 110)
    {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag, cherror))
    {
        if (AnalyseCmdRule(m_SqlOperName, m_TableName, cherror))
        {
            //printf("RecordCallLog true!--\n");
            RecordCallLog(sdata, m_SqlOperName, m_TableName, cherror, true);
            return true;
        }
        else
        {
            //printf("RecordCallLog false!--\n");
            RecordCallLog(sdata, m_SqlOperName, m_TableName, cherror, false);
            return false;
        }
    }
    else
    {
        return true;//解码失败也让通过 因为可能是用户名密码登陆等
    }
}

bool CDB2::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

bool CDB2::DecodeRequest(unsigned char *sdata, int slen, char *cherror)
{
    memset(m_SqlOperName, 0, C_MAX_SQLOPERNAMELEN);
    memset(m_TableName, 0, C_MAX_TABLENAMELEN);
    memset(m_Sql, 0, C_MAX_SQLLEN);

    int sqllen = 0;

    if (!FindSql(sdata, slen, m_Sql, sqllen))
    {
        if (g_debug)
        {
            printf("==FindSql error!\n");
        }
        return false;
    }

    DecodeOper(m_Sql, sqllen, m_SqlOperName, m_TableName);
    //printf("[%s][%s]\n",m_SqlOperName,m_TableName);

    if (strlen(m_SqlOperName) == 0)
    {
        printf("==m_SqlOperName is null!\n");
        return false;
    }

    if (strcmp(m_SqlOperName, "COMMIT") == 0
            || strcmp(m_SqlOperName, "ROLLBACK") == 0)
    {
        return true;
    }

    if (strlen(m_TableName) == 0)
    {
        printf("==m_TableName is null!\n");
        if (strcmp(m_SqlOperName, "CREATE") == 0 ||
                strcmp(m_SqlOperName, "SELECT") == 0)
        {
            return false;
        }
    }

    return true;
}

bool CDB2::FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen)
{
    //必须外部循环为sql语句,内部循环为sql操作符,不能改变
    for (int i = 0; i < slen; i++)
    {
        for (int j = 0; j < C_MAX_SQLOPER; j++)
        {
            if (strncasecmp((char *)(sdata + i), (char *)m_DefSqlOper[j], strlen(m_DefSqlOper[j])) == 0)
            {
                //已经查到了sqloper偏移量
                if (slen - i < C_MAX_SQLLEN)
                {
                    memcpy(sql_com, sdata + i, slen - i);
                    sqllen = slen - i;
                }
                else
                {
                    memcpy(sql_com, sdata + i, C_MAX_SQLLEN - 1);
                    sqllen = C_MAX_SQLLEN - 1;
                }
                if (g_debug)
                {
                    printf("==sql:%s\n", sql_com);
                }
                return true;
            }
        }
    }
    return false;


}

bool CDB2::DecodeOper(char *csql, int sqllen, char *coper, char *cpara)
{
    if (sqllen < 6)
    {
        return false;
    }

    int tablepos = 0, ppos = 0;
    if (strncasecmp(csql, "select ", 6) == 0)
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '*' && csql[6] != '\t')
        {
            return false;
        }
        strcpy(coper, "SELECT"); //copy oper

        //
        //SELECT DATABASE()
        //如果有DATABASE()子串
        //
        if (m_common.casestrstr((const unsigned char *)csql,
                               (const unsigned char *)"DATABASE()", 0, sqllen) == E_COMM_OK)
        {
            strcpy(cpara, "DATABASE()");
            return true;
        }
        for (int j = 7; j < sqllen - 5; j++)
        {
            if (!strncasecmp(csql + j, "from", 4)) //search from
            {
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n' && csql[j + 4] != '\t' && csql[j + 4] != '(')
                {
                    j += 4;
                    continue;
                }
                int k;
                tablepos = j + 4;
                for (k = j + 4; k < sqllen; k++)
                {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
                    {
                        continue;
                    }

                    tablepos = k;
                    break;
                }
                if (k >= sqllen)
                {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    }
    else if (strncasecmp(csql, "insert ", 6) == 0)
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t')
        {
            return false;
        }

        strcpy(coper, "INSERT"); //copy oper
        for (int j = 7; j < sqllen; j++)
        {
            if (strncasecmp(csql + j, "into ", 4) == 0) //search INTO
            {
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n' && csql[j + 4] != '\t')
                {
                    continue;
                }
                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++)
                {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
                    {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen)
                {
                    return false;
                }

                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    }
    else if (strncasecmp(csql, "update ", 6) == 0)
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t')
        {
            return false;
        }
        strcpy(coper, "UPDATE"); //copy oper

        //把回车换行偏移过去
        int k;
        for (k = 7; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            tablepos = k;
            break;
        }
        if (k >= sqllen)
        {
            return false;
        }
        return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
    }
    else if (strncasecmp(csql, "delete ", 6) == 0)
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t')
        {
            return false;
        }
        strcpy(coper, "DELETE"); //copy oper
        for (int j = 7; j < sqllen; j++)
        {
            if (strncasecmp(csql + j, "from ", 4) == 0) //search from
            {
                if (csql[j + 4] != ' ' && csql[j + 4] != '\r' && csql[j + 4] != '\n' && csql[j + 4] != '\t')
                {
                    continue;
                }

                tablepos = j + 5;
                int k;
                for (k = j + 5; k < sqllen; k++)
                {
                    if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
                    {
                        continue;
                    }
                    tablepos = k;
                    break;
                }
                if (k >= sqllen)
                {
                    return false;
                }
                return GetTableName(csql + tablepos, sqllen - tablepos, cpara);
            }
        }
    }
    else if (strncasecmp(csql, "create ", 6) == 0) //e.g. create table tablename(id int);
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t')
        {
            return false;
        }
        strcpy(coper, "CREATE"); //copy oper

        //跳过table之前的空格回车换行
        tablepos = 7;
        int k;
        for (k = 7; k < sqllen; k++)
        {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_')
            {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen)
        {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0)
        {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t')
        {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen)
        {
            //没找到tablename开始的位置
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    }
    else if (strncasecmp(csql, "drop ", 4) == 0)
    {
        if (csql[4] != ' ' && csql[4] != '\r' && csql[4] != '\n' && csql[4] != '\t')
        {
            return false;
        }
        strcpy(coper, "DROP"); //copy oper

        //找table开始的位置
        int k;
        tablepos = 5;
        for (k = 5; k < sqllen; k++)
        {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_')
            {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen)
        {
            //没找到table开始的位置
            return false;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0)
        {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t')
        {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen)
        {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    }
    else if (strncasecmp(csql, "alter ", 5) == 0)
    {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t')
        {
            return false;
        }
        strcpy(coper, "ALTER"); //copy oper

        //找table开始的位置
        tablepos = 6;
        int k;
        for (k = 6; k < sqllen; k++)
        {
            if (isalpha(csql[k]) || isdigit(csql[k]) || csql[k] == '_')
            {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen)
        {
            //没找到table开始的位置
            return false;
        }

        //
        //alter session set PLSQL_DEBUG=true;
        //alter system set log_buffer =655360 scope=both;
        //如果有alter session/system
        //
        if (strncasecmp(csql + tablepos, "session", 7) == 0)
        {
            strcpy(cpara, "session");
            return true;
        }

        if (strncasecmp(csql + tablepos, "system", 6) == 0)
        {
            strcpy(cpara, "system");
            return true;
        }

        //sql语句出错
        if (strncasecmp(csql + tablepos, "table", 5) != 0)
        {
            return false;
        }

        //table之后不是空格 或回车 或换行
        if (csql[tablepos + 5] != ' ' && csql[tablepos + 5] != '\r' && csql[tablepos + 5] != '\n' && csql[tablepos + 5] != '\t')
        {
            return false;
        }

        //把table之后的回车换行空格偏移过去
        for (k = tablepos + 5; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen)
        {
            return false;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    }
    else if (strncasecmp(csql, "grant ", 5) == 0)
    {
        if (csql[5] != ' ' && csql[5] != '\r' && csql[5] != '\n' && csql[5] != '\t')
        {
            return false;
        }
        strcpy(coper, "GRANT"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++)
        {
            if (strncasecmp(csql + k, "on", 2) == 0)
            {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen)
        {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r' && csql[tablepos + 2] != '\n' && csql[tablepos + 2] != '\t')
        {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen)
        {
            return false;
        }
        //grant update on [table] v1 to root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0)
        {
            ppos += 6;
        }
        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    }
    else if (strncasecmp(csql, "revoke ", 6) == 0)
    {
        if (csql[6] != ' ' && csql[6] != '\r' && csql[6] != '\n' && csql[6] != '\t')
        {
            return false;
        }
        strcpy(coper, "REVOKE"); //copy oper

        tablepos = 6;
        int k;
        //找on开始的位置
        for (k = tablepos; k < sqllen; k++)
        {
            if (strncasecmp(csql + k, "on", 2) == 0)
            {
                tablepos = k;
                break;
            }
        }
        if (k >= sqllen)
        {
            //没找到on开始的位置
            return false;
        }

        //on之后不是空格 或回车 或换行
        if (csql[tablepos + 2] != ' ' && csql[tablepos + 2] != '\r' && csql[tablepos + 2] != '\n' && csql[tablepos + 2] != '\t')
        {
            return false;
        }

        //把on之后的回车换行空格偏移过去
        for (k = tablepos + 2; k < sqllen; k++)
        {
            if (csql[k] == ' ' || csql[k] == '\r' || csql[k] == '\n' || csql[k] == '\t')
            {
                continue;
            }
            ppos = k;
            break;
        }
        if (k >= sqllen)
        {
            return false;
        }

        //revoke update on [table] v1 from root@"%";
        //如果有可选的table 则偏移过去
        if (strncasecmp(csql + ppos, "table ", 6) == 0)
        {
            ppos += 6;
        }

        return GetTableName(csql + ppos, sqllen - ppos, cpara);
    }
    else if (strncasecmp(csql, "commit", 6) == 0)
    {
        strcpy(coper, "COMMIT"); //copy oper
        return true;
    }
    else if (strncasecmp(csql, "rollback", 8) == 0)
    {
        strcpy(coper, "ROLLBACK"); //copy oper
        return true;
    }

    return false;
}

bool CDB2::AnalyseCmdRule(char *chcmd, char *chpara, char *cherror)
{
    if (g_debug)
    {
        printf("==AnalyseCmdRule [%s] [%s]\n", chcmd, chpara);
    }

    for (int i = 0; i < m_service->m_cmdnum; i++)
    {
        if (strcasecmp(chcmd, m_service->m_cmd[i]->m_cmd) == 0)
        {
            printf("==find chcmd==\n");
            if (m_common.casestrstr((const unsigned char *)chpara,
                                   (const unsigned char *)m_service->m_cmd[i]->m_parameter, 0,
                                   strlen(chpara)) == E_COMM_OK)
            {
                if (!(m_service->m_cmd[i]->m_action))
                {
                    printf("==DB2_PERM_FORBID==\n");
                    sprintf(cherror, "%s", DB2_PERM_FORBID);
                }

                //printf("==exec Specify action!==\n");
                return m_service->m_cmd[i]->m_action;
            }
        }
    }

    if (!(m_service->m_IfExec))
    {
        printf("==DB2_PERM_FORBID==\n");
        sprintf(cherror, "%s", DB2_PERM_FORBID);
    }

    //printf("==exec default action!==\n");
    return m_service->m_IfExec;
}
