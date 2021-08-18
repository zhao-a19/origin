/*******************************************************************************************
*文件:  StartOracleInst.h
*描述:  开启oracle任务实例
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __START_ORCL_INST_H__
#define __START_ORCL_INST_H__

#include <stdio.h>
#include <unistd.h>
#include "FCOracleSingle.h"
#include "FCSysRulesBS.h"

int StartOracleInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno);
void *OracleCliProcess(void *arg);
void *OracleListenThread(void *arg);

//需要传递给线程使用的参数
typedef struct {
    int seqno;
    int infd;
    char tip[IP_STR_LEN];
    char midip[IP_STR_LEN];
    char dip[IP_STR_LEN];
    char tport[PORT_STR_LEN];
    char tredirectport[PORT_STR_LEN];
    int appno;
    CSYSRULES *rule;
    char authname[AUTH_NAME_LEN];
    char m_SqlOperName[C_MAX_SQLOPERNAMELEN];
    char m_TableName[C_MAX_TABLENAMELEN];
    char m_Sql[C_MAX_SQLLEN];
    char m_chcmd[1024];
} OraclePara;

/* 缓存数据包结构体 */
typedef struct  {
    /* data */
    unsigned char *p;
    /* 当前长度 */
    int len;
    /* 缓冲区长度 */
    int buffer_len;
} PktBuff;

bool DecodeRequest(unsigned char *sdata, int slen, char *cherror, OraclePara *ppara);
bool FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen);
bool DecodeOper(const char *csql, int sqllen, char *coper, char *cpara);
bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror, OraclePara *ppara);
void RecordCallLog(OraclePara *ppara, const char *cherror, bool result);
void *redirect_ser_process(void *arg);

#endif
