/*******************************************************************************************
*文件:  FCSqlServer.h
*描述:  sqlserver数据库访问模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_SQLSERVER_H__
#define __FC_SQLSERVER_H__
#include "FCSingle.h"

class CSQLSERVER : public CSINGLE
{
public:
    CSQLSERVER();
    ~CSQLSERVER();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
    char m_OperName[C_MAX_SQLOPERNAMELEN];
    char m_TableName[C_MAX_TABLENAMELEN];
    char m_sqlstring[C_MAX_SQLLEN];
    char *m_DefSqlOper[C_MAX_SQLOPER];

    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    //bool FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen);
    bool DecodeOper(char *csql, int sqllen, char *cpara);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    void FilterZero(unsigned char *sdata, int slen, int &outlen);
};

#endif
