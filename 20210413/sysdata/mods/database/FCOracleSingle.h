/*******************************************************************************************
*文件:  FCOracleSingle.h
*描述:  ORACLE模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_ORACLE_SINGLE_H__
#define __FC_ORACLE_SINGLE_H__
#include "FCSingle.h"

class CORACLESINGLE : public CSINGLE
{
public:
    CORACLESINGLE();
    ~CORACLESINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
    bool m_redirect;
    char m_SqlOperName[C_MAX_SQLOPERNAMELEN];
    char m_TableName[C_MAX_TABLENAMELEN];
    char m_Sql[C_MAX_SQLLEN];
    char *m_DefSqlOper[C_MAX_SQLOPER];

    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen);
    bool DecodeOper(char *csql, int sqllen, char *coper, char *cpara);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
};

#endif
