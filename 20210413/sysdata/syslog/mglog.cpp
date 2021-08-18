/*******************************************************************************************
*文件:  mglog.cpp
*描述:  syslog发送 mglog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "mglog.h"

enum {
    ID = 0,
    OPTIME,
    OPUSER,
    LOGTYPE,
    RESULT,
    REMARK
};

MGLOG::MGLOG()
{
    SetQuery("select id,optime,opuser,logtype,result,remark from MGLOG where "
             "ifsend=0 or ifsend is null limit 10000");
}

MGLOG::~MGLOG()
{
}

/**
 * [MGLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool MGLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=Manage TIME=%s USER=%s EVENT=%s RESULT=%s REMARK=%s",
                 g_csip, m_row[OPTIME], m_row[OPUSER], m_row[LOGTYPE], m_row[RESULT], m_row[REMARK]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [MGLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool MGLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update MGLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

