/*******************************************************************************************
*文件:  syslog.cpp
*描述:  syslog发送 syslog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "syslog.h"

enum {
    ID = 0,
    OPTIME,
    LOGTYPE,
    RESULT,
    REMARK,
    ISOUT
};

SYSLOG::SYSLOG()
{
    SetQuery("select id,optime,logtype,result,remark,isout from SYSLOG where "
             "ifsend=0 or ifsend is null limit 10000");
}

SYSLOG::~SYSLOG()
{
}

/**
 * [SYSLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool SYSLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=System TIME=%s LEVEL=%s RESULT=%s REMARK=%s ISOUT=%s",
                 g_csip, m_row[OPTIME], m_row[LOGTYPE], m_row[RESULT], m_row[REMARK], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [SYSLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool SYSLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update SYSLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

