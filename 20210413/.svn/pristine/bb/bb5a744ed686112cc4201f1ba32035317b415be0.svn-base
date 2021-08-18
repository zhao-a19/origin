/*******************************************************************************************
*文件:  secmglog.cpp
*描述:  syslog发送 secmglog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "secmglog.h"

enum {
    ID = 0,
    OPTIME,
    OPUSER,
    LOGTYPE,
    RESULT,
    REMARK
};

SECMGLOG::SECMGLOG()
{
    SetQuery("select id,optime,opuser,logtype,result,remark from SECMGLOG where "
             "ifsend=0 or ifsend is null limit 10000");
}

SECMGLOG::~SECMGLOG()
{
}

/**
 * [SECMGLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool SECMGLOG::MakeLogInfo(void)
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
 * [SECMGLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool SECMGLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update SECMGLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
