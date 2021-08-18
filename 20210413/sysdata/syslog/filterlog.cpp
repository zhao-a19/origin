/*******************************************************************************************
*文件:  filterlog.cpp
*描述:  syslog发送 filterlog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "filterlog.h"

enum {
    ID,
    OPTIME,
    OPUSER,
    FNAME,
    REMARK,
    ISOUT,
};

FILTERLOG::FILTERLOG()
{
    SetQuery("select id,optime,opuser,fname,remark,isout from FILTERLOG "
             "where ifsend=0 or ifsend is null limit 10000");
}

FILTERLOG::~FILTERLOG()
{
}

/**
 * [FILTERLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool FILTERLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<4>DEVIP=%s Type=Filter TIME=%s USER=%s FNAME=%s REMARK=%s ISOUT=%s",
                 g_csip, m_row[OPTIME], m_row[OPUSER], m_row[FNAME], m_row[REMARK], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [FILTERLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool FILTERLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update FILTERLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
