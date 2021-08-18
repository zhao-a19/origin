/*******************************************************************************************
*文件:  linklog.cpp
*描述:  syslog发送 linklog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include  "linklog.h"

enum {
    ID = 0,
    OPTIME,
    SRCIP,
    DESTIP,
    SPORT,
    DPORT,
    REMARK,
    ISOUT
};

LINKLOG::LINKLOG()
{
    SetQuery("select id,optime,srcip,destip,sport,dport,remark,isout from LINKLOG "
             "where ifsend=0 or ifsend is null limit 10000");
}

LINKLOG::~LINKLOG()
{
}

/**
 * [LINKLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool LINKLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<4>DEVIP=%s Type=Link TIME=%s SRC=%s DST=%s SPT=%s DPT=%s REMARK=%s ISOUT=%s",
                 g_csip, m_row[OPTIME], m_row[SRCIP], m_row[DESTIP], m_row[SPORT], m_row[DPORT],
                 m_row[REMARK], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [LINKLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool LINKLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update LINKLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
