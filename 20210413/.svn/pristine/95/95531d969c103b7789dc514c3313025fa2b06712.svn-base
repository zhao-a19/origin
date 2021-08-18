/*******************************************************************************************
*文件:  dbsynclog.cpp
*描述:  syslog发送 dbsynclog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "dbsynclog.h"

enum {
    ID,
    OPTIME,
    NAME,
    LOGWAY,
    SRCDB,
    SRCIP,
    DESTDB,
    DESTIP,
    SRCTABLE,
    DESTTABLE,
    REMARK,
};

DBSYNCLOG::DBSYNCLOG()
{
    SetQuery("select id,optime,name,logway,srcdb,srcip,destdb,destip,srctable,desttable,remark "
             "from DBSYNCLOG where ifsend=0 or ifsend is null limit 10000");
}

DBSYNCLOG::~DBSYNCLOG()
{
}

/**
 * [DBSYNCLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool DBSYNCLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=DBSYNC TIME=%s NAME=%s LOGWAY=%s SRCDB=%s "
                 "SRCIP=%s DESTDB=%s DESTIP=%s SRCTABLE=%s DESTTABLE=%s REMARK=%s ",
                 g_csip, m_row[OPTIME], m_row[NAME], m_row[LOGWAY], m_row[SRCDB], m_row[SRCIP],
                 m_row[DESTDB], m_row[DESTIP], m_row[SRCTABLE], m_row[DESTTABLE], m_row[REMARK]);

        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [DBSYNCLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool DBSYNCLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update DBSYNCLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
