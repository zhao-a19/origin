/*******************************************************************************************
*文件:  system_status.cpp
*描述:  syslog发送 system_status
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "system_status.h"

enum {
    ID,
    OPTIME,
    LINKNUM,
    CPUINFO,
    DISKINFO,
    MEMINFO,
    NETINFO,
    NETFLOW,
    DEVSTATUS,
    DESCR,
    ISOUT,
};

SYSTEM_STATUS::SYSTEM_STATUS()
{
    SetQuery("select id,optime,link_num,cpu_info,disk_info,mem_info,net_info,net_flow,dev_status,"
             "descr,isout from SYSTEM_STATUS where ifsend=0 or ifsend is null limit 10000");
}

SYSTEM_STATUS::~SYSTEM_STATUS()
{
}

/**
 * [SYSTEM_STATUS::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool SYSTEM_STATUS::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=SYSTEM_STATUS TIME=%s LINKNUM=%s CPU=%s "
                 "DISK=%s MEM=%s NET=%s NETFLOW=%s DEVSTATUS=%s DESCR=%s ISOUT=%s",
                 g_csip, m_row[OPTIME], m_row[LINKNUM], m_row[CPUINFO], m_row[DISKINFO], m_row[MEMINFO],
                 m_row[NETINFO], m_row[NETFLOW], m_row[DEVSTATUS], m_row[DESCR], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [SYSTEM_STATUS::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool SYSTEM_STATUS::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update SYSTEM_STATUS set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
