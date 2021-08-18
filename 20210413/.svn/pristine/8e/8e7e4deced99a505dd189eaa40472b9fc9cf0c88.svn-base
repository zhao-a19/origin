/*******************************************************************************************
*文件:  calllog.cpp
*描述:  syslog发送 calllog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "calllog.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum {
    ID = 0,
    OPTIME,
    OPUSER,
    SRCIP,
    DSTIP,
    SRCPORT,
    DSTPORT,
    SERVICE,
    CMD,
    PARAM,
    RESULT,
    REMARK,
    ISOUT
};

CALLLOG::CALLLOG()
{
    SetQuery("select id,optime,opuser,srcip,dstip,srcport,dstport,service,cmd,param,"
             "result,remark,isout from CallLOG where ifsend=0 or ifsend is null limit 10000");
}

CALLLOG::~CALLLOG()
{
}

/**
 * [CALLLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool CALLLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=Transmission TIME=%s USER=%s SRC=%s DST=%s "
                 "SPT=%s DPT=%s SERVICE=%s CMD=%s PARAM=%s RESULT=%s REMARK=%s ISOUT=%s",
                 g_csip, m_row[OPTIME], m_row[OPUSER], m_row[SRCIP], m_row[DSTIP],
                 m_row[SRCPORT], m_row[DSTPORT], m_row[SERVICE], m_row[CMD], m_row[PARAM],
                 m_row[RESULT], m_row[REMARK], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [CALLLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool CALLLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update CallLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}
