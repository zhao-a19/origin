/*******************************************************************************************
*文件:  filesynclog.cpp
*描述:  syslog发送 filesynclog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*       select查询添加limit条数限制                                  ------> 2019-07-10
*******************************************************************************************/
#include "filesynclog.h"

enum {
    ID,
    OPTIME,
    TASKID,
    SPATH,
    FILENAME,
    RESULT,
    REMARK,
    ISOUT,
};

FILESYNCLOG::FILESYNCLOG()
{
    SetQuery("select id,optime,task_id,s_path,filename,result,remark,isout "
             "from FileSyncLOG where ifsend=0 or ifsend is null limit 10000");
}

FILESYNCLOG::~FILESYNCLOG()
{
}

/**
 * [FILESYNCLOG::MakeLogInfo 组装syslog语句]
 * @return  [成功返回true]
 */
bool FILESYNCLOG::MakeLogInfo(void)
{
    if (m_b_initok && (m_row != NULL)) {
        snprintf(m_loginfo, sizeof(m_loginfo),
                 "<5>DEVIP=%s Type=FileSync TIME=%s TASKID=%s SPATH=%s FILENAME=%s "
                 "RESULT=%s REMARK=%s ISOUT=%s", g_csip, m_row[OPTIME], m_row[TASKID],
                 m_row[SPATH], m_row[FILENAME], m_row[RESULT], m_row[REMARK], m_row[ISOUT]);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("make loginfo fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

/**
 * [FILESYNCLOG::MakeUpdateSql 制作更新语句]
 * @return  [成功返回true]
 */
bool FILESYNCLOG::MakeUpdateSql(void)
{
    if (m_b_initok && (m_row != NULL)) {
        sprintf(m_updatestr, "update FileSyncLOG set ifsend=1 where id=%s", m_row[ID]);
        return true;
    }

    PRINT_ERR_HEAD
    print_err("make update sql fail. initok[%s]", m_b_initok ? "ok" : "not");
    return false;
}

