/*******************************************************************************************
*文件:  syslog_manager.cpp
*描述:  syslog发送管理者
*作者:  王君雷
*日期:  2019-06-29
*修改:
*******************************************************************************************/
#include "syslog_manager.h"
#include "FCBSTX.h"

#include "syslog.h"
#include "mglog.h"
#include "secmglog.h"
#include "calllog.h"
#include "linklog.h"
#include "filterlog.h"
#include "filesynclog.h"
#include "dbsynclog.h"
#include "system_status.h"

#define SYS_LOG_CYCLE         1  //内网发送syslog的扫描周期s
static CBSUdpSockClient m_send;

//--------------------------------------------------------------------------------------------------
LOGOBJ::LOGOBJ()
{
    memset(m_condquery, 0, sizeof(m_condquery));
    memset(m_loginfo, 0, sizeof(m_loginfo));
    memset(m_updatestr, 0, sizeof(m_updatestr));

    m_b_initok = false;
    m_res = NULL;
}

LOGOBJ::~LOGOBJ()
{
    if (m_res != NULL) {
        mysql_free_result(m_res);
        m_res = NULL;
    }

    if (m_b_initok) {
        mysql_close(&m_query);
        m_b_initok = false;
    }
}

/**
 * [LOGOBJ::SetQuery 设置select查询语句]
 * @param  querystr [select语句]
 * @return          [成功返回true]
 */
bool LOGOBJ::SetQuery(const char *querystr)
{
    if ((querystr != NULL) && (strlen(querystr) < sizeof(m_condquery))) {
        strcpy(m_condquery, querystr);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("set query fail[%s]", querystr);
    return false;
}

/**
 * [LOGOBJ::Init 初始化连接mysql]
 * @return  [成功返回true]
 */
bool LOGOBJ::Init(void)
{
    if (!m_b_initok) {
        int ret = mysql_init_connect(&m_query);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("mysql init fail");
            return false;
        }
        m_b_initok = true;
        PRINT_DBG_HEAD
        print_dbg("mysql init ok");
    }
    return true;
}

/**
 * [LOGOBJ::Query 执行查询操作]
 * @return  [成功返回true]
 */
bool LOGOBJ::Query(void)
{
    if (!m_b_initok) {
        Init();
    }

    if (m_b_initok) {
        if (mysql_query(&m_query, m_condquery) != 0) {
            PRINT_ERR_HEAD
            print_err("mysql query fail[%s][%s]", m_condquery, mysql_error(&m_query));
            mysql_close(&m_query);
            m_b_initok = false;
        } else {

            if (m_res != NULL) {
                mysql_free_result(m_res);
                m_res = NULL;
            }

            m_res = mysql_store_result(&m_query);
            if (m_res == NULL) {
                PRINT_ERR_HEAD
                print_err("mysql store result fail[%s][%s]", m_condquery, mysql_error(&m_query));
                mysql_close(&m_query);
                m_b_initok = false;
            } else {
                return true;
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("mysql query fail");
    return false;
}

/**
 * [LOGOBJ::GetNextRow 获取下一行]
 * @return  [成功返回true 当查询结果中已经不存在下一行时返回false 返回false并不意味着是错误]
 */
bool LOGOBJ::GetNextRow(void)
{
    if (m_b_initok && (m_res != NULL)) {
        m_row = mysql_fetch_row(m_res);
        if (m_row != NULL) {
            return true;
        } else {
            mysql_free_result(m_res);
            m_res = NULL;
        }
    }
    return false;
}

/**
 * [LOGOBJ::DoWithOneRecord 处理一条记录]
 * @return  [成功返回true]
 */
bool LOGOBJ::DoWithOneRecord(void)
{
    return (MakeLogInfo() && MakeUpdateSql() && SendLog() && UpdateLog());
}

/**
 * [LOGOBJ::SendLog 发送syslog]
 * @return  [成功返回true]
 */
bool LOGOBJ::SendLog(void)
{
    if (m_send.Send((unsigned char *)m_loginfo, strlen(m_loginfo)) <= 0) {
        PRINT_ERR_HEAD
        print_err("send syslog fail[%s]", m_loginfo);
        return false;
    }
    return true;
}

/**
 * [LOGOBJ::UpdateLog 更新一条记录]
 * @return  [成功返回true]
 */
bool LOGOBJ::UpdateLog(void)
{
    if (m_b_initok && (strlen(m_updatestr) > 0)) {
        if (mysql_query(&m_query, m_updatestr) != 0) {
            PRINT_ERR_HEAD
            print_err("update sql exec fail[%s]", m_updatestr);

            mysql_close(&m_query);
            m_b_initok = false;
        } else {
            return true;
        }
    }
    return false;
}
//--------------------------------------------------------------------------------------------------
SYSLOG_MAN::SYSLOG_MAN()
{
    m_list.clear();
}

SYSLOG_MAN::~SYSLOG_MAN()
{
}

/**
 * [SYSLOG_MAN::Add 添加]
 * @param plog [待加入的对象指针]
 */
void SYSLOG_MAN::Add(LOGOBJ *plog)
{
    if (plog != NULL) {
        m_list.push_back(plog);
        PRINT_DBG_HEAD
        print_dbg("add logobj ok");
    } else {
        PRINT_ERR_HEAD
        print_err("syslog manager add logobj fail.para null");
    }
}

/**
 * [SYSLOG_MAN::Remove 去除]
 * @param plog [待去除的对象指针]
 */
void SYSLOG_MAN::Remove(LOGOBJ *plog)
{
    if (plog != NULL) {
        m_list.remove(plog);
        PRINT_DBG_HEAD
        print_dbg("remove logobj ok");
    } else {
        PRINT_ERR_HEAD
        print_err("syslog manager remove logobj fail.para null");
    }
}

/**
 * [SYSLOG_MAN::Travel 遍历处理一次]
 */
void SYSLOG_MAN::Travel(void)
{
    list<LOGOBJ *>::iterator iter;
    for (iter = m_list.begin(); iter != m_list.end(); iter++) {
        if ((*iter)->Query()) {
            while ((*iter)->GetNextRow()) {
                (*iter)->DoWithOneRecord();
            }
        }
    }
    PRINT_DBG_HEAD
    print_dbg("send syslog Travel over.list size %d", (int)m_list.size());
}

void *SendSysLogProcess(void *arg)
{
    pthread_setself("sendsyslog");

    SYSLOG_MAN manager;
    manager.Add(new SYSLOG());
    manager.Add(new MGLOG());
    manager.Add(new SECMGLOG());
    manager.Add(new CALLLOG());
    manager.Add(new LINKLOG());
    manager.Add(new FILTERLOG());
    manager.Add(new FILESYNCLOG());
    manager.Add(new DBSYNCLOG());
    manager.Add(new SYSTEM_STATUS());

    while (1) {
        manager.Travel();
        sleep(SYS_LOG_CYCLE);
    }
    return NULL;
}

/**
 * [StartSysLog 开始运行发送syslog的线程]
 * @param  iPort      [端口]
 * @param  chServerIp [IP]
 * @return            [成功返回0]
 */
int StartSysLog(int iPort, char *chServerIp)
{
    if (m_send.Open(chServerIp, iPort) < 0) {
        PRINT_ERR_HEAD
        print_err("syslog m_send open error.server[%s]:%d", chServerIp, iPort);
        return -1;
    }

    pthread_t threadid;
    if (pthread_create(&threadid, NULL, SendSysLogProcess, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create syslog process fail");
        return -2;
    }
    return 0;
}
