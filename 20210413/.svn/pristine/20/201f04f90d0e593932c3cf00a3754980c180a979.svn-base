/*******************************************************************************************
*文件:  FCLogmanage.cpp
*描述:  数据库操作类
*作者:  王君雷
*日期:  2016
*
*修改:
*       WriteCallLog WriteFilterLog 防止传入的字段过长造成内存越界      ------> 2016-08-01
*       连接数据库时不指定本地路径，使用mysql_options自动获取           ------> 2018-04-10
*       写日志的接口，添加参数chisout，可以选择填写日志区域;使用zlog    ------> 2018-07-19
*       去除在本文件中使用全局对象g_log                                 ------> 2018-08-31
*       添加写文件交换日志的接口函数;使用snprintf代替sprintf            ------> 2018-09-03
*       吞吐量使用unsigned long long int类型表示                        ------> 2018-09-27
*       添加DBGlobalPrepare静态成员函数                                 ------> 2019-08-27
*       添加ParseTblName、RepairRequst接口，写数据库失败可以通知修复    ------> 2019-12-15
*       是否记录日志开关真正生效                                        ------> 2020-01-07
*       写数据库前，处理特殊字符，防止插入DB出错                        ------> 2020-01-19
*       支持蜂鸣器时才包含sys/io.h文件                                  ------> 2020-05-15
*       不再包含io.h头文件                                              ------> 2020-05-18
*       添加函数SlogReload，可以重新读取syslog开关                      ------> 2020-07-06
*       操作数据库失败时，重连后重试一次                                 ------> 2021-02-04
*******************************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "tbl_err_comm.h"
#include "FCLogManage.h"
#include "debugout.h"
#include "common.h"

#define DEFAULT_USER "susqlroot"
#define DEFAULT_PASS "suanmitsql"
#define DEFAULT_DB "sudb"

CLOGMANAGE::CLOGMANAGE(void)
{
    m_record = false;
    m_initok = false;
    m_tblerr = false;
    BZERO(m_tblname);
}

CLOGMANAGE::~CLOGMANAGE(void)
{
    if (m_initok) {
        mysql_close(&m_csql);
        m_initok = false;
    }
}

/**
 * [CLOGMANAGE::DisConnect 断开数据库连接]
 */
void CLOGMANAGE::DisConnect(void)
{
    if (m_initok) {
        mysql_close(&m_csql);
        m_initok = false;
    } else {
        PRINT_INFO_HEAD
        print_info("you havenot connected,cannot disConnect");
    }
}

/**
 * [CLOGMANAGE::DBGlobalPrepare 数据库全局环境准备 目的是让后续线程能同时连接数据库]
 * @return  [成功返回true]
 */
bool CLOGMANAGE::DBGlobalPrepare(void)
{
    MYSQL tmpcsql;
    if (mysql_init(&tmpcsql) == NULL) {
        PRINT_ERR_HEAD
        print_err("mysq Init fail");
        return false;
    }
    mysql_close(&tmpcsql);

    PRINT_INFO_HEAD
    print_info("db global prepare ok");
    return true;
}

/**
 * [CLOGMANAGE::ConnectDB 连接数据库]
 * @param  chremote [主机名]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::ConnectDB(const char *chremote)
{
    if (!m_initok) {
        //非线程mysql写连接
        if (mysql_init(&m_csql) == NULL) {
            return E_FALSE;
        }

        if (mysql_options(&m_csql, MYSQL_READ_DEFAULT_GROUP, "client") != 0) {
            PRINT_ERR_HEAD
            print_err("mysql_options error");
            mysql_close(&m_csql);
            return E_FALSE;
        }

        if (mysql_real_connect(&m_csql, chremote, DEFAULT_USER, DEFAULT_PASS, DEFAULT_DB, 0,
                               NULL, 0) == NULL) {
            PRINT_ERR_HEAD
            print_err("connect db error");
            mysql_close(&m_csql);
            return E_FALSE;
        }

        m_initok = true;
    } else {
        PRINT_INFO_HEAD
        print_info("already connected");
    }

    return E_OK;
}

/**
 * [CLOGMANAGE::ReConnectDB 重连]
 * @param  chremote [主机名]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::ReConnectDB(const char *chremote)
{
    DisConnect();
    return ConnectDB(chremote);
}

/**
 * [CLOGMANAGE::ReleaseTableSpace 释放空间]
 * @param  tblname [表名]
 * @return        [成功返回E_OK]
 */
int CLOGMANAGE::ReleaseTableSpace(const char *tblname)
{
    char m_sqlstr[1000] = {0};

    //删临时表
    sprintf(m_sqlstr, "drop table tmp");
    if (WriteToDB(m_sqlstr) == E_FALSE) {
        return E_FALSE;
    }

    //建临时表
    sprintf(m_sqlstr, "create table tmp as select MIN(id) tid,count(id) cnt from %s", tblname);
    if (WriteToDB(m_sqlstr) == E_FALSE) {
        return E_FALSE;
    }

    //删除
    sprintf(m_sqlstr,
            "delete from %s where id < (select tid from tmp)+(select cnt from tmp)/2", tblname);
    if (WriteToDB(m_sqlstr) == E_FALSE) {
        PRINT_ERR_HEAD
        print_err("delete from %s error", tblname);
        return E_FALSE;
    }

    //优化表
    BZERO(m_sqlstr);
    sprintf(m_sqlstr, "OPTIMIZE TABLE %s;", tblname);
    if (WriteToDB(m_sqlstr) == E_FALSE) {
    }

    system("sync");
    return E_OK;
}

/**
 * [CLOGMANAGE::Init 初始化]
 * @param  brec  [是否记录日志]
 * @param  chremote [主机名]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::Init(bool brec, const char *chremote)
{
    m_record = brec;
    return ConnectDB(chremote);
}

/**
 * [CLOGMANAGE::SetRecordFlag 设置是否记录日志]
 * @param brec [是否记录]
 */
void CLOGMANAGE::SetRecordFlag(bool brec)
{
    m_record = brec;
}

/**
 * [CLOGMANAGE::SetTableName 设置当前操作的表名]
 * @param tblname [表名]
 */
void CLOGMANAGE::SetTableName(const char *tblname)
{
    if ((tblname != NULL) && (strlen(tblname) < sizeof(m_tblname))) {
        strcpy(m_tblname, tblname);
    } else {
        memset(m_tblname, 0, sizeof(m_tblname));
        PRINT_ERR_HEAD
        print_err("tblname error[%s]", tblname);
    }
}

/**
 * [CLOGMANAGE::GetSysTime 获取格式化的时间]
 * @param result [输出参数]
 */
void CLOGMANAGE::GetSysTime(char *result)
{
    if (result == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return ;
    }

    char str[100] = {0};
    time_t secs_now = time(NULL);
    struct tm tmtmp;
    localtime_r(&secs_now, &tmtmp);
    strftime(str, 50, "%Y-%m-%d %H:%M:%S", &tmtmp);
    strcpy(result, str);
    return;
}

/**
 * [CLOGMANAGE::WriteSysLog 写系统日志]
 * @param  logtype [日志类型]
 * @param  result  [结果]
 * @param  remark  [备注]
 * @param  chisout [是否为外网]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::WriteSysLog(const char *logtype, const char *result, const char *remark,
                            const char *chisout)
{
    char sql[1000] = {0};
    char dtime[30] = {0};
    GetSysTime(dtime);
    slog.WriteSysLog(logtype, result, remark, SetIO(chisout) ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql),
             "INSERT INTO SYSLOG(optime,logtype,result,remark,ifsend,isout,alarm)"
             "values('%s','%s','%s','%s',%d,%s,%s)",
             dtime, logtype, result, remark, 0, SetIO(chisout) ? "TRUE" : "FALSE", "FALSE");

    return WriteToDB("SYSLOG", sql);
}

/**
 * [CLOGMANAGE::WriteFilterLog 写过滤日志]
 * @param  user    [用户名]
 * @param  fname   [描述]
 * @param  remark  [备注]
 * @param  service  [应用]
 * @param  srcip     [源IP]
 * @param  dstip     [目的IP]
 * @param  srcport   [源端口]
 * @param  dstport   [目的端口]
 * @param  chisout [是否为外网]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::WriteFilterLog(const char *user, const char *fname, const char *remark, const char *service,
                               const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                               const char *chisout)
{
    char sql[1000];
    char dtime[30] = {0};
    GetSysTime(dtime);

    char fname2[800] = {0};
    CCommon common;
    common.SpecialChar(fname, strlen(fname), fname2, sizeof(fname2));

    slog.WriteFilterLog(user, fname2, remark, service, srcip, dstip, srcport, dstport, SetIO(chisout) ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql), "INSERT INTO FILTERLOG"
             "(optime,opuser,fname,remark,ifsend,isout,alarm,service,srcip,dstip,srcport,dstport)"
             "values('%s','%s','%s','%s',%d,%s,%s,'%s','%s','%s','%s','%s')",
             dtime, user, fname2, remark, 0, SetIO(chisout) ? "TRUE" : "FALSE", "FALSE",
             service, srcip, dstip, srcport, dstport);

    return WriteToDB("FILTERLOG", sql);
}

/**
 * [CLOGMANAGE::WriteLinkLog 写攻击防护日志]
 * @param  sip     [源IP]
 * @param  dip     [目的IP]
 * @param  sport   [源端口]
 * @param  dport   [目的端口]
 * @param  remark  [备注]
 * @param  srcmac  [源MAC]
 * @param  dstmac  [目的MAC]
 * @param  chisout [是否外网]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE:: WriteLinkLog(const char *sip, const char *dip, const char *sport,  const char *dport,
                              const char *remark, const char *srcmac, const char *dstmac, const char *chisout)
{
    char sql[1500];
    char dtime[30] = {0};
    GetSysTime(dtime);

    slog.WriteLinkLog(sip, dip, sport, dport, remark, srcmac, dstmac, SetIO(chisout) ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql),
             "INSERT INTO LINKLOG(optime,srcip,destip,sport,dport,remark,ifsend,isout,alarm,srcmac,dstmac)"
             "values('%s','%s','%s','%s','%s','%s',%d,%s,%s,'%s','%s')",
             dtime, sip, dip, sport, dport, remark, 0, SetIO(chisout) ? "TRUE" : "FALSE", "FALSE", srcmac, dstmac);

    return WriteToDB("LINKLOG", sql);
}

/**
 * [CLOGMANAGE::WriteCallLog 写访问日志（交换日志）]
 * @param  user     [用户名]
 * @param  srcip    [源IP]
 * @param  dstip    [目的IP]
 * @param  srcport  [源端口]
 * @param  dstport  [目的端口]
 * @param  srcmac   [源MAC]
 * @param  dstmac   [目的MAC]
 * @param  service  [服务名]
 * @param  cmd      [命令]
 * @param  param    [参数]
 * @param  result   [结果]
 * @param  remark   [备注]
 * @param  chisout  [是否为外网]
 * @return          [成功返回E_OK]
 */
int CLOGMANAGE::WriteCallLog(const char *user, const char *srcip, const char *dstip,
                             const char *srcport, const char *dstport, const char *srcmac, const char *dstmac,
                             const char *service, const char *cmd, const char *param, const char *result,
                             const char *remark, const char *chisout)
{
    char sql[1500] = {0};
    char dtime[30] = {0};
    GetSysTime(dtime);

    char param2[1024] = {0};
    CCommon common;
    common.SpecialChar(param, strlen(param), param2, sizeof(param2));

    slog.WriteCallLog(user, srcip, dstip, srcport, dstport, srcmac, dstmac,
                      service, cmd, param, result, remark, SetIO(chisout) ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql),
             "INSERT INTO CallLOG(optime,opuser,srcip,dstip,srcport,dstport,service,cmd,param,"
             "result,remark,ifsend,isout,alarm,srcmac,dstmac)values('%s','%s','%s','%s','%s','%s','%s','%s','%s',"
             "'%s','%s',%d,%s,%s,'%s','%s')",
             dtime, user, srcip, dstip, srcport, dstport, service, cmd, param2, result, remark,
             0, SetIO(chisout) ? "TRUE" : "FALSE", "FALSE", srcmac, dstmac);

    return WriteToDB("CallLOG", sql);
}

/**
 * [CLOGMANAGE::WriteSysStatusLog 写系统状态日志]
 * @param  linknum   [并发数]
 * @param  cpuinfo   [CPU使用率]
 * @param  diskinfo  [磁盘使用率]
 * @param  meminfo   [内存使用率]
 * @param  netinfo   [隔离通道状态]
 * @param  netflow   [实时吞吐量]
 * @param  devstatus [设备整体状态]
 * @param  descr     [描述]
 * @param  chisout   [是否外网]
 * @return           [成功返回E_OK]
 */
int CLOGMANAGE::WriteSysStatusLog(int linknum, const char *cpuinfo, const char *diskinfo,
                                  const char *meminfo, const char *netinfo, unsigned long long int netflow,
                                  char devstatus, const char *descr, const char *chisout)
{
    char sql[1500] = {0};
    char dtime[30] = {0};
    GetSysTime(dtime);
    slog.WriteSysStatusLog(linknum, cpuinfo, diskinfo, meminfo, netinfo, netflow, devstatus, descr, SetIO(chisout) ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql), "INSERT INTO SYSTEM_STATUS"
             "(optime, link_num, cpu_info, disk_info, mem_info, net_info, net_flow, "
             "dev_status, descr, record,ifsend,isout,alarm)"
             "values('%s',%d,'%s','%s','%s','%s',%llu,'%c','%s','%c',%d,%s,%s)",
             dtime, linknum, cpuinfo, diskinfo, meminfo, netinfo, netflow, devstatus, descr, '1', 0,
             SetIO(chisout) ? "TRUE" : "FALSE", "FALSE");

    return WriteToDB("SYSTEM_STATUS", sql);
}

/**
 * [CLOGMANAGE::WriteToDB 写入数据库]
 * @param  tblname [表名]
 * @param  chsql [sql语句]
 * @return        [成功返回E_OK]
 */
int CLOGMANAGE::WriteToDB(const char *tblname, const char *chsql)
{
    SetTableName(tblname);
    int ret = WriteToDB(chsql);
    if ((ret == E_FALSE) && m_tblerr) {
        //修复请求
        RepairRequst();
    }
    return ret;
}

/**
 * [CLOGMANAGE::ParseTblName 解析sql语句中的表名]
 * @param  chsql  [sql语句]
 * @param  name    [出参 表名]
 * @param  namelen [传参缓冲区长度]
 * @return         [成功返回true]
 */
bool CLOGMANAGE::ParseTblName(const char *chsql, char *name, int namelen)
{
    if ((chsql == NULL) || (name == NULL) || (namelen < (int)sizeof(m_tblname))) {
        PRINT_ERR_HEAD
        print_err("resolv table name para error.[%s][%d]", chsql, namelen);
        return false;
    }

    memset(m_tblname, 0, sizeof(m_tblname));
    const char *headstr = "insert into ";
    int hlen = strlen(headstr);

    if (strncasecmp(chsql, headstr, hlen) == 0) {
        for (int i = 0; i < (int)sizeof(m_tblname); ++i) {
            if ((chsql[hlen + i] == ' ')
                || (chsql[hlen + i] == '(')
                || (chsql[hlen + i] == '\0')) {
                break;
            }
            name[i] = m_tblname[i] = chsql[hlen + i];
        }
        if (strlen(m_tblname) > 0) {
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sql[%s] resolv table name fail", chsql);
            return false;
        }
    } else {
        PRINT_INFO_HEAD
        print_info("sql[%s] not begin with[%s]", chsql, headstr);
        return false;
    }
}

//异常处理
static const pchar _syserror[] = {  //不作为表损坏的判断条件
    "MySQL server has gone away",
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near",
    "Commands out of sync; you can't run this command now",
    "Lost connection to MySQL server during query",
    "Unknown column",//"Unknown column 'srcmac' in 'field list'",
    NULL,
};

/**
 * [CLOGMANAGE::WriteToDB 写入数据库]
 * @param  chsql  [sql语句]
 * @return        [成功返回E_OK]
 */
int CLOGMANAGE::WriteToDB(const char *chsql)
{
    int failcnt = 0;
    char errorinfo[512] = {0};

_again:
    if (mysql_query(&m_csql, chsql) != 0) {
        failcnt++;
        sprintf(errorinfo, "%s", mysql_error(&m_csql));
        int32 i = 0;
        while (_syserror[i] != NULL) {
            if ((strncmp(errorinfo, _syserror[i], strlen(_syserror[i])) == 0)) {
                break;
            }
            i++;
        }
        m_tblerr = (_syserror[i] == NULL);
        ReConnectDB();
        if (failcnt < 2) {
            PRINT_INFO_HEAD
            print_info("[%s][%s]failcnt[%d] goto _again", chsql, errorinfo, failcnt);
            goto _again;
        } else {
            PRINT_ERR_HEAD
            print_err("[%s][%s]failcnt[%d] return false", chsql, errorinfo, failcnt);
            return E_FALSE;
        }
    } else {
        m_tblerr = false;
        return E_OK;
    }
}

/**
 * [CLOGMANAGE::SetIO 设置是否为外网]
 * @param ibuf [输入信息]
 * @return     [是外网返回true]
 */
bool CLOGMANAGE::SetIO(const char *ibuf)
{
    return (ibuf == NULL) ? (DEVFLAG[0] != 'I') : (ibuf[0] != 'I');
}

/**
 * [CLOGMANAGE::WriteFileSyncLog 写文件交换日志]
 * @param  taskid  [任务号]
 * @param  taskname[任务名称]
 * @param  srcip   [源IP]
 * @param  dstip   [目的IP]
 * @param  spath   [源路径]
 * @param  dpath   [目的路径]
 * @param  fname   [文件名]
 * @param  result  [结果]
 * @param  remark  [备注]
 * @param  outtoin [true表示外到内  false表示内到外]
 * @return         [成功返回E_OK]
 */
int CLOGMANAGE::WriteFileSyncLog(int taskid, const char *taskname, const char *srcip, const char *dstip, const char *spath,
                                 const char *dpath, const char *fname, const char *result, const char *remark, bool outtoin)
{
    char sql[4000] = {0};
    char dtime[30] = {0};
    GetSysTime(dtime);

    char fname2[1024] = {0};
    char spath2[1024] = {0};
    char dpath2[1024] = {0};
    CCommon common;
    common.SpecialChar(fname, strlen(fname), fname2, sizeof(fname2));
    common.SpecialChar(spath, strlen(spath), spath2, sizeof(spath2));
    common.SpecialChar(dpath, strlen(dpath), dpath2, sizeof(dpath2));

    slog.WriteFileSyncLog(taskid, taskname, srcip, dstip, spath2, dpath2, fname2, result, remark, outtoin ? 1 : 0, dtime);

    if (!m_record) { return E_OK; }
    snprintf(sql, sizeof(sql),
             "INSERT INTO FileSyncLOG(task_id,optime,s_path,filename,result,remark,ifsend,isout,alarm,srcip,dstip,taskname,d_path)"
             "values(%d,'%s','%s','%s','%s','%s',%d,%s,%s,'%s','%s','%s','%s')",
             taskid, dtime, spath2, fname2, result, remark, 0, outtoin ? "TRUE" : "FALSE", "FALSE", srcip, dstip, taskname, dpath2);
    return WriteToDB("FileSyncLOG", sql);
}

/**
 * [CLOGMANAGE::RepairRequst 修复请求]
 */
void CLOGMANAGE::RepairRequst(void)
{
    tbl_err_put_request(m_tblname, strlen(m_tblname));
}

/**
 * [CLOGMANAGE::SlogReload 重新读取syslog配置]
 */
void CLOGMANAGE::SlogReload(void)
{
    PRINT_INFO_HEAD
    print_info("slog reload config info");
    slog.ReadSwitch();
}
