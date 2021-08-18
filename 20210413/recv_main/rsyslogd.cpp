/*******************************************************************************************
*文件:  rsyslogd.cpp
*描述:  运行rsyslogd线程函数
*作者:  王君雷
*日期:  2020-01-15
*修改:
*       修改syslogd为rsyslogd,20年2月5日引入的问题                     ------> 2020-02-18 wjl
*       启动rsyslogd服务前删除可能存在的pid文件                         ------> 2020-12-31
*       可以设置线程名称                                                ------> 2021-02-23
*******************************************************************************************/
#include <pthread.h>
#include "rsyslogd.h"
#include "fileoperator.h"
#include "debugout.h"
#include "define.h"
#include "common.h"
#include "gap_config.h"

#define RSYSLOG_CONF  "/etc/rsyslog.conf"
#define RSYSLOGD "rsyslogd"
#define RSYSLOGD_PID "/var/run/rsyslogd.pid"

extern bool g_rsyslodchange;
extern int g_linklanipseg;
extern int g_linklan;

void *rsyslogd_thread(void *arg)
{
    pthread_setself("rsyslogd");
    SLOG_SVR_OPER svr;

    while (1) {
        if (g_rsyslodchange) {
            g_rsyslodchange = false;
            svr.ReadConfig();
            svr.WriteConfig();
            svr.RunRsyslogd();
        } else {
            svr.Check();
        }
        sleep(1);
    }
    return NULL;
}

/**
 * [StartRsyslogd 启动rsyslogd线程]
 * @return  [成功返回0]
 */
int StartRsyslogd(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, rsyslogd_thread, NULL) != 0) {
        return -1;
    }
    return 0;
}

SLOG_SVR_OPER::SLOG_SVR_OPER(void)
{
    memset(m_svrip, 0, sizeof(m_svrip));
    memset(m_svrport, 0, sizeof(m_svrport));
    m_syslog = false;
    ReadConfig();
}

SLOG_SVR_OPER::~SLOG_SVR_OPER(void)
{

}

/**
 * [SLOG_SVR_OPER::ReadConfig 读取配置信息]
 * @return  [成功返回0]
 */
int SLOG_SVR_OPER::ReadConfig(void)
{
    int tmpint = 0;
    CFILEOP fop;

    if (fop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("slog read config open[%s] fail", SYSSET_CONF);
        return -1;
    }
    fop.ReadCfgFileInt("SYSTEM", "LogType", &tmpint);
    m_syslog = (tmpint == 1);

    if (m_syslog) {
        if (DEVFLAG[0] == 'I') {
            fop.ReadCfgFile("SYSTEM", "LogServer", m_svrip, sizeof(m_svrip));
            fop.ReadCfgFile("SYSTEM", "LogServerPort", m_svrport, sizeof(m_svrport));
        } else {
            //对于外网侧 服务IP端口写为内联地址和端口
            sprintf(m_svrip, "%d.0.0.254", g_linklanipseg);
            sprintf(m_svrport, "%d", DEFAULT_SYSLOG_PORT);
        }
    }
    fop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("slog svr read conf over. syslog[%d] svrip[%s] svrport[%s]",
              m_syslog ? 1 : 0, m_svrip, m_svrport);
    return 0;
}

/**
 * [SLOG_SVR_OPER::WriteConfig 写rsyslogd使用的配置文件]
 * @return  [成功返回0]
 */
int SLOG_SVR_OPER::WriteConfig(void)
{
    FILE *fileop = NULL;
    char chcmd[1024] = {0};
    if (m_syslog) {
        fileop = fopen(RSYSLOG_CONF, "wb");
        if (fileop == NULL) {
            PRINT_ERR_HEAD
            print_err("slog svr fopen %s fail", RSYSLOG_CONF);
            return -1;
        }
        if (DEVFLAG[0] == 'I') {
            /*
            fputs("$ModLoad imudp\n", fileop);
            sprintf(chcmd, "$UDPServerRun %d\n", DEFAULT_SYSLOG_PORT);
            fputs(chcmd, fileop);
            */
            fputs("module(load=\"imudp\")\n", fileop);
            sprintf(chcmd, "input(type=\"imudp\" port=\"%d\")\n", DEFAULT_SYSLOG_PORT);
            fputs(chcmd, fileop);
        }
        fputs("$ModLoad imuxsock\n", fileop);
        if (strchr(m_svrip, ':') == NULL) {
            sprintf(chcmd, "user.*   @%s:%s\n", m_svrip, m_svrport);
        } else {
            sprintf(chcmd, "user.*   @[%s]:%s\n", m_svrip, m_svrport);
        }
        fputs(chcmd, fileop);
        fclose(fileop);
    }
    return 0;
}

/**
 * [SLOG_SVR_OPER::RunRsyslogd 运行rsyslogd]
 * @return  [成功返回0]
 */
int SLOG_SVR_OPER::RunRsyslogd(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    if (m_syslog) {
        sprintf(chcmd, "ps |grep %s|grep -v grep && killall %s && sleep 1", RSYSLOGD, RSYSLOGD);
        system(chcmd);
        unlink(RSYSLOGD_PID);
        system(RSYSLOGD);
        PRINT_INFO_HEAD
        print_info("%s run. svr[%s] port[%s]", RSYSLOGD, m_svrip, m_svrport);
    } else {
        sprintf(chcmd, "killall %s >/dev/null 2>&1", RSYSLOGD);
        system(chcmd);
    }
    return 0;
}

/**
 * [SLOG_SVR_OPER::Check 检查进程是否存在 退出了就重新拉起]
 */
void SLOG_SVR_OPER::Check(void)
{
    CCommon common;
    if (m_syslog) {
        if (!common.ProcessRuning(RSYSLOGD)) {
            PRINT_ERR_HEAD
            print_err("%s is not running.pull it", RSYSLOGD);
            system(RSYSLOGD);
        }
    }
}
