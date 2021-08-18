/*******************************************************************************************
*文件:  FCSMS.cpp
*描述:  发送短信接口
*作者:  王君雷
*日期:  2016-03
*修改:
*      线程ID使用pthread_t类型                                           ------> 2018-08-07
*      短信告警的内容改为包含服务、命令、备注信息；原来只发送备注        ------> 2019-03-06
*      select 查询添加limit条数限制                                      ------> 2019-07-10
*******************************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <curses.h>
#include <sys/stat.h>
#include <fcntl.h>      /*文件控制定义*/
#include <termios.h>    /*PPSIX 终端控制定义*/
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <pthread.h>
#include "simple.h"
#include "FCLogManage.h"
#include "quote_global.h"
#include "debugout.h"

static char smsserverip[100]; //短信平台服务器IP
static int smsserverport;     //短信平台服务器PORT
static char smsalertphone[16];//管理员手机号

/**
 * [send_sms 发送短信告警信息]
 * @param  ch [告警信息]
 * @return    [返回system调用的返回值]
 */
int send_sms(const char *ch)
{
    char buf[1500] = {0};
    sprintf(buf, "%s ANMIT_SMS '%s' %d LOGALARM TOPRULES V3 '%s' %s",
            SMSCLINET, smsserverip, smsserverport, smsalertphone, ch);

    int ret = system(buf);
    return ret;
}

void *SMSProcess(void *arg)
{
    pthread_setself("smsprocess");

    char sql[200], loginfo[1500];
    int ret;
    MYSQL m_query;
    MYSQL_ROW m_row;
    MYSQL_RES *m_res;

    while (1) {
        //初始化连接mysql
        ret = mysql_init_connect(&m_query);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("smsc mysql init error.retry");
            sleep(1);
            continue;
        }
        while (1) {
            sprintf(sql, "select id,service,cmd,remark from CallLOG "
                    "where result='%s' and (alarm=FALSE or alarm is null) limit 10000", D_REFUSE);
            if (mysql_query(&m_query, sql) != 0) {
                break;
            }
            m_res = mysql_store_result(&m_query);
            if (m_res == NULL) {
                break;
            }

            while (1) {
                m_row = mysql_fetch_row(m_res);
                if (m_row == NULL) {
                    break;
                }

                snprintf(loginfo, sizeof(loginfo),
                         "%s_%s_%s", m_row[1], m_row[2], m_row[3]);
                if (send_sms(loginfo) < 0) {
                    break;
                }

                sprintf(sql, "update CallLOG set alarm=TRUE where id=%s", m_row[0]);
                if (mysql_query(&m_query, sql) != 0) {
                    break;
                }
            }
            mysql_free_result(m_res);
            m_res = NULL;
            sleep(1);
        }
        mysql_close(&m_query);
    }

    PRINT_ERR_HEAD
    print_err("sms process will return");
    return NULL;
}

/**
 * [StartSMS 启动发送短信告警线程]
 * @param  ip    [IP]
 * @param  port  [端口]
 * @param  phone [手机号]
 * @return       [启动成功返回0]
 */
int StartSMS(char *ip, int port, char *phone)
{
    strcpy(smsserverip, ip);
    smsserverport = port;
    strcpy(smsalertphone, phone);

    pthread_t threadid;
    if (pthread_create(&threadid, NULL, SMSProcess, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create sms process fail");
        return -1;
    }
    return 0;
}
