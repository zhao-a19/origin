/*******************************************************************************************
*文件:  sys6.cpp
*描述:  网闸V6版主函数文件
*作者:  王君雷
*日期:
*修改:
*          注册信号函数sigfunction，用以计算界面展示的隔离通道状态  ------> 2016-01-25
*          添加函数bulid_key 和 check_key                           ------> 2016-04-19
*          为主机时才去生成和校验key                                ------> 2016-04-22
*          添加授权功能，只在网闸内网来做                           ------> 2016-04-22
*          添加授权id，防止同一个证书多次导入成功                   ------> 2016-04-25
*          不论主机还是备机都生成和校验key 绑定的网卡改用内部通信口 ------> 2016-04-27
*          并行处理业务日志，提高业务速率                           ------> 2016-08-05
*          代理模式RTSP模块替换URL中的IP为目标IP                    ------> 2016-03-30
*          改用UTF8编码，改用linux缩进格式                          ------> 2018-01-22
*          使用zlog记录日志                                         ------> 2018-04-10
*          系统启动时创建用于互斥访问iptables的锁                   ------> 2018-11-16
*          不使用全局的数据库操作对象                               ------> 2019-01-09
*          后台版本号命名规范调整，如8.1.190226                     ------> 2019-02-26
*          通过宏控制是否启用授权检查                               ------> 2019-04-11
*          VERSION版本号，使用编译时的时间，不再每次都手动修改本文件------> 2019-06-18
*          输出版本号到文件的缓存区大小从64放到到CMD_BUF_LEN        ------> 2019-08-27
*          支持-V参数，打印程序版本号                               ------> 2019-09-02
*          链接注册wireshark接口                                    ------> 2019-10-08-dzj
*          解决在V6环境下编辑不过问题                               ------> 2019-10-08-dzj
*          sys6不写version文件                                      ------> 2019-12-03 wjl
*          捕捉信号11,子进程意外退出时能打印协议栈内容              ------> 2020-07-29 wjl
*******************************************************************************************/
#include <sys/types.h>
#include <sys/wait.h>
#include <semaphore.h>

#include "FCMAINCTRL.h"
#include "FCLogManage.h"
#include "FCKey.h"
#include "speaker.h"
#include "FCLicenseCK.h"
#include "FCLogContainer.h"
#include "debugout.h"
#include "readcfg.h"

#if (SUOS_V!=6)
extern "C" {
#include "su_wireshark_epan.h"
}
#endif

#define VERSION "YYMMDD"

bool g_debug;
loghandle glog_p = NULL;
sem_t *g_iptables_lock;

/**
 * [init_iptables_lock 创建用于互斥访问iptables的锁]
 * @return [成功返回0]
 */
int init_iptables_lock()
{
    //创建访问互斥锁
    sem_unlink(IPTABLES_MUTEX_PATH);
    g_iptables_lock = sem_open(IPTABLES_MUTEX_PATH,
                               O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 1);
    if (g_iptables_lock == SEM_FAILED) {
        PRINT_ERR_HEAD
        print_err("sem_open error[%s:%s]", IPTABLES_MUTEX_PATH, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * [bulid_key 创建key]
 * @param lan [网口号]
 */
void bulid_key(int lan)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char chout[33] = {0};

    KEY mykey(KEY_FILE, lan);
    if (mykey.file_exist(CLI_TOOL_FILE)) {
        if (mykey.file_exist(KEY_FILE)) {
            //因为已经存在key文件了 直接把clitool删除掉
            sprintf(chcmd, "rm -f %s", CLI_TOOL_FILE);
            system(chcmd);
            system("sync");
        } else {
            //创建key文件
            if (mykey.md5(time(NULL), chout)) {
                sprintf(chcmd, "%s %s", CLI_TOOL_FILE, chout);
                system(chcmd);
                if (mykey.file_exist(KEY_FILE)) {

                    PRINT_DBG_HEAD
                    print_dbg("create key ok!");

                    //创建成功后把clitool删除
                    sprintf(chcmd, "rm -f %s", CLI_TOOL_FILE);
                    system(chcmd);
                    system("sync");
                } else {
                    PRINT_ERR_HEAD
                    print_err("create key fail");
                }
            }
        }
    }
}

/**
 * [check_key 检查KEY合法性]
 * @param  lan [网卡号]
 * @return     [合法返回true]
 */
bool check_key(int lan)
{
    char readmd5[33] = {0};//文件中读取到的
    char calcmd5[33] = {0};//当前环境计算得到的

    KEY mykey(KEY_FILE, lan);
    if (mykey.file_exist(KEY_FILE)) {
        if (mykey.read_key(readmd5)) {
            if (mykey.calc_md5(calcmd5)) {
                if (strcmp(readmd5, calcmd5) == 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

/**
 * [read_cslan 读取管理口号]
 * @param  ethno [网卡号 出参]
 * @return       [读取成功返回true]
 */
bool read_cslan(int &ethno)
{
    bool flag = false;
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("OpenFile error[%s]", SYSINFO_CONF);
        goto _out;
    }

    READ_INT(fileop, "SYSTEM", "CSLan", ethno, true, _out);
    flag = true;

_out:
    fileop.CloseFile();
    return flag;
}

/**
 * [read_linklan 读取内联口号]
 * @param  ethno [网卡号 出参]
 * @return       [读取成功返回true]
 */
bool read_linklan(int &ethno)
{
    bool flag = false;
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("OpenFile error[%s]", SYSINFO_CONF);
        goto _out;
    }

    READ_INT(fileop, "SYSTEM", "LinkLan", ethno, true, _out);
    flag = true;

_out:
    fileop.CloseFile();
    return flag;
}

/**
 * [sig_callback 信号回调函数]
 * @param signum [信号值]
 */
void sig_callback(int signum)
{
    switch (signum) {
    case SIGSEGV:
        PRINT_ERR_HEAD;
        print_err("Receive signal SIGSEGV = %d", SIGSEGV);
        stackdump(signum);
        exit(1);
        break;
    default:
        PRINT_INFO_HEAD;
        print_info("Unknown signal = %d", signum);
        break;
    }
    return;
}

int main(int argc, char *argv[])
{
    g_debug = false;
    char chcmd[CMD_BUF_LEN] = {0};

    if ((argc == 2) && (strcasecmp(argv[1], "-v") == 0)) {
        sprintf(chcmd, "cat %s", VERSION_FILE);
        system(chcmd);
        return 0;
    } else if ((argc == 2) && (strcasecmp(argv[1], "-realv") == 0)) {
        printf("%s.%s\n", KERNVER, VERSION);
        return 0;
    } else if ((argc > 1) && (strstr(argv[1], "debug") != NULL)) {
        g_debug = true;
    }

    int linklan = 0;

    //当前程序版本输出到版本文件
    //sprintf(chcmd, "echo %s.%s > %s", KERNVER, VERSION, VERSION_FILE);
    //system(chcmd);

    _log_init_(glog_p, sys6);
    signal(SIGSEGV, sig_callback);

    if (!read_linklan(linklan)) {
        return -1;
    }

    bulid_key(linklan);

    //校验key
    if (!check_key(linklan)) {
        PRINT_ERR_HEAD
        print_err("key error");
        speaker_key_error();
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("check_key ok");

#if (SUOS_V!=6)
    pSuEpanSession = su_epan_new();
    if ( pSuEpanSession == NULL ) {
        PRINT_ERR_HEAD
        print_err("link wireshark error");
        return -1;
    }
#endif

    while (1) {
        pid_t pid = 0;
        pid = fork();
        if (pid < 0) {
            PRINT_ERR_HEAD
            print_err("fork error");
        } else if (pid == 0) {
            //连接数据库
            CLOGMANAGE mlog;
            while (mlog.Init() != E_OK) {
                PRINT_ERR_HEAD
                print_err("log init fail,retry");
                sleep(1);
            }

            sprintf(chcmd, "%s(ver:%s.%s)", LOG_CONTENT_SYS6_RUN, KERNVER, VERSION);
            mlog.WriteSysLog(LOG_TYPE_RUN, D_SUCCESS, chcmd);
            PRINT_INFO_HEAD
            print_info("sys6 run(ver:%s.%s)", KERNVER, VERSION);

            while (init_iptables_lock() != 0) {
                PRINT_ERR_HEAD
                print_err("init iptables lock fail,retry");
                sleep(1);
            }

            //启动一个线程，负责从日志容器中取数据，然后写入数据库
            StartLogThread();

            //启动授权期限检查线程
            if (DEVFLAG[0] == 'I') {
                if (USE_LICENSE_CHECK == 1) {
                    StartLicenseCK();
                } else {
                    PRINT_DBG_HEAD
                    print_dbg("no use license check");
                }
            }

            CMAINCTRL Ctrl;
            if (!Ctrl.Start()) {
                PRINT_ERR_HEAD
                print_err("Ctrl.Start error");
                mlog.WriteSysLog(LOG_TYPE_RUN, D_FAIL, LOG_CONTENT_INIT_BS_ERR);
            }

            while (1) {
                sleep(100);
            }
            exit(0);
        } else {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                PRINT_ERR_HEAD
                print_err("The child process %d exit normally,WEXITSTATUS code[%d],WIFEXITED code[%d]",
                          pid, WEXITSTATUS(status), WIFEXITED(status));
            } else {
                PRINT_ERR_HEAD
                print_err("The child process %d exit abnormally, Status is %d", pid, status);
            }

            //杀掉可能存在的进程
            system(STOP_BUSINESS_SYS6);

            PRINT_ERR_HEAD
            print_err("Daemon restart");
        }

        sleep(2);
    }

#if (SUOS_V!=6)
    su_epan_destroy(pSuEpanSession);
#endif
    return 0;
}
