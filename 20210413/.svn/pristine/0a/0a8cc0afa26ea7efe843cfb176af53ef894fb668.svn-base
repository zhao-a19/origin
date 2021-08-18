/*******************************************************************************************
*文件:    main.cpp
*描述:    光网视频SIP联动
*
*作者:    张冬波
*日期:    2018-04-19
*修改:    创建文件                   ------>     2018-04-19
*         增加任务状态记录           ------>     2018-04-23
*         支持日志记录控制           ------>     2018-05-02
*         修改规则无效处理方式       ------>     2018-05-15
*         修改程序，在网闸中使用     ------>     2018-07-19 王君雷
*         命令行参数个数不对时打印实际个数                       ------> 2018-07-23
*         注释掉stateinit函数中记录成功日志                      ------> 2018-07-25
*         stateinit函数可以记录成功或失败日志                    ------> 2018-07-26
*******************************************************************************************/
#include <sys/types.h>
#include <sys/wait.h>

#include "datatype.h"
#include "debugout.h"
//#include "syscfg.h"
#include "stringex.h"
//#include "sysdir.h"
//#include "sysver.h"
//#include "app.h"
#include "sip_tasks.h"
#include "FCLogManage.h"

static const pchar VersionNO = "1.2.5";     //版本号,尾号为偶数表示正式版本，奇数为测试

int g_linklanipseg = 1;                     //网闸内部通信口IP网段
int g_linklanport = 59876;                  //网闸内部通信使用的UDP端口
bool g_b_isout = 0;                         //是否为外网侧
char g_natip[40];                           //节点网闸传输视频内部DNAT使用的IP
int g_cmdport;                              //通知对端执行iptables命令时 发往这个UDP端口

//----------------------------------------------------------------
static void print_usage(void)
{
    printf("\n************************* -- SIP Module Ver%s -- ************************\n\n", VersionNO);
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    //printf("\t(1)./gapsip 1 for external connected with GAP; if next arg is 1, log will be saved\n");
    //printf("\t(2)./gapsip 2 for internal; not used currently\n");
    printf("\t ./gapsip listenip litenport natip cmdport isout recordlog\n\n");
    printf("For example: ./gapsip 192.168.2.1 6000 1.0.0.254 59876 1 1\n");
    printf("\n*******************************************************************************\n\n");
}

static sip_task tasks[SIP_TASKMAX];
static const pchar SIPMODULE = "SIP START";
//static int32 readcfg(psip_task tasks, int32 taskcnt, SIPMODE mode);
bool brecordlog = true;

extern void modulelogout(const pchar modulename, bool ok);
#define errorbreak(r) {modulelogout(SIPMODULE, false); return r;}

//初始化任务状态
static void stateinit(psip_task task, bool flag)
{
    CLOGMANAGE logmgr;
    logmgr.Init(true);
#if 0
    logmgr.WriteTask("SIP", "视频点播", task->name, "localhost", task->srvip, task->srvport, "", "", "");
#else
    char loginfo[512] = {0};
    sprintf(loginfo, "%s:%s", task->srvip, task->srvport);
    logmgr.WriteSysLog(LOG_TYPE_LINK_SVR, flag ? D_SUCCESS : D_FAIL, loginfo, g_b_isout ? "O" : "I");
#endif
    logmgr.DisConnect();
}

_log_preinit_(glog_p);
//----------------------------------------------------------------
int main (int argc, char  *argv[])
{
    _log_init_(glog_p, sip); //共用控制台日志记录

    int32 taskcnt;
#if 0
    if (argc == 3) {
        if (strcmp(argv[2], "1") == 0) {
            brecordlog = true;
        } else {
            brecordlog = false;
        }
    } else if (argc != 2) {
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "1") == 0) { taskcnt = readcfg(tasks, SIP_TASKMAX, SIP_TASKE); }
    else if (strcmp(argv[1], "2") == 0) { return 1; }
    else {
        print_usage();
        return 0;
    }

    if (taskcnt <= 0) { errorbreak(0); }


    char build[256];
    sprintf(build, "%s %s", __DATE__, __TIME__);
    sysver_write("SIP", VersionNO, build);
    app_getid(KEY_SET);
    modulelogout(SIPMODULE, true);
#else
    if (argc == 7) {
        taskcnt = 1;
        tasks[0].SN = 1;
        strcpy(tasks[0].srvip, argv[1]);
        strcpy(tasks[0].srvport, argv[2]);
        strcpy(g_natip, argv[3]);
        g_cmdport = atoi(argv[4]);
        g_b_isout = (atoi(argv[5]) == 1);
        brecordlog = (atoi(argv[6]) == 1);
    } else {
        print_usage();
        PRINT_INFO_HEAD;
        print_info("ARGC = %d", argc);
        sleep(1);
        return 0;
    }
#endif

    while (1) {
        pid_t pid;
        if ((pid = fork()) == 0) {
            PRINT_INFO_HEAD;
            print_info("SIP TASKS RUNING COUNT = %u", taskcnt);

            sip_init();
            //创建多任务
            for (int32 i = 0; i < taskcnt; i++) {
                if (tasks[i].disabled) { continue; }
                if (sip_createtask(&tasks[i]) < 0) {
                    PRINT_ERR_HEAD;
                    print_err("SIP TASK %d", i);
                }

                //stateinit(&tasks[i]);
            }

            while (true) {
                sleep(60);

                char cmd[200] = {0};
                char infoout[200];
                for (int32 i = 0; i < taskcnt; i++) {
                    if (tasks[i].disabled) { continue; }

                    sprintf(cmd, "netstat -ant|grep LISTEN|grep %s:%s", tasks[i].srvip, tasks[i].srvport);
                    if (sysinfo(cmd, infoout, sizeof(infoout)) == NULL) {
                        stateinit(&tasks[i], false);
                    } else {
                        stateinit(&tasks[i], true);
                    }
                }
            }

        } else if (pid < 0) {
            PRINT_ERR_HEAD;
            print_err("SIP FORK FAILED!");
        } else {

            int status;
            waitpid(pid, &status, 0);

            PRINT_ERR_HEAD;
            print_err("SIP EXIT PID = %d, STATUS = %d!", pid, status);
        }
    }

    //不会执行到这里
    return 1;
}

#if 0
/**
 * [readcfg 读取配置规则]
 * @param  tasks   [任务配置]
 * @param  taskcnt [任务最大数]
 * @param  mode    [任务模式]
 * @return         [有效任务数，-1：失败]
 */
int32 readcfg(psip_task tasks, int32 taskcnt, SIPMODE mode)
{
    if ((tasks == NULL) || (taskcnt <= 0) || (mode != SIP_TASKE)) { return -1; }

    CSYSCFG file;
    int32 num = 0;
    file.open(BConfigFile, true, true);
    file.getitem("SYS", "SIPNUM", num);
    memset(tasks, 0, sizeof(sip_task)*taskcnt);
    taskcnt = MIN(num, taskcnt);

    PRINT_DBG_HEAD;
    print_dbg("SIP CFG = %d", taskcnt);
#if 0
    //测试用
    tasks[0].flag = mode;
    tasks[0].SN = 1;

    strcpy(tasks[0].srvip, "127.0.0.1");
    strcpy(tasks[0].srvport, "56565");

    return 1;
#endif

    for (int32 i = 0; i < taskcnt; i++) {
        char item[100];
        pchar tmp;
        sprintf(item, "SIP_%d", i);

        //忽略无效配置
        num = 0;
        file.getitem(item, "DISABLE", num);
        tasks[i].disabled = (num == 1);

        if ((tmp = file.getitem(item, "TAGNAME")) != NULL) { strcpy(tasks[i].name, tmp); }
        if ((tmp = file.getitem(item, "IPADDR")) != NULL) { strcpy(tasks[i].srvip, tmp); }
        if ((tmp = file.getitem(item, "PORT")) != NULL) { strcpy(tasks[i].srvport, tmp); }

        if (is_strempty(tasks[i].srvip) || is_strempty(tasks[i].srvport)) {
            PRINT_ERR_HEAD;
            print_err("SIP CFG %s = %s:%s", item, tasks[i].srvip, tasks[i].srvport);
            continue;
        }

        tasks[i].flag = mode;
        tasks[i].SN = i + 1;
        PRINT_DBG_HEAD;
        print_dbg("SIP CFG %s %d = %s:%s", tasks[i].name, tasks[i].disabled, tasks[i].srvip, tasks[i].srvport);
    }


    PRINT_DBG_HEAD;
    print_dbg("SIP CFG = %d", taskcnt);
    return taskcnt;
}
#endif
