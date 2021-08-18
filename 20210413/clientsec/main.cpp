/*******************************************************************************************
*文件:    main.cpp
*描述:    用户安全模块
*
*作者:    张昆鹏
*日期:    2016-10-31
*修改:    创建文件                                             ------>     2016-10-31
*         修改部分逻辑处理，修改头文件问题                     ------>     2016-11-22
*         增加fork,使程序意外中断后能重新启动                  ------>     2016-11-24
*         添加启动记录日志功能,添加版本记录                    ------>     2016-11-25
*         修改服务器启动端口号设置，默认10021，用户可输入      ------>     2016-12-02
*         修改重复启动模块造成的死机问题                       ------>     2017-02-20
*         新增长文件名处理功能                                 ------>     2017-12-06
*         修改长文件名处理逻辑                                 ------>     2018-01-05
*         增加状态监控                                         ------>     2018-05-15
*
*******************************************************************************************/

#include <errno.h>
#include <sys/wait.h>
#include <pthread.h>

#include "datatype.h"
#include "syssocket.h"
#include "debugout.h"
#include "sysdb.h"
#include "sysver.h"
#include "app.h"
#include "sysdir.h"
#include "fileoperator.h"

#define S_PORT  10021
#define S_IP   "0.0.0.0"
#define BINDERROR 201                                           //不可为0，201-205 地址绑定

static const pchar VersionNO = "1.2.1";                         //版本号
static void print_usage(void)
{

    printf("\n************************* -- CLIENTSEC Module Ver%s -- *************************\n\n", VersionNO);
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    printf("\t(1)./clientsec 1 or 2 \n");
    printf("\t(2)./clientsec 1 or 2 port\n");
    printf("\n******************************************************************************\n\n");
}

static bool GetPort(puint32 port);
extern void* ClientsecTask(void *arg);
static const pchar CLIENTSECMODULE = "CLIENTSEC START";
extern void modulelogout(const pchar modulename, bool ok);
#define errorbreak(r) {modulelogout(CLIENTSECMODULE, false); return r;}

extern bool MkPrivateDir();
extern bool ReadAllConfig(pchar sr_p);
extern void* ClientProcess(void*param);

_log_preinit_(glog_p);                                           //进程资源，在debugout.h都是使用

int main (int argc, char  *argv[])
{
    _log_init_(glog_p, sec);
    uint32 port = S_PORT;
    GetPort(&port);
    if ((argc == 2) || (argc == 3)) {

        if (argc == 3) port = atoi(argv[2]);
        if ((strcmp(argv[1], "1") == 0) || (strcmp(argv[1], "2") == 0)) {

            if ((!ReadAllConfig(argv[1])) || (!MkPrivateDir())) {
                PRINT_DBG_HEAD;
                print_dbg("Start is failed!");
                errorbreak(1);
            } else {
                //状态监控
                pthread_t statestid;
                if (pthread_create(&statestid, NULL, ClientsecTask, (void*)port) != 0) {

                    PRINT_ERR_HEAD;
                    print_err("Usersrv clientsectask failed(%s)!", strerror(errno));
                } else {

                    while (ESRCH == pthread_kill(statestid, 0))   usleep(1);       //是否运行

                    PRINT_DBG_HEAD;
                    print_dbg("Usersrv clientsectask %d Rrunning...", statestid);
                }
            }
        } else {
            print_usage();
            errorbreak(1);
        }
    } else {
        print_usage();
        errorbreak(1);
    }

    //注册版本信息
    char build[256];
    sprintf(build, "%s %s", __DATE__, __TIME__);
    sysver_write("CLIENTSEC", VersionNO, build);
    app_getid(KEY_SET);
    modulelogout(CLIENTSECMODULE, true);

    while (1) {
        pid_t pid;
        if ((pid = fork()) == 0) {

            CSUSOCKET s_user;

            PRINT_DBG_HEAD;
            print_dbg("Clientsec listen ip:port = %s:%d", S_IP, port);
            if (s_user.suopen(S_IP, port, SOCKET_SRV, SOCKET_TCP)) {

                CSYSDB::globalset_threadsafe(CSYSDB::gSET_START);

                while (1) {
                    if (!s_user.getconnect())  break;

                    pthread_t tid;                                              //客户连接
                    CSUSOCKET *tmp = new CSUSOCKET(s_user);

                    if (pthread_create(&tid, NULL, ClientProcess, (void*)tmp) != 0) {

                        PRINT_ERR_HEAD;
                        print_err("Usersrv client failed(%s)!", strerror(errno));
                        delete tmp;
                    } else {

                        while (ESRCH == pthread_kill(tid, 0))   usleep(1);       //是否运行

                        PRINT_DBG_HEAD;
                        print_dbg("Usersrv client %d Rrunning...", tid);
                    }
                }

                CSYSDB::globalset_threadsafe(CSYSDB::gSET_END);
            } else {
                exit(BINDERROR);                                                 //地址已绑定，结束子进程
            }

        } else if (pid < 0) {
            PRINT_ERR_HEAD;
            print_err("Clientsec fork failed!");
        } else {
            int status;
            waitpid(pid, &status, 0);

            PRINT_ERR_HEAD;
            print_err("Clientsec pid = %d, status = %d!", pid, status);
            if (WIFEXITED(status) && (WEXITSTATUS(status) == BINDERROR)) break;
        }
    }

    _log_finish_(glog_p);
    return 0;
}

/*******************************************************************************************
*功能:    读取监听端口号
*参数:    port                ---->   端口号
*         返回值              ---->   成功，失败
*
*注释:
*******************************************************************************************/
static bool GetPort(puint32 port)
{
    CFILEOP file;
    int32 tmp = S_PORT;

    if (file.OpenFile((char *)BConfigFile) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("Clientsec open cfg(%s) failed!", BConfigFile);
        return false;
    }

    file.ReadCfgFileInt("SYS", "NUSERPORT", (int *)&tmp);
    PRINT_DBG_HEAD;
    print_dbg("Clientsec listen port = %d", tmp);
    *port = (uint32)tmp;

    file.CloseFile();
    return true;
}

