/*******************************************************************************************
*文件:    main.cpp
*描述:    用户安全模块客户端工具
*
*作者:    张昆鹏
*日期:    2016-12-2
*修改:    创建文件                                             ------>     2016-12-02
*         更新版本，支持静态编译                               ------>     2017-02-10
*         修改CreateProcess逻辑，增加条件错误输出              ------>     2017-02-27
*         增加策略开关、优化后缀处理、优化优先级处理           ------>     2017-07-07
*         增加UDP和TCP与服务器通信模式                         ------>     2017-07-29
*         增加并发文件功能                                     ------>     2017-09-08
*         新增长文件名处理功能                                 ------>     2017-12-06
*
*******************************************************************************************/
#include <sys/wait.h>

#include "datatype.h"
#include "debugout.h"
#include "filename.h"

static const pchar VersionNO = "1.2.1";                        //版本号
#define PROCESSERROR 202                                        //不可为0，201-205 地址绑定

//打印程序创建的时间和日期
static void print_usage(void)
{
    printf("\n************************* -- FILECLIENT Module Ver%s -- *************************\n\n", VersionNO);
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    printf("\t(1)./fileclient configfile 0/1 NULL/keyfile\n");
    printf("\n******************************************************************************\n\n");
}

//输出“客户端错误”
static void print_errnum(int32 err)
{
    printf("\n************************* -- FILECLIENT FAILED -- *************************\n\n");
    if (err == -1) {
        printf("configfile error\n");               //打印“配置配置文件错误”
    }
    printf("\n******************************************************************************\n\n");
}
_log_preinit_(glog_p);                              //进程资源，在debugout.h都是使用。声明zlog的使用

extern int32 CreateProcess(pchar config, pchar goblogswth, pchar keywordfilepath);

int32 main (int argc, char  *argv[])
{
    if (argc < 4) {
        print_usage();
        return -1;
    }

    _log_init_(glog_p, fileclient);

    while (1) {
        pid_t pid;
        if ((pid = fork()) == 0) {

            //执行条件出错，程序退出
            int32 k = CreateProcess(argv[1], argv[2], argv[3]);
            if (k > 0) {
                while (1) sleep(60);
            } else {
                print_errnum(k);
                sleep(5);
                exit(PROCESSERROR);
            }
        } else if (pid < 0) {

            PRINT_ERR_HEAD;
            print_err("Fileclient fork failed!");
        } else {
            int32 status;
            waitpid(pid, &status, 0);

            PRINT_ERR_HEAD;
            print_err("Fileclient pid = %d, status = %d!", pid, status);
            if (WIFEXITED(status) && (WEXITSTATUS(status) == PROCESSERROR)) break;
        }
    }
    _log_finish_(glog_p);
    return 0;
}