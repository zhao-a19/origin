/*******************************************************************************************
*文件:    main.cpp
*描述:    后台配置文件扫描
*
*作者:    赵子昂
*日期:    2020-10-19
*修改:    创建文件                                             ------>     2020-10-19
*******************************************************************************************/
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "datatype.h"
#include "debugout.h"
#include "fileoperator.h"
#include "sysdir.h"
#include "syssocket.h"

static pchar VersionNO = "2.0.1";     //版本号,尾号为偶数表示正式版本，奇数为测试
extern int Diffcfg(void);
static void print_usage(void)
{
    printf("\n************************* -- diffcfg Ver%s -- **************************\n\n", VersionNO);
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    printf("\t(1)./diffcfg \n");
    printf("\n******************************************************************************\n\n");

}
loghandle glog_p = NULL;

int main(int argc, char const *argv[])
{
    if (argc > 1) {
        print_usage();
        exit(0);
    }
    _log_init_(glog_p, diffcfg);

    PRINT_INFO_HEAD
    print_info("info : diffcfg process begin");

    while (1) {
        pid_t pid = fork();
        if (pid < 0) {
            PRINT_ERR_HEAD
            print_err("diffcfg fork error !!");
        } else if (pid == 0) {
            if (Diffcfg() == -1) exit(0);
            while (1) {
                sleep(100);
            }
            exit(0);
        } else {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                PRINT_ERR_HEAD
                print_err("diffcfg : The child process %d exit normally,WEXITSTATUS code[%d],WIFEXITED code[%d]",
                          pid, WEXITSTATUS(status), WIFEXITED(status));
            } else {
                PRINT_ERR_HEAD
                print_err("The child process %d exit abnormally, Status is %d", pid, status);
            }
            PRINT_ERR_HEAD
            print_err("diffcfg restart !!");
            system("/etc/init.d/startall &");//防止段错误后应用配置完全失效
        }
        sleep(2);
    }

    return 0;
}