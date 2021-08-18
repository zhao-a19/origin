/*******************************************************************************************
*文件:  monitor.c
*描述:  文件监视程序，当发现SYSRULES有变动时，重启sys6_test
*作者:  王君雷
*日期:  2015
*
*修改:
*       配置文件使用宏表示,改用linux风格,utf8编码                  ------> 2018-04-23
*       去掉killall命令后台执行符号，否则可能把接下来启动的程序杀掉------> 2018-04-24
*       使用STOP_SYS6_TEST宏                                       ------> 2018-08-28
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"

loghandle glog_p = NULL;

#define STOP_SYS6_TEST "killall sys6_test >/dev/null 2>&1"

/**
 * [readversion 读取版本信息]
 * @param  ver [版本 出参]
 * @param  len [版本缓冲区长度]
 * @return     [成功返回true]
 */
bool readversion(char *ver, int len)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(START_CF, "r") == E_FILE_FALSE) {
        return false;
    }
    m_fileop.ReadCfgFile("SYSTEM", "Version", ver, len);
    m_fileop.CloseFile();
    return true;
}

int main(int argc, char **argv)
{
    _log_init_(glog_p, monitor);

    char version[100] = {0};
    readversion(version, sizeof(version));

    struct stat buf;
    time_t tprev = 0;

    printf("version[%s]\n", version);

    if (strncmp(version, "test", 4) == 0) {
        //保存一开始文件的最后修改时间
        stat(RULE_CONF_TEST, &buf);
        tprev = buf.st_mtime;

        system(STOP_SYS6_TEST);
        system("busybox nohup /initrd/abin/sys6_test >/dev/null &");

        while (1) {
            usleep(1000);
            //当发现文件有变动
            stat(RULE_CONF_TEST, &buf);
            if (buf.st_mtime != tprev) {
                usleep(1000);//保证文件传输完毕
                system(STOP_SYS6_TEST);//重启
                system("busybox nohup /initrd/abin/sys6_test >/dev/null &");
                tprev = buf.st_mtime;
            }
        }
    } else {
    }

    return 0;
}
