/*******************************************************************************************
*文件:  smsmain.cpp
*描述:  短信告警
*作者:
*日期:
*修改:
*       支持zlog；支持ipv6                                            ------> 2019-03-06
*******************************************************************************************/
#include "FCBSTX.h"
#include "debugout.h"

loghandle glog_p = NULL;

/*
** 函数名称: main
** 函数功能: 进程主函数
** 传入参数: 无
** 传出参数: 无
** 引用函数:
** 返回值 : 无
** 备注 : 为客户接收进程主函数
*/
int main(int argc, char *argv[])
{
    _log_init_(glog_p, smsc);

    if ((argc < 5) || (strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "-help") == 0)) {
        printf("Using: %s KEY address port <cmd> [para0] [para1] [para2] [para3] [para4]....\n", argv[0]);
        return -1;
    }

    if (strcmp(argv[1], "ANMIT_SMS") != 0) {
        printf("KEY error!\n");
        PRINT_ERR_HEAD
        print_err("key error[%s]", argv[1]);
        return -2;
    }

    CBSUdpSockClient m_dev;
    if (m_dev.Open(argv[2], atoi(argv[3])) < 0) {
        printf("SmsClient Open Error!\n");
        PRINT_ERR_HEAD
        print_err("SmsClient Open Error[ip %s, port %s]", argv[2], argv[3]);
        return -3;
    }

    char cmds[300] = {0};
    char para[300] = {0};
    char sendstr[300] = {0};
    snprintf(cmds, sizeof(cmds), "%s:", argv[4]);
    for (int i = 5; i < argc; i++) {
        if (i > 5) {
            strcat(para, "|");
        }
        strcat(para, argv[i]);
    }

    snprintf(sendstr, sizeof(sendstr), "%s%s", cmds, para);

    int res = m_dev.Send((unsigned char *)sendstr, strlen(sendstr));
    printf("send cmd=%s res=%d\n", sendstr, res);
    if (res > 0) {
        PRINT_DBG_HEAD
        print_dbg("send sms ok.sendstr[%s] res[%d]", sendstr, res);
    } else {
        PRINT_ERR_HEAD
        print_err("send sms fail.sendstr[%s] res[%d]", sendstr, res);
    }

    m_dev.Close();
    return res;
}
