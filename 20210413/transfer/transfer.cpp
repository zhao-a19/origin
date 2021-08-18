/*******************************************************************************************
*文件:  transfer.cpp
*描述:  TCP传输文件
*作者:  王君雷
*日期:  2020-03-07
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "transfer.h"
#include "transfer_server.h"
#include "transfer_client.h"
#include "debugout.h"

loghandle glog_p = NULL;
enum {
    ROLE_UNKNOWN = 0,
    ROLE_SERVER = 1,
    ROLE_CLIENT,
};

#define SELF_VERSION "20201221"

/**
 * [usage 使用介绍]
 * @param name [程序名称]
 */
void Usage(const char *name)
{
    printf("Usage(%s build time:%s %s):\n\t%s <-S |-C> <-a ipaddress> <-p port> [-s spath] [-d dpath] [-P perm] [-t threadnum] [-m mode]\n\n",
           SELF_VERSION, __DATE__, __TIME__, name);
    printf(" -S           #server model\n");
    printf(" -C           #client model\n");
    printf(" -a ipaddress #ip address.ipv4 or ipv6\n");
    printf(" -p port      #port\n");
    printf("\nserver model options:\n");
    printf(" -t threadnum #how many threads to create in thread pool. %d by default\n", DEFAULT_THREAD_NUM);
    printf("\nclient model options:\n");
    printf(" -s spath     #source file path\n");
    printf(" -d dpath     #destination file path,absolute path required\n");
    printf(" -P perm      #permission. 1 means executable, while 0 means the opposite\n");
    printf(" -m mode      #mode. 0 means asynchronous,1 means synchronous, 0 by default.\n");
}

int main (int argc, char **argv)
{
    _log_init_(glog_p, transfer);

    int ch;
    int role = ROLE_UNKNOWN;
    const char *ip = NULL;
    const char *port = NULL;
    const char *spath = NULL;
    const char *dpath = NULL;
    const char *perm = NULL;
    const char *threadnum = NULL;
    const char *mode = NULL;

    while ((ch = getopt(argc, argv, "SCa:p:s:d:P:t:m:")) != -1) {
        switch (ch) {
        case 'S':
            role = ROLE_SERVER;
            break;
        case 'C':
            role = ROLE_CLIENT;
            break;
        case 'a':
            ip = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 's':
            spath = optarg;
            break;
        case 'd':
            dpath = optarg;
            break;
        case 'P':
            perm = optarg;
            break;
        case 't':
            threadnum = optarg;
            break;
        case 'm':
            mode = optarg;
            break;
        case '?':
            printf("Unknown option: %c\n", (char)optopt);
            break;
        }
    }

    if ((role == ROLE_SERVER) && (ip != NULL) && (port != NULL)) {

        int tnum = (threadnum == NULL) ? DEFAULT_THREAD_NUM : atoi(threadnum);
        PRINT_DBG_HEAD
        print_dbg("server begin.ip[%s] port[%s] threadnum[%d]", ip, port, MIN(tnum, MAX_THREAD_NUM));

        do_server(ip, atoi(port), MIN(tnum, MAX_THREAD_NUM));
    } else if ((role == ROLE_CLIENT) && (ip != NULL) && (port != NULL)
               && (spath != NULL) && (dpath != NULL) && (perm != NULL)) {
        int modenum = (mode == NULL) ? DEFAULT_MODE : atoi(mode);

        PRINT_DBG_HEAD
        print_dbg("client begin.ip[%s] port[%s] spath[%s] dpath[%s] perm[%s] mode[%d]",
                  ip, port, spath, dpath, perm, modenum);

        do_client(ip, atoi(port), spath, dpath, atoi(perm), modenum);
    } else {
        Usage(argv[0]);
    }
    return 0;
}
