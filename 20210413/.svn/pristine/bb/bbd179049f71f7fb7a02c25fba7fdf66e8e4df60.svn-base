/*******************************************************************************************
*文件: ausvr.cpp
*描述: 授权服务程序
*作者: 王君雷
*日期: 2018-09-20
*修改:
*     授权无效时，删除用户信息文件
*     管理口信息通过命令行参数传进去，不用读取配置文件了               ------> 2018-09-28
*     使用新建的au_logtrans.h,方便工程移植                             ------> 2018-10-12
*     包含头文件au_define.h,移动头文件中不需要暴露出去的信息;
*     修改BUG,系统时间修改到超期后的时间,没有把最后时间更新到授权文件  ------> 2018-10-15
*     对于使用CST时区的系统 签发时间做偏移                             ------> 2019-01-17
*     可以设置线程名称                                                ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ausvr.h"
#include "au_define.h"
#include "au_logtrans.h"
#include "debugout.h"
#include "authinfo.h"
#include "FCMD5.h"
#include "common.h"

loghandle glog_p = NULL;
bool g_authexpired = false;

#define CREATE_TIME "2019-01-17"
#define WEB_SHOW_AUTH "/etc/init.d/sysver.cf" //WEB读取该文件 展示授权时长状态信息
#define WEB_SHOW_USER "/etc/init.d/userver.cf"//WEB读取该文件 展示用户名称（项目名称）等信息

/**
 * [clear_webshow 清空WEB展示使用的文件]
 */
void clear_webshow()
{
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "echo %s>%s", AUTH_INVALIED_VERSION, WEB_SHOW_AUTH);
    system(chcmd);
    sprintf(chcmd, "rm -f %s", WEB_SHOW_USER);
    system(chcmd);
}

/**
 * [wirte_usershow 把用户信息输出到文件]
 * @param authbody [body]
 */
void wirte_usershow(AUTH_BODY &authbody)
{
    char chcmd[CMD_BUF_LEN] = {0};
    if (strcmp(authbody.user, "") == 0) {
        sprintf(chcmd, "rm  -f %s", WEB_SHOW_USER);
        system(chcmd);
    } else {
        sprintf(chcmd, "echo %s >%s", authbody.user, WEB_SHOW_USER);
        system(chcmd);
    }
}

/**
 * [auth_timeok 判断授权是否ok]
 * @param  authbody [body]
 * @return          [没过期返回true]
 */
bool auth_timeok(AUTH_BODY &authbody)
{
    int64 tnow = time(NULL);

    if ((tnow >= authbody.starttime)
        && (tnow <= authbody.stoptime)
        && (tnow >= authbody.lastupdate)) {
        return true;
    }

    PRINT_ERR_HEAD
    print_err("auth time not ok.start[%lld] stop[%lld] lastupdate[%lld] now[%lld]",
              authbody.starttime, authbody.stoptime, authbody.lastupdate, tnow);

    return false;
}

/**
 * [write_timeshow 把授权时间信息输出到文件]
 * @param authbody [body]
 */
void write_timeshow(AUTH_BODY &authbody)
{
    char chcmd[CMD_BUF_LEN] = {0};
    int day = 0;

    if (authbody.authday == AUTH_FOREVER) {
        sprintf(chcmd, "echo %s > %s", AUTH_FOREVER_VERSION, WEB_SHOW_AUTH);
        system(chcmd);
    } else {
        if (auth_timeok(authbody)) {
            day = (authbody.stoptime - time(NULL)) / SECONDS_PER_DAY;
            sprintf(chcmd, "echo %s %d > %s", AUTH_TEMP_VERSION, day, WEB_SHOW_AUTH);
            system(chcmd);
        } else {
            sprintf(chcmd, "echo %s > %s", AUTH_EXPIRED_VERSION, WEB_SHOW_AUTH);
            system(chcmd);
        }
    }
}

/**
 * [set_auth_time 设置结构体中时间相关字段]
 * @param authbody [body]
 */
void set_auth_time(AUTH_BODY &authbody)
{
    int64 tnow = time(NULL);

    if (authbody.authday == AUTH_FOREVER) {
        //对于永久授权
    } else if (authbody.authday == AUTH_DEFAULT) {
        //对于默认90天的授权 不以签发时间计算 以第一次运行时的系统时间来计算
        authbody.starttime = tnow;
        authbody.stoptime = tnow + AUTH_DEFAULT_DAYS * SECONDS_PER_DAY;
        authbody.lastupdate = tnow;

        PRINT_INFO_HEAD
        print_info("auth is default[%d:%s],start[%lld] stop[%lld] lastupdate[%lld] now[%lld]",
                   authbody.authday, authbody.authid, authbody.starttime, authbody.stoptime, authbody.lastupdate, tnow);
    } else {
        //对于特定设备的授权 以签发时间计算
        authbody.starttime = CST_CALIBRATE(authbody.maketime);
        authbody.stoptime = authbody.starttime + authbody.authday * SECONDS_PER_DAY;
        authbody.lastupdate = tnow;

        PRINT_INFO_HEAD
        print_info("auth is specified[%d:%s],start[%lld] stop[%lld] lastupdate[%lld] now[%lld]",
                   authbody.authday, authbody.authid, authbody.starttime, authbody.stoptime, authbody.lastupdate, tnow);
    }
}

/**
 * [authbak 授权文件备份]
 * @param src [源拷贝路径]
 * @param dst [目的拷贝路径]
 */
void authbak(const char *src, const char *dst)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if ((src != NULL) && (dst != NULL)) {
        PRINT_DBG_HEAD
        print_dbg("auth bak");

        snprintf(chcmd, sizeof(chcmd), "cp -f %s %s", src, dst);
        system(chcmd);
        system("sync");
    }
}

/**
 * [do_with_heartbeat 处理一个心跳连接]
 * @param clifd [描述符]
 */
void do_with_heartbeat(int clifd)
{
    int rlen = 0, wlen = 0;
    char requestbuff[HEARTBEAT_REQUEST_LEN] = {0};
    AU_RESPONSE response;
    CCommon common;

    int yes = 1;
    setsockopt(clifd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

    //接收心跳
    rlen = recv(clifd, requestbuff, sizeof(requestbuff), 0);
    if (rlen <= 0) {
        PRINT_ERR_HEAD
        print_err("recv error[%d:%s]", rlen, strerror(errno));
        close(clifd);
        return;
    }

    //请求字符置换
    common.CharReplace(requestbuff, sizeof(requestbuff));

    //求MD5
    if (!md5sum_buff(requestbuff, sizeof(requestbuff), NULL, response.md5buff32)) {
        PRINT_ERR_HEAD
        print_err("md5sum buff fail");
        close(clifd);
        return;
    }
    response.result = g_authexpired ? AUSVR_RESULT_FAIL : AUSVR_RESULT_OK;

    //心跳回应
    wlen = send(clifd, &response, sizeof(response), 0);
    if (wlen != sizeof(response)) {
        PRINT_ERR_HEAD
        print_err("send response fail[%d:%s]", wlen, strerror(errno));
        close(clifd);
        return;
    }

    //关闭
    close(clifd);
    return;
}

/**
 * [heartbeat_proc 心跳服务线程函数]
 * @param  argv [暂未使用]
 * @return      [暂未使用]
 */
void *heartbeat_proc(void *argv)
{
    pthread_setself("heartbeat");
    int fd = 0, clifd = 0;
    struct sockaddr_un addr_srv, addr_cli;
    socklen_t addr_len = 0;

    //socket
    while ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) <= 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        sleep(5);
    }

    //addr
    if (strlen(UNIX_AUTHSVR) >= sizeof(addr_srv.sun_path)) {
        PRINT_ERR_HEAD
        print_err("unixpath too long[%s], max support %d", UNIX_AUTHSVR, (int)sizeof(addr_srv.sun_path));
        close(fd);
        return NULL;
    }
    BZERO(addr_srv);
    addr_srv.sun_family = AF_LOCAL;
    strcpy(addr_srv.sun_path, UNIX_AUTHSVR);
    unlink(UNIX_AUTHSVR);

    //bind
    if (bind(fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error[%s]", strerror(errno));
        close(fd);
        return NULL;
    }

    //listen
    if (listen(fd, 10) < 0) {
        PRINT_ERR_HEAD
        print_err("listen error[%s]", strerror(errno));
        close(fd);
        return NULL;
    }

    while (1) {
        //接收客户端连接
        BZERO(addr_cli);
        addr_len = sizeof(addr_cli);
        clifd = accept(fd, (struct sockaddr *)&addr_cli, &addr_len);
        if (clifd < 0) {
            PRINT_ERR_HEAD
            print_err("accept error[%s]", strerror(errno));
            continue;
        }

        do_with_heartbeat(clifd);
    }

    return NULL;
}

/**
 * [start_au_ck_thread 启动心跳服务线程]
 * @return [成功返回true]
 */
bool start_au_ck_thread()
{
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, heartbeat_proc, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create process heartbeat fail");
        return false;
    }
    return true;
}

/**
 * [start_authcheck 授权定期检查程序]
 * @param  authhead [头部]
 * @param  authbody [body]
 * @return      [description]
 */
bool start_authcheck(AUTH_HEAD &authhead, AUTH_BODY &authbody)
{
    int64 tnow = 0;
    while (1) {
        if (auth_timeok(authbody)) {
            authbody.lastupdate = time(NULL);
            //把更新后的授权写入文件
            if (auth_tofile(authhead, authbody, AUTH_FILE_PATH1)) {
                authbak(AUTH_FILE_PATH1, AUTH_FILE_PATH2);
            }

            write_timeshow(authbody);
            PRINT_DBG_HEAD
            print_dbg("auth ok.remaining days[%.2f]",
                      (float)(authbody.stoptime - time(NULL)) / SECONDS_PER_DAY);
            sleep(5 * 60);
        } else {
            g_authexpired = true;
            tnow = time(NULL);
            //最后更新时间只会变大 不会变小
            if (authbody.lastupdate < tnow) {
                authbody.lastupdate = tnow;
                //把更新后的授权写入文件
                if (auth_tofile(authhead, authbody, AUTH_FILE_PATH1)) {
                    authbak(AUTH_FILE_PATH1, AUTH_FILE_PATH2);
                }
            }
            write_timeshow(authbody);
            PRINT_ERR_HEAD
            print_err("auth expired");
            break;
        }
    }

    return false;
}

/**
 * [auth_process 授权处理子进程]
 * @param  mancardname [管理网卡名称]
 * @return [成功返回true]
 */
bool auth_process(const char *mancardname)
{
    AUTH_HEAD authhead;
    AUTH_BODY authbody;

    if (read_authinfo(AUTH_FILE_PATH1, authhead, authbody)
        && check_auth(authhead, authbody, mancardname)) {

        //输出用户信息到文件
        wirte_usershow(authbody);
        //开启心跳服务线程
        start_au_ck_thread();

        //对于永久授权 可以退出了
        if (authbody.authday == AUTH_FOREVER) {
            write_timeshow(authbody);
            PRINT_DBG_HEAD
            print_dbg("auth forever[%s]", authbody.authid);
            return true;
        }

        //三者为空 说明是新导入的授权第一次运行
        if ((authbody.starttime == 0) && (authbody.stoptime == 0) && (authbody.lastupdate == 0)) {
            //填写起止时间及最后一次更新的时间
            set_auth_time(authbody);

            if (!get_mybindid(mancardname, authbody.bindid)) {
                return false;
            }
        }

        return start_authcheck(authhead, authbody);
    } else {

        PRINT_ERR_HEAD
        print_err("auth info error");
        clear_webshow();
        return false;
    }
}

/**
 * [usage 使用说明]
 * @param name [程序名称]
 */
void usage(const char *name)
{
    printf("Usage(%s):\n\t%s mancardname\n\n", CREATE_TIME, name);
}

int main(int argc, char **argv)
{
    int status = 0;
    _log_init_(glog_p, ausvr);

    PRINT_DBG_HEAD
    print_dbg("%s(%s) begin", argv[0], CREATE_TIME);

    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    while (1) {

        pid_t pid = 0;
        pid = fork();
        if (pid < 0) {

            //可能是内存不足 延迟数秒再创建
            PRINT_ERR_HEAD
            print_err("fork error(%s)", strerror(errno));
        } else if (pid == 0) {

            //子进程 启动处理程序
            auth_process(argv[1]);
            while (1) {
                sleep(1000);
            }
        } else {

            //父进程监视子进程有没有退出 退出就重新拉起
            waitpid(pid, &status, 0);
            PRINT_ERR_HEAD
            print_err("child process %d exit %s,status: %d. restart...",
                      pid, WIFEXITED(status) ? "normally" : "abnormally", status);
        }

        sleep(2);
    }

    return 0;
}
