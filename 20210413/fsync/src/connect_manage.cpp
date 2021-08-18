/*******************************************************************************************
*文件:    connect_manager.cpp
*描述:    链接管理模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10
*1.修改挂载函数，增加总路径检测成功日志。                       ------>2020-02-24
*2.增加所有子路径检测函数                                       ------> 2020-03-01
*3.添加挂载状态检测函数                                         ------> 2020-03-01
*3.修改路径检查相关函数                                         ------> 2020-03-03
*4.网络异常检查增加失败重试逻辑                                 ------> 2020-03-05
*5.挂载状态检查完善                                             ------> 2020-03-05
*6.优化网络异常写日志逻辑                                       ------> 2020-03-13
*******************************************************************************************/
#include "connect_manage.h"
#include "common_func.h"
#include "utf8_code.h"

#ifndef __linux__

#define mount(...) 0
#define umount(...)
#define MS_NOEXEC 0

#endif


/*******************************************************************************************
*功能:      检查所有服务器连接
*参数:      rule               ----> 策略信息
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool check_all_internet(fs_rule_t *rule) {

    bool bret = false;
    char buf[FSYNC_NAME_MAX_LEN] = {0};
    CLOGMANAGE web_log;
    web_log.Init(rule->syslog_flag);

    bret = check_server_internet(rule->int_srv.use_ip, rule->int_srv.port);
    if ((!bret) && (rule->log_flag == FSYNC_TURN_ON)) {
        sprintf(buf, "%s%s", CONNECT_FAILED, INT_SRV);
        web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip, "", rule->int_srv.real_ip, "", "",
                                 S_FAILED, buf, false);
    }

    if (bret) {
        bret = check_server_internet(rule->out_srv.use_ip, rule->out_srv.port);
        if ((!bret) && (rule->log_flag == FSYNC_TURN_ON)) {
            sprintf(buf, "%s%s", CONNECT_FAILED, OUT_SRV);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_srv.real_ip, "", rule->out_srv.real_ip, "", "",
                                     S_FAILED, buf, true);
        }
    }

    if (bret && (rule->int_bak_flag != FSYNC_TURN_OFF)) {
        bret = check_server_internet(rule->int_bak.use_ip, rule->int_bak.port);
        if ((!bret) && (rule->log_flag == FSYNC_TURN_ON)) {
            sprintf(buf, "%s%s", CONNECT_FAILED, INT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_bak.real_ip, "", rule->int_bak.real_ip, "", "",
                                     S_FAILED, buf, false);
        }
    }

    if (bret && (rule->out_bak_flag != FSYNC_TURN_OFF)) {
        bret = check_server_internet(rule->out_bak.use_ip, rule->out_bak.port);
        if ((!bret) && (rule->log_flag == FSYNC_TURN_ON)) {
            sprintf(buf, "%s%s", CONNECT_FAILED, OUT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_bak.real_ip, "", rule->out_bak.real_ip, "", "",
                                     S_FAILED, buf, true);
        }
    }

    return bret;
}

/*******************************************************************************************
*功能:      服务器连接检查
*参数:     in_to_out           ----> 同步方向
*          rule                ----> 策略信息
*          srv_info            ----> 服务器信息
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool check_server_internet(const char *ip, int port) {

    bool bret = false;

    for (int i = 0; i < FSYNC_CONNECT_TIMES; i++) {
        if (strchr(ip, ':') != NULL) {
            bret = ipv6_tcp_connect(ip, port);
        } else {
            bret = ipv4_tcp_connect(ip, port);
        }
        if (bret) {
            break;
        }
        sleep(FSYNC_CONNECT_TIMES);
    }

    return bret;
}

/*******************************************************************************************
*功能:        ipv4的tcp连接检测
*参数:        remote_ip                          ----> IP地址
*            port                         ---->  目标列表
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool ipv4_tcp_connect(const char *ip, int port) {
    bool bret = false;
    int sock_fd = -1;
    struct sockaddr_in dest4;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create sock_fd failed:%s", strerror(sock_fd));
        bret = false;
    } else {
        bret = true;
    }

    if (bret) {
        struct timeval time_out = {5, 0};
        if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;
            print_err("set time out failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }

    bzero(&dest4, sizeof(dest4));
    dest4.sin_family = AF_INET;
    dest4.sin_port = htons(port);
    if (bret) {
        if (inet_pton(AF_INET, ip, &dest4.sin_addr) != 1) {
            PRINT_ERR_HEAD;
            print_err("inet pton failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }
    if (bret) {
        if (connect(sock_fd, (struct sockaddr *) &dest4, sizeof(dest4)) != 0) {
            PRINT_ERR_HEAD;
            print_err("connect failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }

    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("connect remote_ip = %s ,port = %d success", ip, port);
    } else {
        PRINT_ERR_HEAD;
        print_err("connect remote_ip = %s ,port = %d failed", ip, port);
    }
    close(sock_fd);
    return bret;
}

/*******************************************************************************************
*功能:        ipv6的tcp连接检测
*参数:        remote_ip                          ----> IP地址
*            port                         ---->  目标列表
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool ipv6_tcp_connect(const char *ip, int port) {
    bool bret = false;
    int sock_fd = 0;
    struct sockaddr_in6 dest6;

    sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create sock_fd failed:%s", strerror(sock_fd));
        bret = false;
    } else {
        bret = true;
    }

    if (bret) {
        struct timeval time_out = {5, 0};
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;
            print_err("set time out failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }

    bzero(&dest6, sizeof(dest6));
    dest6.sin6_family = AF_INET6;
    dest6.sin6_port = htons(port);
    if (bret) {
        if (inet_pton(AF_INET6, ip, &dest6.sin6_addr) != 1) {
            PRINT_ERR_HEAD;
            print_err("inet pton failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }
    if (bret) {
        if (connect(sock_fd, (struct sockaddr *) &dest6, sizeof(dest6)) != 0) {
            PRINT_ERR_HEAD;
            print_err("connect failed:%s", strerror(errno));
            bret = false;
        } else {
            bret = true;
        }
    }

    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("connect remote_ip = %s ,port = %d success", ip, port);
    } else {
        PRINT_ERR_HEAD;
        print_err("connect remote_ip = %s ,port = %d failed", ip, port);
    }
    close(sock_fd);
    return bret;
}

