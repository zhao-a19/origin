/*******************************************************************************************
*文件:  FCLogTran.cpp
*描述:  外网向内网发送日志
*作者:  王君雷
*日期:  2014
*
*修改:
*           封装函数LogTranRecvMsgAck，记录下最后一次传输日志成功的时间  ------> 2016-01-25
*           发送失败时避免死循环                                         ------> 2016-06-24
*           解决删除表SYSTEM_STATUS返回成功，而实际没有删除掉的问题      ------> 2016-12-12
*           线程ID使用pthread_t类型                                      ------> 2018-08-07
*           修改指针没有为空判断导致进程死掉的BUG                        ------> 2019-05-15
*           select查询添加limit条数限制                                  ------> 2019-07-10
*           外网同步日志线程移动到recvmain                               ------> 2019-11-19-dzj
*           mysql.h使用系统头文件                                        ------> 2020-04-11-wjl
*           可以设置线程名称                                             ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "define.h"
#include "struct_info.h"
#include "mysql.h"
#include "simple.h"
#include "FCLogTran.h"
#include "quote_global.h"
#include "FCMsgAck.h"
#include "debugout.h"
#include "common.h"

#define LOG_TRAN_CYCLE        2  //外网向内网发送日志的周期s

//日志传输部分接收确认
int LogTranRecvMsgAck(int fd, struct sockaddr_in *addr, socklen_t addrlen)
{
    return RecvMsgAck(fd, addr, addrlen, LOG_INFO_TYPE, NULL);
}

//传输交换日志
int calllog_tran(MYSQL *pmysql)
{
    pthread_setself("logtran");
    PRINT_DBG_HEAD
    print_dbg("call log tran begin...");

    MYSQL_RES *m_res;
    MYSQL_ROW m_row;

    HEADER header;
    header.appnum = LOG_INFO_TYPE;
    char sql[256] = {0};
    char sqlstr[MAX_SQL_LEN] = {0};
    unsigned int length = 0;
    int ret, fd;
    char sql_com[sizeof(HEADER) + sizeof(length) + sizeof(sqlstr)] = {0};

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("fd socket");
        return -1;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("call log tran. socket ok[%d]", fd);

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //查询条件
    sprintf(sql, "select id,optime,opuser,srcip,dstip,srcport,dstport,"
            "service,cmd,param,result,remark,ifsend,isout,alarm,srcmac,dstmac from CallLOG order by id limit 10000");
    if (mysql_query(pmysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //查询结果放入m_res中
    m_res = mysql_store_result(pmysql);
    if (m_res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(pmysql));
        close(fd);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("call log fetch row ...");

    //处理查询结果
    while (1) {
        m_row = mysql_fetch_row(m_res);
        if (m_row == NULL) {
            break;
        }

        char para[MAX_PARA_NAME_LEN * 2] = {0};
        CCommon common;
        common.SpecialChar(m_row[9], strlen(m_row[9]), para, sizeof(para));

        //组装一条将发送的消息
        BZERO(sqlstr);
        BZERO(sql_com);
        sprintf(sqlstr, "INSERT INTO CallLOG"
                "(optime,opuser,srcip,dstip,srcport,dstport,service,cmd,param,result,remark,ifsend,isout,alarm,srcmac,dstmac)"
                "values('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%s,%s,%s,'%s','%s')",
                m_row[1], m_row[2], m_row[3], m_row[4], m_row[5], m_row[6], m_row[7], m_row[8], para,
                m_row[10], m_row[11], m_row[12], m_row[13], m_row[14], m_row[15], m_row[16]);
        length = sizeof(length) + strlen(sqlstr);
        memcpy(sql_com, &header, sizeof(header));
        memcpy(sql_com + sizeof(header), &length, sizeof(length));
        memcpy(sql_com + sizeof(header) + sizeof(length), sqlstr, strlen(sqlstr));

        //发送给内网
        ret = sendto( fd, sql_com, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("log_tran sendto");
            close(fd);
            mysql_free_result(m_res);
            return -1;
        }

        if (LogTranRecvMsgAck(fd, &addr, sizeof(addr)) == 0) {
            //删除这条记录
            sprintf(sql, "delete from CallLOG where id = %s", m_row[0]);
            if (mysql_query(pmysql, sql) != 0) {
                PRINT_ERR_HEAD
                print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
                close(fd);
                mysql_free_result(m_res);
                return -1;
            }
        }
    }

    close(fd);
    mysql_free_result(m_res);

    PRINT_DBG_HEAD
    print_dbg("call log tran over...");
    return 0;
}

//传输系统日志
int syslog_tran(MYSQL *pmysql)
{
    PRINT_DBG_HEAD
    print_dbg("sys log tran begin...");
    MYSQL_RES *m_res;
    MYSQL_ROW m_row;

    HEADER header;
    header.appnum = LOG_INFO_TYPE;
    char sql[256] = {0};
    char sqlstr[MAX_SQL_LEN] = {0};
    unsigned int length = 0;
    int ret, fd;
    char sql_com[sizeof(HEADER) + sizeof(length) + sizeof(sqlstr)] = {0};

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("fd socket");
        return -1;
    }
    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    sprintf(sql, "select id,optime,logtype,result,remark,ifsend,isout,alarm from SYSLOG order by id limit 10000");
    if (mysql_query(pmysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //查询结果放入m_res中
    m_res = mysql_store_result(pmysql);
    if (m_res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //处理查询结果
    while (1) {
        m_row = mysql_fetch_row(m_res);
        if (m_row == NULL) {
            break;
        }

        //组装一条将发送的消息
        BZERO(sqlstr);
        BZERO(sql_com);
        sprintf(sqlstr, "INSERT INTO SYSLOG"
                "(optime,logtype,result,remark,ifsend,isout,alarm) values('%s','%s','%s','%s',%s,%s,%s)",
                m_row[1], m_row[2], m_row[3], m_row[4], m_row[5], m_row[6], m_row[7]);
        length = sizeof(length) + strlen(sqlstr);

        memcpy(sql_com, &header, sizeof(header));
        memcpy(sql_com + sizeof(header), &length, sizeof(length));
        memcpy(sql_com + sizeof(header) + sizeof(length), sqlstr, strlen(sqlstr));

        //发送给内网
        ret = sendto( fd, sql_com, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("log_tran sendto");
            close(fd);
            mysql_free_result(m_res);
            return -1;
        }

        if (LogTranRecvMsgAck(fd, &addr, sizeof(addr)) == 0) {
            //删除这条记录
            sprintf(sql, "delete from SYSLOG where id = %s", m_row[0]);
            if (mysql_query(pmysql, sql) != 0) {
                PRINT_ERR_HEAD
                print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
                close(fd);
                mysql_free_result(m_res);
                return -1;
            }
        }
    }

    close(fd);
    mysql_free_result(m_res);
    return 0;
}

//传输连接日志
int linklog_tran(MYSQL *pmysql)
{
    PRINT_DBG_HEAD
    print_dbg("link log tran begin...");
    MYSQL_RES *m_res;
    MYSQL_ROW m_row;

    HEADER header;
    header.appnum = LOG_INFO_TYPE;
    char sql[256] = {0};
    char sqlstr[MAX_SQL_LEN] = {0};
    unsigned int length = 0;
    int ret, fd;
    char sql_com[sizeof(HEADER) + sizeof(length) + sizeof(sqlstr)] = {0};

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("fd socket");
        return -1;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if ( ret <= 0 ) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //查询条件
    sprintf(sql, "select id,optime,srcip,destip,sport,dport,remark,ifsend,isout,alarm,srcmac,dstmac from "
            "LINKLOG order by id limit 10000");
    if (mysql_query(pmysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
        close(fd);
        return -1;
    }
    m_res = mysql_store_result(pmysql);
    if (m_res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //处理查询结果
    while (1) {
        m_row = mysql_fetch_row(m_res);
        if (m_row == NULL) {
            break;
        }

        BZERO(sqlstr);
        BZERO(sql_com);
        sprintf(sqlstr, "INSERT INTO LINKLOG"
                "(optime,srcip,destip,sport,dport,remark,ifsend,isout,alarm,srcmac,dstmac)"
                "values('%s','%s','%s','%s','%s','%s',%s,%s,%s,'%s','%s')",
                m_row[1], m_row[2], m_row[3], m_row[4], m_row[5], m_row[6], m_row[7],
                m_row[8], m_row[9], m_row[10], m_row[11]);
        length = sizeof(length) + strlen(sqlstr);

        memcpy(sql_com, &header, sizeof(header));
        memcpy(sql_com + sizeof(header), &length, sizeof(length));
        memcpy(sql_com + sizeof(header) + sizeof(length), sqlstr, strlen(sqlstr));

        //发送给内网
        ret = sendto( fd, sql_com, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("log_tran sendto");
            close(fd);
            mysql_free_result(m_res);
            return -1;
        }

        if (LogTranRecvMsgAck(fd, &addr, sizeof(addr)) == 0) {
            sprintf(sql, "delete from LINKLOG where id = %s", m_row[0]);
            if (mysql_query(pmysql, sql) != 0) {
                PRINT_ERR_HEAD
                print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
                close(fd);
                mysql_free_result(m_res);
                return -1;
            }
        }
    }

    close(fd);
    mysql_free_result(m_res);
    return 0;
}

//传输系统状态日志
int system_status_tran(MYSQL *pmysql)
{
    PRINT_DBG_HEAD
    print_dbg("system status log tran begin...");
    MYSQL_RES *m_res;
    MYSQL_ROW m_row;

    HEADER header;
    header.appnum = LOG_INFO_TYPE;
    char sql[256] = {0};
    char sqlstr[MAX_SQL_LEN] = {0};
    unsigned int length = 0;
    int ret, fd;
    char sql_com[sizeof(HEADER) + sizeof(length) + sizeof(sqlstr)] = {0};

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("fd socket");
        return -1;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if ( ret <= 0 ) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //查询条件
    sprintf(sql, "select id,optime,link_num,cpu_info,disk_info,"
            "mem_info,net_info,net_flow,dev_status,descr,record,ifsend,isout,alarm "
            "from SYSTEM_STATUS order by id limit 10000");
    if (mysql_query(pmysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //查询结果放入m_res中
    m_res = mysql_store_result(pmysql);
    if (m_res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //处理查询结果
    while (1) {
        m_row = mysql_fetch_row(m_res);
        if (m_row == NULL) {
            break;
        }

        //组装一条将发送的消息
        BZERO(sqlstr);
        BZERO(sql_com);
        sprintf(sqlstr, "INSERT INTO SYSTEM_STATUS"
                "(optime,link_num,cpu_info,disk_info,mem_info,net_info,net_flow,dev_status,descr,"
                "record,ifsend,isout,alarm) values('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%s,%s,%s)",
                m_row[1], m_row[2], m_row[3], m_row[4], m_row[5], m_row[6], m_row[7], m_row[8],
                m_row[9], m_row[10], m_row[11], m_row[12], m_row[13]);
        length = sizeof(length) + strlen(sqlstr);

        memcpy(sql_com, &header, sizeof(header));
        memcpy(sql_com + sizeof(header), &length, sizeof(length));
        memcpy(sql_com + sizeof(header) + sizeof(length), sqlstr, strlen(sqlstr));

        //发送给内网
        for (int i = 0; i < 3; i++) {
            ret = sendto( fd, sql_com, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
            if (ret < 0) {
                perror("log_tran sendto");
                close(fd);
                mysql_free_result(m_res);
                return -1;
            }

            if (LogTranRecvMsgAck(fd, &addr, sizeof(addr)) == 0) {
                break;
            }
        }

        //删除这条记录
        sprintf(sql, "delete from SYSTEM_STATUS where id = %s", m_row[0]);
        if (mysql_query(pmysql, sql) != 0) {
            PRINT_ERR_HEAD
            print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
            close(fd);
            mysql_free_result(m_res);
            return -1;
        } else {
            if (mysql_affected_rows(pmysql) == 0) {
                //被删除的记录数为0
                mysql_query(pmysql, "delete from SYSTEM_STATUS");
            }
        }
    }

    close(fd);
    mysql_free_result(m_res);
    return 0;
}

//传输内容过滤日志
int filterlog_tran(MYSQL *pmysql)
{
    PRINT_DBG_HEAD
    print_dbg("filter log tran begin...");
    MYSQL_RES *m_res;
    MYSQL_ROW m_row;

    HEADER header;
    header.appnum = LOG_INFO_TYPE;
    char sql[256] = {0};
    char sqlstr[MAX_SQL_LEN] = {0};
    unsigned int length = 0;
    int ret, fd;
    char sql_com[sizeof(HEADER) + sizeof(length) + sizeof(sqlstr)] = {0};

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("fd socket");
        return -1;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if ( ret <= 0 ) {
        perror("inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    sprintf(sql, "select id,optime,opuser,fname,remark,ifsend,isout,alarm,service,srcip,dstip,"
            "srcport,dstport from FILTERLOG order by id limit 10000");
    if (mysql_query(pmysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //查询结果放入m_res中
    m_res = mysql_store_result(pmysql);
    if (m_res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(pmysql));
        close(fd);
        return -1;
    }

    //处理查询结果
    while (1) {
        m_row = mysql_fetch_row(m_res);
        if (m_row == NULL) {
            break;
        }

        //组装一条将发送的消息
        BZERO(sqlstr);
        BZERO(sql_com);
        sprintf(sqlstr, "INSERT INTO FILTERLOG"
                "(optime,opuser,fname,remark,ifsend,isout,alarm,service,srcip,dstip,srcport,dstport) "
                "values('%s','%s','%s','%s',%s,%s,%s,'%s','%s','%s','%s','%s')",
                m_row[1], m_row[2], m_row[3], m_row[4], m_row[5], m_row[6], m_row[7], m_row[8],
                m_row[9], m_row[10], m_row[11], m_row[12]);
        length = sizeof(length) + strlen(sqlstr);
        memcpy(sql_com, &header, sizeof(header));
        memcpy(sql_com + sizeof(header), &length, sizeof(length));
        memcpy(sql_com + sizeof(header) + sizeof(length), sqlstr, strlen(sqlstr));

        //发送给内网
        ret = sendto( fd, sql_com, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("log_tran sendto");
            close(fd);
            mysql_free_result(m_res);
            return -1;
        }

        if (LogTranRecvMsgAck(fd, &addr, sizeof(addr)) == 0) {
            //删除这条记录
            sprintf(sql, "delete from FILTERLOG where id = %s", m_row[0]);
            if (mysql_query(pmysql, sql) != 0) {
                PRINT_ERR_HEAD
                print_err("mysql query fail[%s][%s]", sql, mysql_error(pmysql));
                close(fd);
                mysql_free_result(m_res);
                return -1;
            }
        }
    }

    close(fd);
    mysql_free_result(m_res);
    return 0;
}

void *log_tran(void *arg)
{
    PRINT_DBG_HEAD
    print_dbg("log tran begin...");

    MYSQL mysql;
    int cnt = 0;
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "%s*.log", WEBPROXY_RUN_CONF);

LOG_TRAN_TAG:
    //初始化连接mysql
    while (mysql_init_connect(&mysql) != 0) {
        sleep(1);
        printf("mysql_init_connect ... retry!cnt[%d]", cnt);
    }

    PRINT_DBG_HEAD
    print_dbg("log tran mysql connect ok...");

    while (1) {
        if (calllog_tran(&mysql) < 0) { break; }
        if (syslog_tran(&mysql) < 0) { break; }
        if (linklog_tran(&mysql) < 0) { break; }
        if (system_status_tran(&mysql) < 0) { break; }
        if (filterlog_tran(&mysql) < 0) { break; }

        sleep(LOG_TRAN_CYCLE);
        cnt++;

        //外网每(LOG_TRAN_CYCLE)个小时，删除一次webproxy日志文件
        if (cnt % 3600 == 0) {
            system(chcmd);
        }

        if (cnt >= 60 * 60 * 24 * 30) {
            cnt -= 60 * 60 * 24 * 30;
        }
    }
    PRINT_ERR_HEAD
    print_err("mysql query fail[%s]", mysql_error(&mysql));
    mysql_close(&mysql);
    sleep(5);
    goto LOG_TRAN_TAG;

    return NULL;
}

/**
 * [StartLogTran 启动日志传输线程]
 * @return  [启动成功返回0   否则返回负值]
 */
int StartLogTran(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, log_tran, NULL) != 0) {
        return -1;
    }
    return 0;
}
