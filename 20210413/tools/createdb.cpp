/*******************************************************************************************
*文件:    createdb.cpp
*描述:    创建数据库表的工具
*作者:    王君雷
*日期:    2016
*修改:    添加创建表SECMGLOG功能                                   ------> 2016-06-08
*         添加创建表su_gap_sessions的功能                          ------> 2016-08-03
*         使用zlog记录日志                                         ------> 2018-07-23
*         随SYSLOG标准化一起表结构修改                             ------> 2020-01-16 wjl
*         MGLOG SECMGLOG CallLOG FILTERLOG,用户名字段扩大到100字节 ------> 2020-03-12
*         SYSTEM_STATUS表中net_flow字段类型改为BIGINT              ------> 2020-04-09 宋宇
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "FCLogManage.h"
#include "debugout.h"

loghandle glog_p = NULL;
#define CREATEDB_VER "2018-07-23"

int main(int argc, char *argv[])
{
    _log_init_(glog_p, createdb);

    if (argc < 2) {
        printf("Usage(%s):%s ip/hostname [tablename]\n", CREATEDB_VER, argv[0]);
        exit(-1);
    }

    CLOGMANAGE m_log;
    int res = m_log.Init(true, argv[1]);
    if (res == -1) {
        PRINT_ERR_HEAD
        print_err("create db init fail[%d]", res);
        exit(-1);
    }

    bool b_SYSTEM_STATUS = false;
    bool b_SYSLOG = false;
    bool b_MGLOG = false;
    bool b_SECMGLOG = false;
    bool b_CallLOG = false;
    bool b_LINKLOG = false;
    bool b_FILTERLOG = false;
    bool b_FileSyncLOG = false;
    bool b_DBSYNCLOG = false;
    bool b_su_gap_sessions = false;

    if (argc == 2) {
        b_SYSTEM_STATUS = true;
        b_SYSLOG = true;
        b_MGLOG = true;
        b_SECMGLOG = true;
        b_CallLOG = true;
        b_LINKLOG = true;
        b_FILTERLOG = true;
        b_FileSyncLOG = true;
        b_DBSYNCLOG = true;
        b_su_gap_sessions = true;
    } else if (strcmp(argv[2], "SYSTEM_STATUS") == 0) {
        b_SYSTEM_STATUS = true;
    } else if (strcmp(argv[2], "SYSLOG") == 0) {
        b_SYSLOG = true;
    } else if (strcmp(argv[2], "MGLOG") == 0) {
        b_MGLOG = true;
    } else if (strcmp(argv[2], "SECMGLOG") == 0) {
        b_SECMGLOG = true;
    } else if (strcmp(argv[2], "CallLOG") == 0) {
        b_CallLOG = true;
    } else if (strcmp(argv[2], "LINKLOG") == 0) {
        b_LINKLOG = true;
    } else if (strcmp(argv[2], "FILTERLOG") == 0) {
        b_FILTERLOG = true;
    } else if (strcmp(argv[2], "FileSyncLOG") == 0) {
        b_FileSyncLOG = true;
    } else if (strcmp(argv[2], "DBSYNCLOG") == 0) {
        b_DBSYNCLOG = true;
    } else if (strcmp(argv[2], "su_gap_sessions") == 0) {
        b_su_gap_sessions = true;
    } else {
        printf("tablename may error![%s]\n", argv[2]);
    }

    printf("begin create table...\n");

    if (b_SYSTEM_STATUS) {
        m_log.WriteToDB("drop table SYSTEM_STATUS");
        m_log.WriteToDB("create table SYSTEM_STATUS( \
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime datetime,\
            link_num integer,\
            cpu_info varchar(20),\
            disk_info varchar(20),\
            mem_info varchar(20),\
            net_info varchar(20),\
            net_flow BIGINT,\
            dev_status varchar(20),\
            descr varchar(80),\
            record varchar(20),\
            ifsend int,\
            isout boolean,\
            alarm boolean \
        );");
    }

    if (b_SYSLOG) {
        m_log.WriteToDB("drop table SYSLOG");
        m_log.WriteToDB("create table SYSLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            logtype varchar(50),\
            result varchar(50),\
            remark varchar(1000),\
            ifsend int,\
            isout boolean,\
            alarm boolean \
        );");
    }

    if (b_MGLOG) {
        m_log.WriteToDB("drop table MGLOG");
        m_log.WriteToDB("create table MGLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            opuser varchar(100),\
            logtype varchar(50),\
            result varchar(50),\
            remark varchar(1000),\
            ifsend int,\
            alarm boolean,\
            ipaddr varchar(100) \
        );");
    }

    if (b_SECMGLOG) {
        m_log.WriteToDB("drop table SECMGLOG");
        m_log.WriteToDB("create table SECMGLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            opuser varchar(100),\
            logtype varchar(50),\
            result varchar(50),\
            remark varchar(1000),\
            ifsend int,\
            alarm boolean, \
            ipaddr varchar(100) \
        );");
    }

    if (b_CallLOG) {
        m_log.WriteToDB("drop table CallLOG");
        m_log.WriteToDB("create table CallLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            opuser varchar(100),\
            srcip varchar(50),\
            dstip varchar(50),\
            srcport varchar(10),\
            dstport varchar(10),\
            service varchar(50),\
            cmd varchar(50),\
            param varchar(100),\
            result varchar(50),\
            remark varchar(1000),\
            ifsend int,\
            isout boolean,\
            alarm boolean,\
            srcmac varchar(20),\
            dstmac varchar(20)\
        );");
    }

    if (b_LINKLOG) {
        m_log.WriteToDB("drop table LINKLOG");
        m_log.WriteToDB("create table LINKLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            srcip varchar(50),\
            destip varchar(30),\
            sport varchar(10),\
            dport varchar(10),\
            remark varchar(1000),\
            ifsend int,\
            isout boolean,\
            alarm boolean,\
            srcmac varchar(20),\
            dstmac varchar(20)\
        );");
    }

    if (b_FILTERLOG) {
        m_log.WriteToDB("drop table FILTERLOG");
        m_log.WriteToDB("create table FILTERLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30),\
            opuser varchar(100),\
            fname varchar(1000),\
            remark varchar(1000),\
            ifsend int,\
            isout boolean,\
            alarm boolean,\
            service varchar(50),\
            srcip varchar(50),\
            dstip varchar(50),\
            srcport varchar(10),\
            dstport varchar(10)\
        );");
    }

    if (b_FileSyncLOG) {
        m_log.WriteToDB("drop table FileSyncLOG");
        m_log.WriteToDB("create table FileSyncLOG(\
            id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            task_id int,\
            optime varchar(30),\
            s_path varchar(4096),\
            filename varchar(4096),\
            result varchar(64),\
            remark varchar(1024),\
            ifsend int,\
            isout boolean,\
            alarm boolean,\
            srcip varchar(50),\
            dstip varchar(50),\
            taskname varchar(100),\
            d_path varchar(4096)\
        );");
    }

    if (b_DBSYNCLOG) {
        m_log.WriteToDB("drop table DBSYNCLOG");
        m_log.WriteToDB("create table DBSYNCLOG(\
            id BIGINT(22) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
            optime varchar(30) NULL,\
            name varchar(100) NULL,\
            logway varchar(20) NULL,\
            srcdb varchar(100) NULL,\
            srcip varchar(30) NULL,\
            destdb varchar(100) NULL,\
            destip varchar(30) NULL,\
            srctable varchar(100) NULL,\
            desttable varchar(100) NULL,\
            remark varchar(1000) NULL,\
            ifsend int,\
            isout boolean,\
            alarm boolean \
        );");
    }

    if (b_su_gap_sessions) {
        m_log.WriteToDB("drop table su_gap_sessions");
        m_log.WriteToDB("create table su_gap_sessions (\
            session_id varchar(60) DEFAULT '0' NOT NULL,\
            ip_address varchar(50) DEFAULT '0', \
            user_agent varchar(200), \
            last_activity bigint(20) DEFAULT 0,\
            user_data text DEFAULT '', \
            PRIMARY KEY (session_id)\
        )");
    }

    m_log.DisConnect();
    printf("Create table finish!!\n");
    return 1;
}
