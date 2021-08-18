/*
 *  Compilation: gcc -Wall ex1.c -o ex1 -lclamav
 *
 *  Copyright (C) 2007 - 2009 Sourcefire, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
/*******************************************************************************************
*修改:
*      把病毒库查杀服务的本地套接字路径放到gap_config.h中               ------> 2018-08-07
*      飞腾平台移植，飞腾平台使用较新版本的clamav接口                   ------> 2020-09-15
*      添加江民、瑞星、安天病毒引擎，添加选择开关                        ------->2021-01-28
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <errno.h>
#include <semaphore.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <clamav.h>
#include "gap_config.h"
#include "sysvirus.h"
#include "datatype.h"
#include "debugout.h"
#include "fileoperator.h"

/**
 * 病毒引擎选择
 */
enum {
    CAVLLIB = 0,   //安天病毒库
    CCLAMAVLIB,    //clamav病毒库
    CJMAVLIB,      //江民
    CRISINGAVLIB,  //瑞星
};

/**
 * [judge_size 判断文件是否需要查毒]
 * @param  fname [文件路径]
 * @return       [需要查毒返回true]
 */
bool judge_size(const char *fname)
{
    if (fname == NULL) {
        PRINT_ERR_HEAD;
        print_err("recv file is null! please check src file!");
        return false;
    }

    unsigned long filesize = -1;
    struct stat statbuff;
    if (stat(fname, &statbuff) < 0) {
        PRINT_ERR_HEAD;
        print_err("failed to read file properties!");
        return false;
    } else {
        filesize = statbuff.st_size / (1024 * 1024); //MB
        PRINT_DBG_HEAD;
        print_dbg("file: %s | filesize: %uldMB", fname, filesize);
#if 1
        return (filesize < 100);                //小于100M的才查毒
#else
        return true;
#endif
    }
}

int ChildProcess(void)
{
    char tmpfilename[MAX_VIR_FILE_PATH_LEN] = {0};
    char virus_name[1024] = {0};
    char versionbuf[1024] = {0};
    char sbuf[1024] = {0};
    int ret = 0;
    int cli_fd = 0;
    int viruslib = CCLAMAVLIB;
    IVIRUS *gvfilter = NULL;
    //读配置文件选择病毒引擎
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") == E_FILE_OK) {
        if (fileop.ReadCfgFileInt("SYSTEM", "VIRUSLIB", &viruslib) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("start read viruslib fail");
            viruslib = CCLAMAVLIB;
        }
        fileop.CloseFile();
    }

    switch (viruslib) {
    case CAVLLIB:
        // gvfilter = new CAVL;                                     //zza
        break;
    case CCLAMAVLIB:
        gvfilter = new CCLAMAV;
        PRINT_INFO_HEAD;
        print_info("viruslib is clamav");
        break;
    case CJMAVLIB:
        // gvfilter = new CJMAV;                                    //zza
        PRINT_INFO_HEAD;
        print_info("viruslib is jmav");
        break;
    case CRISINGAVLIB:
        gvfilter = new CRISINGAV;
        PRINT_INFO_HEAD;
        print_info("viruslib is risingav");
        break;
    default:
        break;
    }

    if (gvfilter->InitEngine() == NULL) {
        PRINT_ERR_HEAD;
        print_err("virus engine init fail");
        return 0;
    }

    cpchar ver = gvfilter->getversion();
    if (ver != NULL) {
        PRINT_INFO_HEAD;
        print_info("virus ver %s", ver);
        unlink(VIRUS_VERSION_FILE);
        sprintf(versionbuf, "echo %d.%s > %s", VERSION, ver, VIRUS_VERSION_FILE);   //写病毒库版本号到version文件
        system(versionbuf);
    } else {
        PRINT_ERR_HEAD;
        print_err("get virus ver fail");
    }

    /*接收数据socket描述符*/
    int recv_fd = 0;
    recv_fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (recv_fd < 0) {
        PRINT_ERR_HEAD;
        print_err("socket fail");
        gvfilter->release();
        return 0;
    }

    /*处理网络通信的地址*/
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s", UNIX_VIRUS_PATH);

    /*先删除要使用的路径*/
    unlink(UNIX_VIRUS_PATH);

    /*服务端绑定UNIX域路径*/
    if (bind(recv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD;
        print_err("bind fail");
        close(recv_fd);
        gvfilter->release();
        return 0;
    }

    /*UNIX域套接字开始监听*/
    if (listen(recv_fd, 10) < 0) {
        PRINT_ERR_HEAD;
        print_err("listen fail");
        close(recv_fd);
        gvfilter->release();
        return 0;
    }

    while (1) {
        cli_fd = accept(recv_fd, NULL, NULL);
        if (cli_fd < 0) {
            PRINT_ERR_HEAD;
            print_err("accept fail");
            continue;
        }
        memset(tmpfilename, 0, sizeof(tmpfilename));
        ret = recv(cli_fd, tmpfilename, sizeof(tmpfilename) - 1, 0);
        if (ret <= 0) {
            PRINT_ERR_HEAD;
            print_err("recv fail");
            close(cli_fd);
            continue;
        }

        if (!judge_size(tmpfilename)) {
            //大小不符合时 直接返回无毒
            memset(sbuf, '0', 1);
            send(cli_fd, sbuf, strlen(sbuf), 0);
            close(cli_fd);
            PRINT_INFO_HEAD;
            print_info("return no virus");
            continue;
        }

        if (gvfilter->scanvirus(tmpfilename, virus_name)) {     //查到病毒
            PRINT_INFO_HEAD;
            print_info("file: %s |virus: %s", tmpfilename, virus_name);
            memset(sbuf, '1', 1);
            memcpy(sbuf + 1, virus_name, strlen(virus_name));
        } else {
            PRINT_INFO_HEAD;
            print_info("file: %s  not find virus", tmpfilename);
            memset(sbuf, '0', 1);
        }

        send(cli_fd, sbuf, strlen(sbuf), 0);
        close(cli_fd);
        usleep(1000);
    }

    close(recv_fd);
    gvfilter->release();
    unlink(UNIX_VIRUS_PATH);

    PRINT_ERR_HEAD;
    print_err("ChildProcess exit!");
    return 0;
}

loghandle glog_p = NULL;

int main(int argc, char **argv)
{
    _log_init_(glog_p, virus);
    while (1) {
        pid_t pid = 0;
        pid = fork();
        if (pid < 0 ) {
            PRINT_ERR_HEAD;
            print_err("fork fail");
            sleep(1);
        } else if ( pid == 0 ) {
            ChildProcess();
            exit(0);
        } else {
            //父进程守护
            int status = 0;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                PRINT_ERR_HEAD;
                print_err("The child process %d exit normally", pid);
            } else {
                PRINT_ERR_HEAD;
                print_err("The child process %d exit abnormally.status is %d", pid, status);
            }
            PRINT_INFO_HEAD;
            print_info("main pull up again");
        }
        sleep(2);
    }

    PRINT_INFO_HEAD;
    print_info("main exit!");
    return 0;
}
