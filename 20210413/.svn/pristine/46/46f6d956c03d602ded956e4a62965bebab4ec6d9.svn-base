/*******************************************************************************************
*文件:    clientsec.h
*描述:
*
*作者:    张昆鹏
*日期:    2016-10-31
*修改:    创建文件                            ------>     2016-11-01
*         修改头文件                          ------>     2016-11-22
*         调整代码结构，与客户端达成共用      ------>     2016-12-18
*         修改部分代码实现                    ------>     2016-12-26
*         修改传输文件中出现的bug             ------>     2017-02-09
*         增加兼容UDP模式                     ------>     2017-07-30
*         增加文件传输校验功能                ------>     2017-08-01
*         增加文件接收备份功能                ------>     2017-08-15
*
*******************************************************************************************/

#ifndef CLIENTSEC_H
#define CLIENTSEC_H

#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "datatype.h"
#include "syssocket.h"
#include "fileoperator.h"
#include "debugout.h"
#include "stringex.h"
#include "syscfg.h"
#include "sysdir.h"
#include "md5.h"
#include "priority.h"

#ifndef __CYGWIN__
#include "sysdb.h"
#endif

#define MAX_USERNUM  100
#define MAX_USERLEN  100
#define MAX_TIME     50
#define MAX_MSGSIZE  2048
#define MAX_FILESIZE 2048
#define TIMEOUT      60
#define MD5LEN       32

#define  DEF_PORT  10021         //默认通讯端口

#define  MODE_SUTCP  0           //TCP客户端-光闸模式
#define  MODE_UDP    1           //UDP客户端-服务器模式
#define  MODE_TCP    2           //TCP客户端-服务器模式

typedef struct MYSQLSYSDB {
#ifndef __CYGWIN__
    CSYSDB *sql;                                  //数据库
#else
    pchar sql;
#endif

    CHAR guid[100];                              //标识
} SYSDBSQL;

enum COMMAND {
    USERLOGIN = 0,               //登陆验证
    RECORDLOG,                   //添加CallLOG记录
    RECORDSFILE,                 //添加SFILE记录
    READDEVNAME,                 //获取设备号
    LOCK,                        //锁定当前用户
    RFILE,                       //读文件
    MKDIR,                       //创建目录
    SFILE,                       //写文件
    DIR_,                        //查看文件夹列表
    PDIR,                        //查看文件夹列表
    CKLEVEL,                     //查看文件访问权限（文件尾字节）
    READTIMES,                   //获取服务器时间
    CHANGEUPASS,                 //修改密码*/
    DEL,                         //删除
    LPDIR,                       //查看文件夹列表
    LSFILE,                      //写文件
};

#define strcmd(a)  {a, #a}
#define strcmd_(a) #a

static const CHAR FILELEVEL_0 = '0';                                    //数据级别
static const CHAR FILELEVEL_1 = '1';
static const CHAR FILELEVEL_2 = '2';

static const CHAR FLODERSYMBOL = '0';                                   //文件夹
static const CHAR FILESYMBOL = '1';                                     //文件
static const pchar  MKDIROK = "OK";                                     //创建目录通讯使用
static const pchar  RET_PREPARE_FALSE =  "PREPARE_FALSE";               //收发文件通讯关键词
static const pchar  RET_PREPARE_OK =  "PREPARE_OK";
static const pchar  RET_FILE_OK = "okrs";                               //发送文件通讯关键字
static const pchar  RET_FILE_END = "recv_finish";
static const pchar  LINUX_LOGIN = "@$fileclient@$";                     //用于linux客户端验证用户名


#define SHUTDOWN(s) shutdown((s).getsocket(SOCKET_SRV), SHUT_WR);

/*******************************************************************************************
*功能:    判断路径或文件或指定权限是否存在
*参数:    path                      ---->    路径
*         mode                      ---->    权限判断
*         返回值                    ---->    true存在  false不存在
*注释:
*
*******************************************************************************************/
bool accesspath(pchar path, int mode = F_OK)
{
    if (access(path, mode) < 0) {
        PRINT_ERR_HEAD;
        print_err("Path(%s) does not exist or permissions(%d) are insufficient", path, mode);
        return false;
    }

    return true;
}

/*******************************************************************************************
*功能:    文件md5
*参数:    fp                        ---->    文件句柄
*         size                      ---->    文件大小
*         flag                      ---->    校验算法
*         md5                       ---->    计算结果
*
*注释:    先要计算size的md5
*
*******************************************************************************************/
bool getfilemd5(FILE *fp, uint64 size, int32 flag, puint8 md5)
{
    if ((fp == NULL) || (md5 == NULL))  return false;

    //判断算法配置
    uint8 digest[16] = {0};
    PRINT_DBG_HEAD;
    print_dbg("FILE CHECK %lld %d", size, flag);

    if (flag != 0) {
        uint64 pos = ftell(fp);
        uint8 buf[TMPBUFFMAX];
        int32 n;
        int32 sleepcnt = 0;
        uint64 nread = 0ULL;

        MD5_CTX md5_t;
        MD5Init(&md5_t);
        MD5Update(&md5_t, (const puint8)&size, sizeof(uint64));

        fseek(fp, 0, SEEK_SET);
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
            MD5Update(&md5_t, buf, n);

            nread += n;
            if (flag > 0) {if (nread / (1024 * 1024) == flag) break;} //文件头部分数据

            //防止资源占用过高, 每20MB等待
            if (++sleepcnt >= 2500) {
                usleep(1);
                sleepcnt = 0;
            }
        }

        //结束文件
        if (flag > 0) {
            uint64 nleft = 0ULL;
            fseek(fp, 0, SEEK_END);
            if ((nleft = (ftell(fp) - nread)) > 0ULL) {

                fseek(fp, MIN(nleft, sizeof(buf)), SEEK_END);
                n = fread(buf, 1, sizeof(buf), fp);
                MD5Update(&md5_t, buf, n);
            }
        }

        MD5Final(digest, &md5_t);
        memcpy(md5, digest, sizeof(digest));

        fseek(fp, pos, SEEK_SET);
    } else {
        memset(md5, 0, sizeof(digest));
    }

    PRINT_DBG_HEAD;
    print_dbg("FILE CHECK (%s)", printbuf(md5, sizeof(digest)));

    return true;
}

/*******************************************************************************************
*功能:      发送文件
*参数:      cli_p                       ---->   CSUSOCKET
*           fpath                       ---->   路径
*           parea                       ---->   true 公有区
*           c_s                         ---->   true 服务器一端
*           chk                         ---->   md5校验控制，0关闭，-1，全部，>0：文件头数据块
*          返回值                       ---->   true成功
*注释:
*******************************************************************************************/
static bool SendFile(CSUSOCKET *cli_p, const pchar fpath, bool parea = false, bool c_s = true, int32 chk = 0, SYSDBSQL *dbsql = NULL)
{
    if (!is_file(fpath)) return false;
    uint8 filebuf[MAX_FILESIZE] = {0};
    bool bret = false;
    FILE *fop = fopen(fpath, "rb");
    if (fop != NULL) {

        struct stat filestat;
        stat(fpath, &filestat);
        int32 len;
        if (!c_s) {
            len = sizeof(filestat.st_size);
            memcpy(filebuf, &filestat.st_size, len);

        } else {
            sprintf((pchar)filebuf, "%llu", filestat.st_size);
            len = strlen((const pchar)filebuf);
        }
        PRINT_DBG_HEAD;
        print_dbg("Send filesize = %lld, len=%d", filestat.st_size, len);
        if ((cli_p->writesocket(filebuf, len)) == len) bret = true;

        //修改0 K文件传输问题
        if (bret && ((len = cli_p->readsocket(filebuf, sizeof(filebuf))) > 0)) {
            bret = (memcmp((const pchar)filebuf, RET_FILE_OK, strlen(RET_FILE_OK)) == 0);
            if (filestat.st_size == 0) {
                PRINT_DBG_HEAD;
                print_dbg("Send null file %s", fpath);
                fclose(fop);
#ifndef __CYGWIN__
                if (dbsql != NULL) {
                    CHAR sqlcmd[_FILEPATHMAX] = {0};
                    sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstatus=3, etendtime=NOW(), etfinishsize=%ld WHERE ettaskid='%s'", 0, dbsql->guid);
                    dbsql->sql->runsql(sqlcmd, NULL);
                }
#endif
                return true;
            }
            if (!bret) {
                PRINT_ERR_HEAD;
                print_err("Send failed; filebuf=%s, len=%d", filebuf, len);
            }
        }

        if (chk != 0) {

            uint8 dmd5[MD5LEN] = {0};
            //计算文件MD5, 包括文件长度
            getfilemd5(fop, filestat.st_size, chk, dmd5);
            if ((cli_p->writesocket(dmd5, sizeof(dmd5))) > 0) bret = true;
            memset(filebuf, 0, sizeof(filebuf));
            if (bret && (cli_p->readsocket(filebuf, sizeof(filebuf)) > 0)) {
                bret = (memcmp((const pchar)filebuf, RET_FILE_OK, strlen(RET_FILE_OK)) == 0);
            } else {
                bret = false;
            }
            if (!bret) {
                PRINT_ERR_HEAD;
                print_err("Send Md5 (%s) error!", fpath);
            }
        }
        // 设置优先级
        int32 j  =  priority_set(true);

        int32 k = 0;
        uint64 readcnt = 0ULL;
        clock_t start = clock();
        while (bret && ((k = fread(filebuf, 1, sizeof(filebuf), fop)) > 0)) {        //发送文件
            if (cli_p->writesocket(filebuf, k) != k) {
                PRINT_ERR_HEAD;
                print_err("Send failed; size = %d!", k);
                bret = false;
            }
            readcnt += k;
            // 设置优先级
            _priority_set(j);
#ifndef __CYGWIN__
            if ((dbsql != NULL) && (((clock() - start) / CLOCKS_PER_SEC) == 5)) {
                start = clock();
                CHAR sqlcmd[_FILEPATHMAX] = {0};
                sprintf(sqlcmd, "UPDATE nt_exchange_task SET etfinishsize=%ld WHERE ettaskid='%s'", readcnt, dbsql->guid);
                PRINT_DBG_HEAD;
                print_dbg("UPDATE cmd=%s", sqlcmd);
                dbsql->sql->runsql(sqlcmd, NULL);
            }
#endif
        }
        fclose(fop);

        PRINT_DBG_HEAD;
        print_dbg("Send size = %lld!", readcnt);

        // 设置优先级
        priority_end_task(j);

        if (bret && (!parea)) {
            if ((len = cli_p->readsocket(filebuf, sizeof(filebuf))) > 0) {
                bret = (memcmp((const pchar)filebuf, RET_FILE_END, len) == 0);
                PRINT_DBG_HEAD;
                print_dbg("Recv recv_finish success");
            } else {
                bret = false;
            }
        }

        PRINT_DBG_HEAD;
        print_dbg("Send file %s %s", fpath, (bret ? "success" : "failed"));
#ifndef __CYGWIN__
        if ((dbsql != NULL) && (bret)) {
            CHAR sqlcmd[_FILEPATHMAX] = {0};
            sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstatus=3, etendtime=NOW(), etfinishsize=%ld WHERE ettaskid='%s'", readcnt, dbsql->guid);
            dbsql->sql->runsql(sqlcmd, NULL);
        }
#endif
    }
    return bret;
}

/*******************************************************************************************
*功能:     接收文件
*参数:      cli_p                      ---->    CSUSOCKET
*           fpath                      ---->    文件名
*           parea                      ---->    true 公有区
*           c_s                        ---->    true 服务器一端
*           chk                        ---->    md5校验控制，0关闭，-1，全部，>0：文件头数据块
*           bakpath                    ---->    备份路径，默认不备份
*          返回值                      ---->    true 成功
*注释:
*******************************************************************************************/
static bool RecvFile(CSUSOCKET *cli_p, const pchar fpath, bool parea = false, bool c_s = true,
                     int32 chk = 0, pchar bakpath = NULL)
{
    FILE *bakfop = NULL;
    //创建文件目录，保证接收文件路径存在
    {
        CHAR tmp[_FILEPATHMAX] = {0};
        CHAR cmd[_FILEPATHMAX] = {0};
        split_filepath(fpath, tmp);

        if (!is_dir(tmp)) {
            sprintf(cmd, "mkdir '%s' -p", tmp);
            system(cmd);
        }
        PRINT_DBG_HEAD;
        print_dbg("Recv file dir = %s", tmp);
        if (!is_strempty(bakpath)) {
            CHAR tmppath[_FILEPATHMAX] = {0};
            split_filepath(bakpath, tmppath);

            if (!is_dir(tmppath)) {
                sprintf(cmd, "mkdir '%s' -p", tmppath);
                system(cmd);
            }
            bakfop = fopen(bakpath, "wb");
        }
    }

    uint8 filebuf[MAX_FILESIZE] = {0};
    bool bret = false;
    FILE *fop = fopen(fpath, "wb");
    if (fop != NULL) {

        uint64 filesize = 0ULL;
        uint8 md5[MD5LEN] = {0};
        uint64 readcnt = 0ULL;
        int32 len = cli_p->readsocket(filebuf, sizeof(filebuf));
        if (len > 0) {

            bret = true;
            if (!c_s) {
                str2long((const pchar)filebuf, &filesize);
            } else {
                memcpy(&filesize, filebuf, len);
            }
            PRINT_DBG_HEAD;
            print_dbg("Recv filesize = %lld,len = %d", filesize, len);
        }

        if (bret) {                                                                  //接收文件
            len = cli_p->writesocket(RET_FILE_OK, strlen(RET_FILE_OK));
            if (filesize <= 0) {                 //修改0 K文件传输问题
                if (!parea) {
                    //cli_p->writesocket(RET_FILE_END, strlen(RET_FILE_END));
                    fclose(fop);
                    if (bakfop != NULL) fclose(bakfop);
                    PRINT_DBG_HEAD;
                    print_dbg("Recv null file %s", fpath);
                    return true;
                }
            }

            if (chk != 0) {
                if ((cli_p->readsocket(md5, sizeof(md5))) > 0) bret = true;
                if (bret) cli_p->writesocket(RET_FILE_OK, strlen(RET_FILE_OK));
            }

            // 设置优先级
            int32 j  =  priority_set(true);
            int32 i, k;
            while (bret && ((i = cli_p->readsocket(filebuf, sizeof(filebuf))) > 0)) {

                readcnt += i;
                k = (int32)fwrite(filebuf, 1, i, fop);
                if (k != i) {
                    PRINT_ERR_HEAD;
                    print_err("Recv failed; size = %d fwrite = %d!", i, k);
                    printf("Recv failed; size = %d fwrite = %d!\n", i, k);
                    bret = false;
                }
                if (bakfop != NULL) fwrite(filebuf, 1, i, bakfop);
                if (parea) {
                    if (readcnt > filesize)  break;
                } else {
                    if (readcnt >= filesize)  break;
                }

                // 设置优先级
                _priority_set(j);
            }

            // 设置优先级
            priority_end_task(j);

            if (readcnt < filesize) {
                PRINT_ERR_HEAD;
                print_err("Recv failed; size = %lld filesize = %lld!", readcnt, filesize);
                printf("Recv failed; size = %lld filesize = %lld!\n", readcnt, filesize);
                bret = false;
            }
        }
        fclose(fop);

        if (bret && (chk != 0)) {

            uint8 tmp[MD5LEN] = {0};

            FILE *fop = fopen(fpath, "rb");
            getfilemd5(fop, readcnt, chk, tmp);
            if (fop != NULL) fclose(fop);   //文件打开错误异常

            bret = (memcmp(tmp, md5, sizeof(md5)) == 0);
            if (!bret) {
                PRINT_ERR_HEAD;
                print_err("md5_recv = %s, md5 = %s", printbuf(md5, sizeof(md5)), printbuf(tmp, sizeof(tmp)));
                printf("md5_recv = %s, md5 = %s\n", printbuf(md5, sizeof(md5)), printbuf(tmp, sizeof(tmp)));
            }
        }

        PRINT_DBG_HEAD;
        print_dbg("Recv file %s %s", fpath, (bret ? "success" : "failed"));
        if (!bret)  remove(fpath);

        cli_p->writesocket(RET_FILE_END, strlen(RET_FILE_END));
    } else {
        PRINT_ERR_HEAD;
        print_err("Recv file open %s", fpath);
    }
    if (bakfop != NULL) fclose(bakfop);
    return bret;
}

/*******************************************************************************************
*功能:        拼接发送命令信息
*参数:        sendmsg                      ---->  存储发送信息
*             cmd                          ---->  关键词
*             firstmsg                     ---->  信息一
*             secondmsg                    ---->  信息二，可为NULL
*             返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool MySprintf(pchar sendmsg, pchar cmd, pchar firstmsg, pchar secondmsg = NULL)
{
    if (secondmsg != NULL) {

        CHAR path[_FILEPATHMAX] = {0};
        make_filepath(firstmsg, secondmsg, path);
        memset(sendmsg, 0, sizeof(sendmsg));
        sprintf(sendmsg, "%s:%s", cmd, path);
    } else {
        sprintf(sendmsg, "%s:%s", cmd, firstmsg);
    }
    return true;
}


/*******************************************************************************************
*功能:        替换win路径
*参数:        path                         ---->  文件路径
*             返回值                       ---->
*注释:
*******************************************************************************************/
void Checkwinpath(pchar path)
{
    if (path != NULL) {

        for (int i = 0; i < strlen(path); ++i) {

#ifndef __CYGWIN__
            if (path[i] == '\\') path[i] = '/';
#else
            if (path[i] == '/') path[i] = '\\';
#endif
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("CHECK DIR %s", path);
}



#endif
