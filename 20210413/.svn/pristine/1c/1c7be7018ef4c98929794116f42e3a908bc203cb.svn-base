/*******************************************************************************************
*文件:  main.cpp
*描述:  策略自动备份
*作者:  王君雷
*日期:  2019-06-26
*
*修改:
*   解决FTP_TASK变量没有初始化清空，导致读取开关失败时，也会按开启处理的BUG ------> 2019-07-05
*   修改策略备份文件校验标志                                             ------> 20210520 LL
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "gap_config.h"
#include "readcfg.h"
#include "FCLogManage.h"
#include "fileoperator.h"
#include "libftp.h"
#include "debugout.h"
#include "common.h"

loghandle glog_p = NULL;
#define LOCALBAKFILE  "/tmp/bakup.rbk"       //本地策略备份压缩包文件
#define LOCALTMPFILE  "/tmp/bakup.anmit.tmp" //为备份压缩包添加校验信息的过程中使用的临时文件路径

//FTP 任务参数
typedef struct _ftp_task {
    bool istest;            //是否为测试版本
    int userulebak;         //非零表示启用策略备份
    char ftpserver[100];    //IP信息
    int ftpport;            //端口
    char user[50];          //用户名
    char pwd[50];           //密码
    int bakcycle;           //备份周期 单位s
    char innerdevtype[11];  //设备内部型号 备份出的策略，会打上标记，只有同型号的设备才允许导入使用
    char confpath[256];     //配置文件路径
    char bakpath[256];      //待备份的规则路径
    char tmpfile[256];      //为备份压缩包添加校验信息的过程中使用的临时文件路径

    char localfile[256];    //本地文件
    char remotefile[256];   //远端文件
    char remarkinfo[1024];  //存放出错、备注等信息
} FTP_TASK, *PFTP_TASK;

/**
 * [WriteSysLog 写系统日志]
 * @param logtype [日志类型]
 * @param result  [结果 成功 or 失败]
 * @param remark  [备注信息]
 */
void WriteSysLog(const char *logtype, const char *result, const char *remark)
{
    CLOGMANAGE m_log;

    if ((logtype != NULL) && (result != NULL) && (remark != NULL)) {
        m_log.Init();
        if (m_log.WriteSysLog(logtype, result, remark) != E_OK) {
            PRINT_ERR_HEAD
            print_err("write syslog to db fail[%s][%s][%s]", logtype, result, remark);
        }
        m_log.DisConnect();
    }
}

/**
 * [ReadInnerDevType 读取设备内部型号]
 * @param  ptask [FTP任务]
 * @return       [成功返回true]
 */
bool ReadInnerDevType(PFTP_TASK ptask)
{
    if (ptask == NULL) {
        PRINT_ERR_HEAD
        print_err("read innerdevtype para null");
        return false;
    }

    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("auto bak open [%s] fail", SYSINFO_CONF);
        return false;
    }

    READ_STRING(fileop, "SYSTEM", "InnerDevType", ptask->innerdevtype, true, _out);
    fileop.CloseFile();
    return true;

_out:
    fileop.CloseFile();
    return false;
}

/**
 * [ReadConf 读取FTP配置信息]
 * @param  ptask [FTP任务]
 * @return       [成功返回true]
 */
bool ReadConf(PFTP_TASK ptask)
{
    if (ptask == NULL) {
        PRINT_ERR_HEAD
        print_err("read ftp conf para null");
        return false;
    }

    CFILEOP fileop;
    if (fileop.OpenFile(ptask->confpath, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read ftp conf open [%s] fail", ptask->confpath);
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s%s", LOG_CONTENT_OPEN_FILE_ERR,
                 ptask->confpath);
        return false;
    }

    //不启用策略自动备份，就直接返回
    READ_INT(fileop, "SYSTEM", "AUTOBAK", ptask->userulebak, false, _out);
    if (ptask->userulebak == 0) {
        goto _ok;
    }

    READ_STRING(fileop, "SYSTEM", "AUTOBAK_TO", ptask->ftpserver, false, _out);
    if (strcmp(ptask->ftpserver, "") == 0) {
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s", LOG_CONTENT_AUTOBAK_IP_ERR);
        goto _out;
    }

    READ_INT(fileop, "SYSTEM", "AUTOBAK_PORT", ptask->ftpport, false, _out);
    if (ptask->ftpport <= 0) {
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%d]",
                 LOG_CONTENT_AUTOBAK_PORT_ERR, ptask->ftpport);
        goto _out;
    }

    READ_INT(fileop, "SYSTEM", "AUTOBAK_TIME", ptask->bakcycle, false, _out);
    if (ptask->bakcycle <= 0) {
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%d]",
                 LOG_CONTENT_AUTOBAK_CYCLE_ERR, ptask->bakcycle);
        goto _out;
    }
    ptask->bakcycle *= 60;

    READ_STRING(fileop, "SYSTEM", "AUTOBAK_USER", ptask->user, false, _out);
    READ_STRING(fileop, "SYSTEM", "AUTOBAK_PASS", ptask->pwd, false, _out);
_ok:
    fileop.CloseFile();
    return true;
_out:
    fileop.CloseFile();
    return false;
}

/**
 * [GetSysTime 获取时间字符串]
 * @param Result [出参]
 */
void GetSysTime(char *Result)
{
    char str[100] = {0};
    time_t secs_now = time(NULL);
    struct tm tmtmp;
    localtime_r(&secs_now, &tmtmp);
    strftime(str, sizeof(str), "%Y-%m-%d_%H_%M_%S", &tmtmp);
    strcpy(Result, str);
}

/**
 * [AddCheckMark 备份文件添加校验标志]
 * @param  ptask [FTP任务]
 * @return       [成功返回true]
 */
bool AddCheckMark(PFTP_TASK ptask)
{
    if (ptask == NULL) {
        PRINT_ERR_HEAD
        print_err("add check mark para null");
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "add check mark para null");
        return false;
    }

    CCommon common;
    char cmd[256] = "";
    char readbuf[1024] = {0};
    int rlen = 0, wlen = 0;

    //打开临时文件
    FILE *fptemp = fopen(ptask->tmpfile, "wb");
    if (fptemp == NULL) {
        PRINT_ERR_HEAD
        print_err("auto bak open file error[%s:%s]", ptask->tmpfile, strerror(errno));
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%s]",
                 LOG_CONTENT_AUTOBAK_TMPFILE_ERR, ptask->tmpfile);
        return false;
    }

    //向临时文件写入检验字符串 anmit+innerdevtype 共15个字符
    char mark[64] = "anmit";
    if (!ptask->istest) {
        memcpy(mark + 5, ptask->innerdevtype, 10);
    }

    snprintf(cmd, sizeof(cmd), "%s %s", EN_FILE_PATH, ptask->localfile);
    if (common.Sysinfo(cmd, &mark[strlen(mark)], sizeof(mark) - strlen(mark)) == NULL) {
        PRINT_ERR_HEAD
        print_err("sysinfo [%s] fail", cmd);

        fclose(fptemp);
        return false;
    }

    wlen = strlen(mark);
    if (fwrite(mark, 1, wlen, fptemp) != wlen) {
        PRINT_ERR_HEAD
        print_err("auto bak fwrite error[%s][%s]", ptask->tmpfile, strerror(errno));
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%s]",
                 LOG_CONTENT_AUTOBAK_TMPFILE_WRITE_ERR, ptask->tmpfile);
        fclose(fptemp);
        return false;
    }

    //打开localfile文件
    FILE *fptar = fopen(ptask->localfile, "rb");
    if (fptar == NULL) {
        PRINT_ERR_HEAD
        print_err("auto bak fopen error[%s][%s]", ptask->localfile, strerror(errno));
        snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%s]",
                 LOG_CONTENT_AUTOBAK_TMPFILE_ERR, ptask->localfile);
        fclose(fptemp);
        unlink(ptask->tmpfile);
        return false;
    }

    //把localfile文件内容追加到临时文件
    while (!feof(fptar)) {
        rlen = fread(readbuf, 1, sizeof(readbuf), fptar);
        if (rlen <= 0) {
            break;
        }
        wlen = fwrite(readbuf, 1, rlen, fptemp);
        if (wlen != rlen) {
            PRINT_ERR_HEAD
            print_err("auto bak fwrite error.[%s][%s]wlen[%d]rlen[%d]", ptask->tmpfile,
                      strerror(errno), wlen, rlen);
            snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%s]",
                     LOG_CONTENT_AUTOBAK_TMPFILE_WRITE_ERR, ptask->tmpfile);
            fclose(fptar);
            fclose(fptemp);
            unlink(ptask->tmpfile);
            return false;
        }
    }
    fflush(fptemp);
    fclose(fptar);
    fclose(fptemp);

    //rename
    char chcmd[1024] = {0};
    snprintf(chcmd, sizeof(chcmd), "mv %s %s", ptask->tmpfile, ptask->localfile);
    system(chcmd);
    return true;
}

/**
 * [PrepareFile 准备要上传的文件]
 * @param  ptask [FTP任务]
 * @return       [成功返回true]
 */
bool PrepareFile(PFTP_TASK ptask)
{
    char chcmd[1024] = {0};
    char nowtime[50] = {0};

    if (ptask == NULL) {
        PRINT_ERR_HEAD
        print_err("prepare file para null");
        return false;
    }
    unlink(ptask->localfile);
    //压缩
    snprintf(chcmd, sizeof(chcmd), "tar -czf %s %s", ptask->localfile, ptask->bakpath);
    system(chcmd);

    //加校验标志
    if (!AddCheckMark(ptask)) {
        PRINT_ERR_HEAD
        print_err("add check mark fail");
        WriteSysLog(LOG_TYPE_AUTOBAK, D_FAIL, ptask->remarkinfo);
        return false;
    }

    //组装备份文件名称
    GetSysTime(nowtime);
    snprintf(ptask->remotefile, sizeof(ptask->remotefile), "gap%s.rbk", nowtime);
    system("sync");

    PRINT_DBG_HEAD
    print_dbg("prepare file ok.localfile[%s] remotefile[%s]", ptask->localfile, ptask->remotefile);
    return true;
}

/**
 * [UploadFile 上传备份文件]
 * @param  ptask [FTP任务]
 * @return       [成功返回true]
 */
bool UploadFile(PFTP_TASK ptask)
{
    if (ptask == NULL) {
        PRINT_ERR_HEAD
        print_err("upload file para null");
        return false;
    }

    FTPINFO ftp_handle;

    ftp_init(&ftp_handle, OFF);

    PRINT_DBG_HEAD
    print_dbg("server[%s]:%d user[%s] pwd[%s]", ptask->ftpserver, ptask->ftpport,
              ptask->user, ptask->pwd);

    if (ftp_setport(&ftp_handle, ptask->ftpport) < 0) {
        PRINT_ERR_HEAD
        print_err("ftp set port fail[%d]", ptask->ftpport);
        return false;
    }
    if (ftp_login(&ftp_handle, ptask->ftpserver, ptask->user, ptask->pwd, NULL) < 0) {
        PRINT_ERR_HEAD
        print_err("ftp login fail.server[%s]:%d user[%s]pwd[%s]", ptask->ftpserver, ptask->ftpport,
                  ptask->user, ptask->pwd);
        WriteSysLog(LOG_TYPE_AUTOBAK, D_FAIL, LOG_CONTENT_AUTOBAK_LOGIN_ERR);
        return false;
    }
    if (ftp_binary(&ftp_handle) < 0) {
        PRINT_ERR_HEAD
        print_err("ftp binary fail");
        goto _out;
    }

    if (ftp_putfile(&ftp_handle, ptask->remotefile, ptask->localfile) < 0) {
        PRINT_ERR_HEAD
        print_err("ftp putfile fail.remotefile[%s] localfile[%s]", ptask->remotefile, ptask->localfile);
        goto _out;
    }
    ftp_bye(&ftp_handle);

    snprintf(ptask->remarkinfo, sizeof(ptask->remarkinfo), "%s[%s][%s]:%d",
             LOG_CONTENT_AUTOBAK_PUT_OK, ptask->remotefile, ptask->ftpserver, ptask->ftpport);
    WriteSysLog(LOG_TYPE_AUTOBAK, D_SUCCESS, ptask->remarkinfo);

    PRINT_DBG_HEAD
    print_dbg("autobak ok[%s] server[%s]:%d", ptask->remotefile, ptask->ftpserver, ptask->ftpport);
    return true;
_out:
    ftp_bye(&ftp_handle);
    WriteSysLog(LOG_TYPE_AUTOBAK, D_FAIL, LOG_CONTENT_AUTOBAK_PUT_ERR);
    return false;
}

int main(int argc, char **argv)
{
    FTP_TASK task;
    memset(&task, 0, sizeof(task));

    _log_init_(glog_p, autobak);

    if (argc != 2) {
        printf("Usage(%s %s):%s test/normal\n", __DATE__, __TIME__, argv[0]);
        return -1;
    }

    //判断是test版，还是normal版
    if (strstr(argv[1], "test") != NULL) {
        task.istest = true;
        strcpy(task.confpath, SYSSET_CONF_TEST);
        strcpy(task.bakpath, RULES_DIR_TEST);
    } else {
        task.istest = false;
        strcpy(task.confpath, SYSSET_CONF);
        strcpy(task.bakpath, RULES_DIR);

        if (!ReadInnerDevType(&task)) {
            char remark[128] = {0};
            snprintf(remark, sizeof(remark), "%s[%s]", LOG_CONTENT_READ_FILE_ERR, SYSINFO_CONF);
            WriteSysLog(LOG_TYPE_AUTOBAK, D_FAIL, remark);
            return -1;
        }
    }
    strcpy(task.localfile, LOCALBAKFILE);
    strcpy(task.tmpfile, LOCALTMPFILE);

    while (!ReadConf(&task)) {
        WriteSysLog(LOG_TYPE_AUTOBAK, D_FAIL, task.remarkinfo);
        sleep(10);
    }

    if (task.userulebak != 0) {
        WriteSysLog(LOG_TYPE_AUTOBAK, D_SUCCESS, LOG_CONTENT_AUTOBAK_RUN);

        PRINT_DBG_HEAD
        print_dbg("use rule bak. begin run");

        //sys6没有完全启动之前，ip地址还没设置好，登陆备份服务器可能会失败，所以sleep5s
        sleep(5);
        int x = 0;
        while (1) {
            if (PrepareFile(&task) && UploadFile(&task) && (x == 0)) {
                WriteSysLog(LOG_TYPE_AUTOBAK, D_SUCCESS, LOG_CONTENT_AUTOBAK_WORKING);
                x = 1;
            }
            sleep(task.bakcycle);
        }
    }

    return 0;
}
