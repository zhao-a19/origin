/*******************************************************************************************
*文件:    main.cpp
*描述:    dbsync_tool
*
*作者:    李亚洲
*日期:    2020-07-24
*修改:    创建文件                            ------>     2020-07-24
*修改:    更新策略备份文件路径                ------>     2020-10-29
*修改:    更新是否开启日志记录                ------>     2020-11-09
*修改:    添加获取后台服务接口                ------>     2020-11-24
*修改:    添加编译开关区别后台接口            ------>     2021-02-26
*修改:    添加对数据库类型转化(统一大写)      ------>     2021-03-23
*         跟java通信时使用内联IP             ------>     2021-06-10 王君雷
*******************************************************************************************/
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include "datatype.h"
#include "debugout.h"

#include "fileoperator.h"
#include "sysdir.h"
#ifdef DBSYNC_DEBUG
#include "dbsync_task_debug.h"
#else
#include "dbsync_task.h"
#endif


static pchar VersionNO = "2.2.5";     //版本号,尾号为偶数表示正式版本，奇数为测试
static dbsync_task tasks[DBSYNC_TASKMAX], tasks_bak[DBSYNC_TASKMAX];
#define STRTOINT(i_data, s_data)  {strstrip_(s_data, " \t\r\n\'");\
                         i_data = atoi(s_data);}
#define FILTERSTR(str)  {strstrip_(str, " \t\r\n\'");}
bool exit_flag = false;
int g_ipseg = 1;
static pchar dbsync_to_upper(pchar str);
static int locktest();
//----------------------------------------------------------------
static void print_usage(void)
{
    printf("\n************************* -- dbsync_tool tool Ver%s -- **************************\n\n", VersionNO);
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    printf("\t(1)./dbsync_tool 1 for thread num\n");
    printf("\t(3)if no mode set, looking for %s\n", DConfigFile);
    printf("\n******************************************************************************\n\n");

}

//static pchar DBMODULE = "dbsync_tool status fail";
//extern void modulelogout(pchar modulename, bool ok);
//#define errorbreak(r) {modulelogout(DBMODULE, false); return r;}

static int32 get_tasklist(pdbsync_task list, int32 listcnt, pdbsync_time timer, uint32 thread_num, pchar cfg = DBConfigFile);
static int32 get_tasklist_old(pdbsync_task list, int32 listcnt, pdbsync_time timer, pchar cfg = DBConfigFile);
static int32 get_logflag(pdbsync_log log_data, pchar cfg);
_log_preinit_(glog_p);

/***********************************************
 * 函数功能：设置数据库退出状态
 *
 *
 * *********************************************/
static void set_exit(int sig)
{

    PRINT_DBG_HEAD;
    print_dbg("HA TASK_(%u) SIG %u(0x%x)", (uint32)pthread_self(), sig, sig);

    switch (sig) {
    case SIGTERM:
        exit_flag = true;
        break;
    default:
        break;
    }

}

/**
 * [readIPSeg 读取内部通信使用的网段]
 * @return       [返回内部通信使用的IP段]
 */
int readlinkseg(void)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail. use default 1.[%s]", SYSINFO_CONF);
        return 1;
    }

    char tmp[100] = {0};
    if (fileop.ReadCfgFile("SYSTEM", "LinkLanIPSeg", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read LinkLanIPSeg fail.use default 1");
        strcpy(tmp, "1");
    }
    fileop.CloseFile();

    int seg = atoi(tmp);
    if (seg < 1 || seg > 255) {
        return 1;
    }
    return seg;
}

//---------------------------------------------------------------
int main (int argc, char  *argv[])
{
    DBSYNCMODE type;
    //dbsync_task tasks[DBSYNC_TASKMAX], tasks_bak[DBSYNC_TASKMAX];
    dbsync_time timer;
    int32 taskcnt, taskcnt_bak;

    uint32 thread_num = 0;
    dbsync_log log_data;

    //防止同时调用
    //locktest();
    signal(SIGTERM, set_exit);
    if (argc > 2) {
        print_usage();
        exit(-1);
        //errorbreak(1);
    }
    _log_init_(glog_p, dbsync_tool);
    if (argc == 2) {
        thread_num = atoi(argv[1]);
    }
    memset(&tasks, 0, sizeof(tasks));
    memset(&tasks_bak, 0, sizeof(tasks_bak));
    memset(&timer, 0, sizeof(timer));
    memset(&log_data, 0, sizeof(log_data));

    //读取内部通信IP网段配置
    g_ipseg = readlinkseg();

    if (( taskcnt = get_tasklist_old(tasks, sizeof(tasks) / sizeof(dbsync_task), &timer)) > 0) {
#ifdef DBSYNC_DEBUG
        dbsync_back_task_info_old_debug(taskcnt, tasks, timer, DBConfigFileTmp);
#else
        dbsync_back_task_info_old(taskcnt, tasks, timer, DBConfigFileTmp);
#endif
        char cmd[512] = {0};
        sprintf(cmd, "mv %s %s", DBConfigFileTmp, DBConfigFile);
        system(cmd);
    }

    taskcnt = get_tasklist(tasks, sizeof(tasks) / sizeof(dbsync_task), &timer, thread_num);
    taskcnt_bak = get_tasklist(tasks_bak, sizeof(tasks_bak) / sizeof(dbsync_task), NULL, thread_num, DBConfigFileBak);
    get_logflag(&log_data, SYSFile);

    if (taskcnt < 0)   exit(-1);
    //if (taskcnt < 0)   errorbreak(-1);
    if (taskcnt == 0 && taskcnt_bak == 0) return 0;

#ifdef DBSYNC_DEBUG
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool DBSYNC_DEBUG!");
    dbsync_status_debug();

    //解决数据延迟30s，原因是后台延迟30s防止数据丢失(光闸不统一)
    dbsync_set_log_debug(log_data);
    //策略下发
    if (thread_num > 0)
        dbsync_task_check_thread_debug(taskcnt, tasks, taskcnt_bak, tasks_bak, timer, thread_num);
    else
        dbsync_task_check_debug(taskcnt, tasks, taskcnt_bak, tasks_bak, timer);
    //备份配置文件(成功备份)
#if 1
    dbsync_update_taskinfo_debug(taskcnt, tasks);
#endif
    dbsync_back_task_info_debug(taskcnt, tasks, taskcnt_bak, tasks_bak, DBConfigFileBak);
#else
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool DBSYNC!");
    dbsync_status();

    //解决数据延迟30s，原因是后台延迟30s防止数据丢失(光闸不统一)
    dbsync_set_log(log_data);
    //策略下发
    if (thread_num > 0)
        dbsync_task_check_thread(taskcnt, tasks, taskcnt_bak, tasks_bak, timer, thread_num);
    else
        dbsync_task_check(taskcnt, tasks, taskcnt_bak, tasks_bak, timer);
    //备份配置文件(成功备份)
#if 1
    dbsync_update_taskinfo(taskcnt, tasks);
#endif
    dbsync_back_task_info(taskcnt, tasks, taskcnt_bak, tasks_bak, DBConfigFileBak);
#endif
finish:
    PRINT_ERR_HEAD;
    print_err("dbsync_tool EXIT!");
    for (int i = 0; i < taskcnt; i++) {
        for (int j = 0; j < tasks[i].tables_num; j++) {
            DBSYNC_FREE(tasks[i].tables[j]);
        }
    }
    for (int i = 0; i < taskcnt_bak; i++) {
        for (int j = 0; j < tasks_bak[i].tables_num; j++) {
            DBSYNC_FREE(tasks_bak[i].tables[j]);
        }
    }
    _log_finish_(glog_p);
    return 1;
}
/*******************************************************************************************
*功能:    读取配置文件信息
*参数:    list                ---->   列表首地址
*         listcnt             ---->   列表空间最大个数
*         timer               ---->   数据库同步参数
*         返回值              ---->   任务数(正数)
*
*注释:
*******************************************************************************************/
static int32 get_tasklist(pdbsync_task list, int32 listcnt, pdbsync_time timer, uint32 thread_num, pchar cfg)
{
    pchar SYSROOT[2] = {"MAIN", "TaskNum"};
    pchar TASKCFG = "Task";

    CFILEOP file;
    int32 taskcnt = 0;
    char tasktmp[64] = {0}, tmpdata[64] = {0};
    int32 err = 0;
    if (list == NULL)    return -1;

    //初始化参数
    memset(list, 0, listcnt * sizeof(dbsync_task));
    if (listcnt > DBSYNC_TASKMAX) {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool TASK IS OVERFLOW, CNT = %d, MAX = %d", listcnt, DBSYNC_TASKMAX);
        listcnt = DBSYNC_TASKMAX;
    }

    if (file.OpenFile((char *)cfg, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool OPEN CFG(%s) ERROR!!", cfg);
        return -1;
    }

    //读取任务数
    file.ReadCfgFile((char *)SYSROOT[0], (char *)SYSROOT[1], tmpdata, sizeof(tmpdata));
    STRTOINT(taskcnt, tmpdata);
    if (taskcnt > listcnt) {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool TASK IS OVERFLOW, LIST = %d, CFG = %d", listcnt, taskcnt);
        taskcnt = listcnt;

    }
    if (timer != NULL) {
        int32 tmp;
        tmp = -1;
        if (file.ReadCfgFile((char *)SYSROOT[0], "CKSyncDay", tmpdata, sizeof(tmpdata)) == E_FILE_OK) {
            STRTOINT(tmp, tmpdata);

            if (tmp == -1) timer->chsyncday = 0;
            else timer->chsyncday = (uint32)tmp;
        } else {
            timer->chsyncday = 0;
        }

        file.ReadCfgFile((char *)SYSROOT[0], "Synctimer", timer->sysnctimer, sizeof(timer->sysnctimer));
        FILTERSTR(timer->sysnctimer);

        tmp = -1;
        if (file.ReadCfgFile((char *)SYSROOT[0], "Syncspe", tmpdata, sizeof(tmpdata)) == E_FILE_OK) {
            STRTOINT(tmp, tmpdata);
            if (tmp == -1) timer->syncspe = 0;
            else timer->syncspe = (uint32)tmp;
        } else {
            timer->syncspe = 0;
        }
    }

    //读取
    for (int32 i = 0; i < taskcnt; i++) {
        int32 tmp;
        char idtmp[64] = {0};
        char tmptable_tmp[64] = {0};

        list[i].thread_num = thread_num;
        list[i].task_num = taskcnt;
        sprintf(tasktmp, "%s%d", TASKCFG, i);
        file.ReadCfgFile(tasktmp, "Name", list[i].name, sizeof(list[i].name));
        FILTERSTR(list[i].name);

        file.ReadCfgFile(tasktmp, "ID", idtmp, sizeof(idtmp));
        FILTERSTR(idtmp);
        list[i].id = atoll(idtmp);

        err |= file.ReadCfgFile(tasktmp, "SDBTYPE", list[i].sdbtype, sizeof(list[i].sdbtype));
        FILTERSTR(list[i].sdbtype);
        err |= file.ReadCfgFile(tasktmp, "SCHARSET", list[i].sdbcharset, sizeof(list[i].sdbcharset));
        FILTERSTR(list[i].sdbcharset);
        err |= file.ReadCfgFile(tasktmp, "SDATABASE", list[i].sdatabase, sizeof(list[i].sdatabase));
        FILTERSTR(list[i].sdatabase);
        err |= file.ReadCfgFile(tasktmp, "SDBMSIP", list[i].sdbmsip, sizeof(list[i].sdbmsip));
        FILTERSTR(list[i].sdbmsip);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "SPORT", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].sport = 0;
        else list[i].sport = (uint32)tmp;

        err |= file.ReadCfgFile(tasktmp, "SUSERNAME", list[i].susername, sizeof(list[i].susername));
        FILTERSTR(list[i].susername);
        err |= file.ReadCfgFile(tasktmp, "SPASSWORD", list[i].spassword, sizeof(list[i].spassword));
        FILTERSTR(list[i].spassword);

        err |= file.ReadCfgFile(tasktmp, "TDBTYPE", list[i].tdbtype, sizeof(list[i].tdbtype));
        FILTERSTR(list[i].tdbtype);
        err |= file.ReadCfgFile(tasktmp, "TCHARSET", list[i].tdbcharset, sizeof(list[i].tdbcharset));
        FILTERSTR(list[i].tdbcharset);
        err |= file.ReadCfgFile(tasktmp, "TDATABASE", list[i].tdatabase, sizeof(list[i].tdatabase));
        FILTERSTR(list[i].tdatabase);

        err |= file.ReadCfgFile(tasktmp, "TDBMSIP", list[i].tdbmsip, sizeof(list[i].tdbmsip));
        FILTERSTR(list[i].tdbmsip);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "TPORT", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].tport = 0;
        else list[i].tport = (uint32)tmp;

        err |= file.ReadCfgFile(tasktmp, "TUSERNAME", list[i].tusername, sizeof(list[i].tusername));
        FILTERSTR(list[i].tusername);
        err |= file.ReadCfgFile(tasktmp, "TPASSWORD", list[i].tpassword, sizeof(list[i].tpassword));
        FILTERSTR(list[i].tpassword);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "DIRECTION", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].direction = 0;
        else list[i].direction = (uint32)tmp;

        tmp = -1;
        file.ReadCfgFile(tasktmp, "DOUBLESIDED", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].doublesided = 0;
        else list[i].doublesided = (uint32)tmp;

        tmp = -1;
        sprintf(tmptable_tmp, "%llu_TMPTABLE", list[i].id);
        file.ReadCfgFile(tasktmp, tmptable_tmp, tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].tmptable = 0;
        else list[i].tmptable = (uint32)tmp;

        tmp = -1;
        file.ReadCfgFile(tasktmp, "ENABLE", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].enable = DBSYNC_TASK_STOP;
        else list[i].enable = (uint32)tmp ? DBSYNC_TASK_START : DBSYNC_TASK_STOP;

        tmp = -1;
        file.ReadCfgFile(tasktmp, "TABLENUM", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].tables_num = 0;
        else list[i].tables_num = (uint32)tmp > DBSYNC_TABLES_NUM ? DBSYNC_TABLES_NUM : (uint32)tmp;

        for (int j = 0; j < list[i].tables_num; j++) {
            char tables_tmp[64] = {0};
            sprintf(tables_tmp, "%llu_TABLE%d", list[i].id, j);
            list[i].tables[j] = (char *)malloc(DBSYNC_TABLES_MAX);
            memset(list[i].tables[j], 0, DBSYNC_TABLES_MAX);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].tables[j], DBSYNC_TABLES_MAX);
            FILTERSTR(list[i].tables[j]);
            PRINT_INFO_HEAD;
            print_info("dbsync_tool tables %d -> %s", j, list[i].tables[j]);

        }

        err |= file.ReadCfgFile(tasktmp, "SOWNER", list[i].sowner, sizeof(list[i].sowner));
        FILTERSTR(list[i].sowner);
        err |= file.ReadCfgFile(tasktmp, "OBJALIAS", list[i].objalias, sizeof(list[i].objalias));
        FILTERSTR(list[i].objalias);
        err |= file.ReadCfgFile(tasktmp, "TOWNER", list[i].towner, sizeof(list[i].towner));
        FILTERSTR(list[i].towner);

        err |= file.ReadCfgFile(tasktmp, "tempTableName", list[i].tempTableName, sizeof(list[i].tempTableName));
        FILTERSTR(list[i].tempTableName);

        PRINT_INFO_HEAD;
        print_info("dbsync_tool %s, id:%llu, name:%s, sdbtype:%s, sdbcharset:%s, sdatabase:%s, sdbmsip:%s, sport:%u, susername:%s, spassword:%s, tdbtype:%s, tdbcharset:%s, \
                     tdatabase:%s, tdbmsip:%s, tport:%u, tusername:%s, tpassword:%s, direction:%u, doublesided:%u, tmptable:%u, enable:%u, sowner:%s, objalias:%s, towner:%s",
                   tasktmp, list[i].id, list[i].name, list[i].sdbtype, list[i].sdbcharset, list[i].sdatabase, list[i].sdbmsip, list[i].sport,
                   list[i].susername, list[i].spassword, list[i].tdbtype, list[i].tdbcharset, list[i].tdatabase, list[i].tdbmsip,
                   list[i].tport, list[i].tusername, list[i].tpassword, list[i].direction, list[i].doublesided, list[i].tmptable, list[i].enable,
                   list[i].sowner, list[i].objalias, list[i].towner);
    }

    file.CloseFile();

    if (err == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool READ CFG(%s) ERROR, PLS CHECK FILE WITH LOG INFO!!", cfg);
        taskcnt = -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool READ CFG(%s) TASKS = %d", cfg, taskcnt);
    }

    return taskcnt;
}
/*******************************************************************************************
*功能:    读取配置文件信息
*参数:    log_data        ---->   日志标志数据
*         cfg             ---->   文件路径
*
*注释:
*******************************************************************************************/
static int32 get_logflag(pdbsync_log log_data, pchar cfg)
{
    pchar SYSROOT[3] = {"SYSTEM", "RecordLog", "LogType"};

    CFILEOP file;
    int32 tmp = 0;
    if (log_data == NULL)    return -1;

    if (file.OpenFile((char *)cfg, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool OPEN CFG(%s) ERROR!!", cfg);
        return -1;
    }

    //读取任务数
    tmp = -1;
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&tmp);
    if (tmp == -1) log_data->userlog = 0;
    else log_data->userlog = (uint32)tmp;

    tmp = -1;
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[2], (int *)&tmp);
    if (tmp == -1) log_data->syslog = 0;
    else log_data->syslog = (uint32)tmp;

    file.CloseFile();

    return 0;
}
/*******************************************************************************************
*功能:    截取源字符串.符号
*参数:    dst                ---->   目的字符串
*         src                ---->   源字符串
*         返回值
*
*注释:
*******************************************************************************************/
static void dbsync_dealstr(pchar dst, pchar src)
{
    if ((dst == NULL) && (src == NULL)) {
        return;
    }
    pchar p = NULL;
    p = strstr(src, ".");
    if (p == NULL) {
        return;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool dbsync_dealstr: %s", p);
    memcpy(dst, src, p - src);
    memcpy(src, p + 1, strlen(p));
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool dbsync_dealstr dst: %s", dst);
}
/*******************************************************************************************
*功能:    密码加密
*参数:    output                ---->   目标字符串
*         input                 ---->   源字符串
*         返回值                 目标字符串
*
*注释:
*******************************************************************************************/
static pchar dbsync_CDencode(pchar output, pchar input)
{
    if (output == NULL)
        return NULL;
    char chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    int32 i = 0, j = 0;
    pchar _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    while (i < strlen(input)) {

        chr1 = input[i++];
        chr2 = input[i++];
        chr3 = input[i++];

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (i > (strlen(input) + 1)) {
            enc3 = enc4 = 64;
        } else if (i > strlen(input)) {
            enc4 = 64;
        }
        if (enc1 < 62)
            output[j++] = _keyStr[enc1];
        if (enc2 < 62)
            output[j++] = _keyStr[enc2];
        if (enc3 < 62)
            output[j++] = _keyStr[enc3];
        if (enc4 < 62)
            output[j++] = _keyStr[enc4];
    }
    return output;
}
/*******************************************************************************************
*功能:    字符串替换
*参数:    dest                ---->   目标字符串
*         src                 ---->   源字符串
*         oldstr              ---->   旧的字符串
*         newstr              ---->   替换新的字符串
*         返回值              目标字符串
*
*注释:
*******************************************************************************************/
static pchar dbsync_strreplace(pchar dest, pchar src, const char *oldstr, const char *newstr)
{

    char *needle = NULL;
    char *tmp = NULL;
    if ((dest == NULL) || (src == NULL))
        return NULL;
    memcpy(dest, src, strlen(src));
    if (strcmp(oldstr, newstr) == 0) {
        return dest;
    }

    while ((needle = strstr(dest, oldstr))) {

        tmp = (char *)malloc(strlen(dest) + (strlen(newstr) - strlen(oldstr)) + 1);
        strncpy(tmp, dest, needle - dest);
        tmp[needle - dest] = '\0';
        strcat(tmp, newstr);
        strcat(tmp, needle + strlen(oldstr));
        memset(dest, 0, strlen(dest));
        memcpy(dest, tmp, strlen(tmp));
        free(tmp);
    }
    return dest;
}
/*******************************************************************************************
*功能:    密码加密
*参数:    output                ---->   目标字符串
*         output_len            ---->   目标字符串空间长度
*         pstr                  ---->   源密码
*         rand_data             ---->   随机数种子
*         返回值
*
*注释:
*******************************************************************************************/
static pchar  dbsync_np_encode(pchar output, int32 output_len, pchar pstr, uint64 rand_data)
{
    pchar arr_pw = "ABCDEFGHIJKabcdefghijklLMNOPQRSTUVWXYZmnopqrstuvwxyz0123456789";

    char out_str[512] = {0};
    int ipos = 0;
    int  i = 0;
    char n_pstr[512] = {0};
    char p_header[512] = {0};
    char p_end[512] = {0};

    if (pstr == NULL)
        return NULL;

    srand(rand_data);

    dbsync_CDencode(output, pstr);
    dbsync_strreplace(out_str, output, "=", "");
    memset(output, 0, output_len);
    memcpy(output, out_str, strlen(out_str));
    memset(out_str, 0, sizeof(out_str));
    for (i = 0; i < 13; i++) {
        ipos = (rand() * 100 + 1) % (strlen(arr_pw));
        out_str[i] = arr_pw[ipos];
    }

    if (strlen(output) > 3) {
        memcpy(p_header, output, 3);
        memcpy(p_end, output + 3, strlen(output) - 3);
    } else {
        memcpy(p_header, output, strlen(output));
    }
    sprintf(n_pstr, "%s%s", out_str, p_header);
    memset(out_str, 0, sizeof(out_str));
    for (i = 0; i < 5; i++) {
        ipos = (rand() * 100 + 2) % (strlen(arr_pw));
        out_str[i] = arr_pw[ipos];
    }
    sprintf(n_pstr + strlen(n_pstr), "%s", out_str);
    memset(out_str, 0, sizeof(out_str));

    for (i = 0; i < 12; i++) {
        ipos = (rand() * 100 + 3) % (strlen(arr_pw));
        out_str[i] = arr_pw[ipos];
    }

    sprintf(n_pstr + strlen(n_pstr), "%s%s", p_end, out_str);

    memset(output, 0, output_len);
    dbsync_CDencode(output, n_pstr);
    dbsync_strreplace(out_str, output, "=", "");
    memset(output, 0, output_len);
    memcpy(output, out_str, strlen(out_str));
    return output;
}

/*******************************************************************************************
*功能:    读取配置文件信息
*参数:    list                ---->   列表首地址
*         listcnt             ---->   列表空间最大个数
*         timer               ---->   数据库同步参数
*         返回值              ---->   任务数(正数)
*
*注释:
*******************************************************************************************/
static int32 get_tasklist_old(pdbsync_task list, int32 listcnt, pdbsync_time timer, pchar cfg)
{
    pchar SYSROOT[2] = {"MAIN", "TaskNum"};
    pchar TASKCFG = "Task";

    CFILEOP file;
    int32 taskcnt = 0;
    char tasktmp[64] = {0}, tmpdata[64] = {0};
    int32 err = 0;
    if (list == NULL)    return -1;

    //初始化参数
    memset(list, 0, listcnt * sizeof(dbsync_task));
    if (listcnt > DBSYNC_TASKMAX) {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool TASK IS OVERFLOW, CNT = %d, MAX = %d", listcnt, DBSYNC_TASKMAX);
        listcnt = DBSYNC_TASKMAX;
    }

    if (file.OpenFile((char *)cfg, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool OPEN CFG(%s) ERROR!!", cfg);
        return -1;
    }

    //读取任务数
    file.ReadCfgFile((char *)SYSROOT[0], (char *)SYSROOT[1], tmpdata, sizeof(tmpdata));
    STRTOINT(taskcnt, tmpdata);
    if (taskcnt > listcnt) {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool TASK IS OVERFLOW, LIST = %d, CFG = %d", listcnt, taskcnt);
        taskcnt = listcnt;

    }
    if (timer != NULL) {
        int32 tmp;
        tmp = -1;
        if (file.ReadCfgFile((char *)SYSROOT[0], "CKSyncDay", tmpdata, sizeof(tmpdata)) == E_FILE_OK) {
            STRTOINT(tmp, tmpdata);

            if (tmp == -1) timer->chsyncday = 0;
            else timer->chsyncday = (uint32)tmp;
        } else {
            timer->chsyncday = 0;
        }

        file.ReadCfgFile((char *)SYSROOT[0], "Synctimer", timer->sysnctimer, sizeof(timer->sysnctimer));
        FILTERSTR(timer->sysnctimer);

        tmp = -1;
        if (file.ReadCfgFile((char *)SYSROOT[0], "Syncspe", tmpdata, sizeof(tmpdata)) == E_FILE_OK) {
            STRTOINT(tmp, tmpdata);
            if (tmp == -1) timer->syncspe = 0;
            else timer->syncspe = (uint32)tmp;
        } else {
            timer->syncspe = 0;
        }
    }

    //读取
    for (int32 i = 0; i < taskcnt; i++) {
        int32 tmp;
        char idtmp[64] = {0};
        char tmptable_tmp[64] = {0};
        char passwd_tmp[512] = {0};

        list[i].task_num = taskcnt;
        sprintf(tasktmp, "%s%d", TASKCFG, i);

        if (file.ReadCfgFile(tasktmp, "ID", tasktmp, sizeof(tasktmp)) == E_FILE_OK) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool not old");
            taskcnt = -1;
            break;
        }

        file.ReadCfgFile(tasktmp, "Name", list[i].name, sizeof(list[i].name));
        FILTERSTR(list[i].name);

        struct timeval tv;
        gettimeofday(&tv, NULL);
        // file.ReadCfgFile(tasktmp, "ID", idtmp, sizeof(idtmp));
        // FILTERSTR(idtmp);
        list[i].id = tv.tv_sec * 1000 + tv.tv_usec / 1000;

        err |= file.ReadCfgFile(tasktmp, "InDBMS", list[i].sdbtype, sizeof(list[i].sdbtype));
        FILTERSTR(list[i].sdbtype);
        dbsync_to_upper(list[i].sdbtype);
        err |= file.ReadCfgFile(tasktmp, "Charset", list[i].sdbcharset, sizeof(list[i].sdbcharset));
        FILTERSTR(list[i].sdbcharset);
        err |= file.ReadCfgFile(tasktmp, "InDBName", list[i].sdatabase, sizeof(list[i].sdatabase));
        FILTERSTR(list[i].sdatabase);
        err |= file.ReadCfgFile(tasktmp, "InDBServer", list[i].sdbmsip, sizeof(list[i].sdbmsip));
        FILTERSTR(list[i].sdbmsip);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "InDBPort", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].sport = 0;
        else list[i].sport = (uint32)tmp;

        err |= file.ReadCfgFile(tasktmp, "InUser", list[i].susername, sizeof(list[i].susername));
        FILTERSTR(list[i].susername);
        err |= file.ReadCfgFile(tasktmp, "InPWD", passwd_tmp, sizeof(passwd_tmp));
        //err |= file.ReadCfgFile(tasktmp, "InPWD", list[i].spassword, sizeof(list[i].spassword));
        FILTERSTR(passwd_tmp);
        dbsync_np_encode(list[i].spassword, sizeof(list[i].spassword), passwd_tmp, list[i].id);

        err |= file.ReadCfgFile(tasktmp, "OutDBMS", list[i].tdbtype, sizeof(list[i].tdbtype));
        FILTERSTR(list[i].tdbtype);
        dbsync_to_upper(list[i].tdbtype);
        err |= file.ReadCfgFile(tasktmp, "Charset", list[i].tdbcharset, sizeof(list[i].tdbcharset));
        FILTERSTR(list[i].tdbcharset);
        err |= file.ReadCfgFile(tasktmp, "OutDBName", list[i].tdatabase, sizeof(list[i].tdatabase));
        FILTERSTR(list[i].tdatabase);

        err |= file.ReadCfgFile(tasktmp, "OutDBServer", list[i].tdbmsip, sizeof(list[i].tdbmsip));
        FILTERSTR(list[i].tdbmsip);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "OutDBPort", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].tport = 0;
        else list[i].tport = (uint32)tmp;

        err |= file.ReadCfgFile(tasktmp, "OutUser", list[i].tusername, sizeof(list[i].tusername));
        FILTERSTR(list[i].tusername);
        err |= file.ReadCfgFile(tasktmp, "OutPWD", passwd_tmp, sizeof(passwd_tmp));
        FILTERSTR(passwd_tmp);
        dbsync_np_encode(list[i].tpassword, sizeof(list[i].tpassword), passwd_tmp, list[i].id + 1);

        tmp = -1;
        file.ReadCfgFile(tasktmp, "Area", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) {
            list[i].direction = 0;
            list[i].doublesided = 0;
        } else {
            list[i].direction = ((uint32)tmp == 2) ? 0 : (uint32)tmp;
            list[i].doublesided = ((uint32)tmp == 2) ? 1 : 0;
        }

        list[i].tmptable = 0;

        tmp = -1;
        file.ReadCfgFile(tasktmp, "status", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].enable = 0;
        else list[i].enable = (uint32)tmp;

        tmp = -1;
        file.ReadCfgFile(tasktmp, "TblNum", tmpdata, sizeof(tmpdata));
        STRTOINT(tmp, tmpdata);
        if (tmp == -1) list[i].tables_num = 0;
        else list[i].tables_num = (uint32)tmp > DBSYNC_TABLES_NUM ? DBSYNC_TABLES_NUM : (uint32)tmp;

        list[i].table = (pdbsync_table)calloc(list[i].tables_num, sizeof(dbsync_table));

        for (int j = 0; j < list[i].tables_num; j++) {
            char tables_tmp[64] = {0};

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "SrcTblName%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].SrcTblName, sizeof(list[i].table[j].SrcTblName));
            FILTERSTR(list[i].table[j].SrcTblName);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "DstTblName%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].DstTblName, sizeof(list[i].table[j].DstTblName));
            FILTERSTR(list[i].table[j].DstTblName);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKTmpTbl%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKTmpTbl, sizeof(list[i].table[j].CKTmpTbl));
            FILTERSTR(list[i].table[j].CKTmpTbl);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKCopy%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKCopy, sizeof(list[i].table[j].CKCopy));
            FILTERSTR(list[i].table[j].CKCopy);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKUpsert%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKUpsert, sizeof(list[i].table[j].CKUpsert));
            FILTERSTR(list[i].table[j].CKUpsert);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "Filter%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].Filter, sizeof(list[i].table[j].Filter));
            FILTERSTR(list[i].table[j].Filter);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKInsert%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKInsert, sizeof(list[i].table[j].CKInsert));
            FILTERSTR(list[i].table[j].CKInsert);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKUpdate%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKUpdate, sizeof(list[i].table[j].CKUpdate));
            FILTERSTR(list[i].table[j].CKUpdate);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKDelete%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKDelete, sizeof(list[i].table[j].CKDelete));
            FILTERSTR(list[i].table[j].CKDelete);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "SrcKey%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].SrcKey, sizeof(list[i].table[j].SrcKey));
            FILTERSTR(list[i].table[j].SrcKey);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "DstKey%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].DstKey, sizeof(list[i].table[j].DstKey));
            FILTERSTR(list[i].table[j].DstKey);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "SrcField%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].SrcField, sizeof(list[i].table[j].SrcField));
            FILTERSTR(list[i].table[j].SrcField);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "DstField%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].DstField, sizeof(list[i].table[j].DstField));
            FILTERSTR(list[i].table[j].DstField);

            memset(tables_tmp, 0, sizeof(tables_tmp));
            sprintf(tables_tmp, "CKTrigger%d", j);
            err |= file.ReadCfgFile(tasktmp, tables_tmp, list[i].table[j].CKTrigger, sizeof(list[i].table[j].CKTrigger));
            FILTERSTR(list[i].table[j].CKTrigger);

            PRINT_INFO_HEAD;
            print_info("dbsync_tool tables %d", j);
            dbsync_dealstr(list[i].sowner, list[i].table[j].SrcTblName);
            dbsync_dealstr(list[i].towner, list[i].table[j].DstTblName);
        }

        err |= file.ReadCfgFile(tasktmp, "ObjAlias", list[i].objalias, sizeof(list[i].objalias));
        FILTERSTR(list[i].objalias);

        snprintf(list[i].tempTableName, sizeof(list[i].tempTableName), "%lld", list[i].id);

        PRINT_INFO_HEAD;
        print_info("dbsync_tool %s, id:%llu, name:%s, sdbtype:%s, sdbcharset:%s, sdatabase:%s, sdbmsip:%s, sport:%u, susername:%s, spassword:%s, tdbtype:%s, tdbcharset:%s, \
                     tdatabase:%s, tdbmsip:%s, tport:%u, tusername:%s, tpassword:%s, direction:%u, doublesided:%u, tmptable:%u, enable:%u, sowner:%s, objalias:%s, towner:%s",
                   tasktmp, list[i].id, list[i].name, list[i].sdbtype, list[i].sdbcharset, list[i].sdatabase, list[i].sdbmsip, list[i].sport,
                   list[i].susername, list[i].spassword, list[i].tdbtype, list[i].tdbcharset, list[i].tdatabase, list[i].tdbmsip,
                   list[i].tport, list[i].tusername, list[i].tpassword, list[i].direction, list[i].doublesided, list[i].tmptable, list[i].enable,
                   list[i].sowner, list[i].objalias, list[i].towner);
        usleep(1000);//确保id值是唯一的
    }

    file.CloseFile();

    if (err == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool READ CFG(%s) ERROR, PLS CHECK FILE WITH LOG INFO!!", cfg);
        taskcnt = -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("dbsync_tool READ CFG(%s) TASKS = %d", cfg, taskcnt);
    }

    return taskcnt;
}
/*******************************************************************************************
*功能:    字符串转化大写
*参数:    str                ---->   源字符串
*         返回值             ---->    转化后的字符串
*
*注释:
*******************************************************************************************/
static pchar dbsync_to_upper(pchar str)
{
    int i = 0;
    if (str == NULL)
        return NULL;
    while (str[i] != 0) {
        if ((str[i] >= 'a') && (str[i] <= 'z'))
            str[i] -= 32;
        i++;
    }
    return str;
}

/**
 * [locktest 文件锁测试 为了避免多个进程同时调用]
 * @return [成功返回0]
 */
static int locktest()
{
    int pidfd = 0;
    char line[1024] = {0};

    pidfd = open(DBSYNC_TOOL_PID_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (pidfd < 0) {
        perror("open");
        return -1;
    }

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;

    if (fcntl(pidfd, F_SETLK, &fl) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            printf("dbsync_tool already running\n");
            exit (-1);
        } else {
            printf("dbsync_tool unable to lock %s\n", DBSYNC_TOOL_PID_PATH);
            return (-1);
        }
    }
    snprintf(line, sizeof(line), "%d", (long)getpid());
    if (ftruncate(pidfd, 0) < 0) {
        perror("dbsync_tool ftruncate");
        return (-1);
    }

    if (write(pidfd, line, strlen(line)) < 0) {
        perror("dbsync_tool write");
        return (-1);
    }

    return 0;
}