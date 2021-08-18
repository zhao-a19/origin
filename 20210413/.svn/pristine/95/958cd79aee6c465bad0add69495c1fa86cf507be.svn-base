/*******************************************************************************************
*文件:    dbsync_task.cpp
*描述:
*
*作者:    李亚洲
*日期:    2020-07-24
*修改:    创建文件                          ------>     2020-07-24
*修改:    适配网闸                          ------>     2020-08-14
*修改:    修复添加新策略死循环问题          ------>     2020-09-07
*修改:    添加多线程启动后台程序            ------>     2020-10-19
*修改:    新增接口改为编辑接口              ------>     2020-10-25
*修改:    修改反写策略信息接口              ------>     2020-10-28
*修改:    记录详细日志信息                  ------>     2020-10-30
*修改:    添加重建临时表参数                ------>     2020-11-10
*修改:    添加转移\字符                     ------>     2020-11-18
*修改:    收到信号15条用后台接口退出         ------>     2021-04-12
*修改:    跟java程序通信后，强制认为调用成功  ------>     2021-06-09 王君雷
*         跟java通信时使用内联IP             ------>     2021-06-10 王君雷
*******************************************************************************************/
#include "dbsync_task_debug.h"
#include "fileoperator.h"
#include <curl/curl.h>


#define ADD_CH_STR(dst, src) {memset(dst, 0, MAX_VALUE_LEN);\
                            snprintf(dst, MAX_VALUE_LEN - 1, "\'%s\'", src);}
#define ADD_CH_INT(dst, src) {memset(dst, 0, MAX_VALUE_LEN);\
                            snprintf(dst, MAX_VALUE_LEN - 1, "\'%d\'", src);}
extern bool exit_flag;
extern int g_ipseg;
static void dbsync_tash_state(bool status, pchar stat);
static void *dbsync_update(void *arg);
static void *dbsync_del(void *arg);
static int32 dbsync_udate_file(pchar filename, pchar item, pchar value, uint32 num, bool line_flag = false, int32 line = -1);
/*******************************************************************************************
*功能:    htpps回调函数，获取返回值
*参数:
*
*注释:
*******************************************************************************************/
static size_t push_string(void *buffer, size_t size, size_t nmemb, void *stream)
{
    if ( (size_t) size * nmemb < DBSYNC_HTTPBUF_MAX) {
        memcpy((pchar )stream, (pchar )buffer, (size_t) size * nmemb);
    }
    return size * nmemb;
}

/*******************************************************************************************
*功能:    htpps发送请求函数
*参数:
*    url    url地址
*    param  JSON参数
*    st     请求返回值
*    返回值 -1失败 0 成功
*注释:
*******************************************************************************************/
static bool dbsync_send_post(pchar url, pchar param, pchar st)
{
    if (st == NULL)
        return DBSYNC_TASK_FAILED;
    CURL *curl_handle = NULL;
    CURLcode curl_res;
    curl_res = curl_global_init(CURL_GLOBAL_ALL);
    if (curl_res == CURLE_OK) {
        curl_handle = curl_easy_init();
        if (curl_handle != NULL) {
            char thisurl[1024] = {0};
            sprintf(thisurl, url, g_ipseg);
            PRINT_DBG_HEAD
            print_dbg("url:%s", thisurl);
            curl_easy_setopt(curl_handle, CURLOPT_URL, thisurl);
            curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
            if (param != NULL) {
                curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, strlen(param));
                curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, param);
                curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 500);//删除临时表时间长，即扩大超时时间
            } else {
                curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, 0);
                //curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, param);
                curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 40);
            }
            curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
            curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
            //curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30);
            curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L);
            curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, push_string);
            curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, st);
            curl_easy_setopt(curl_handle, CURLOPT_HEADER, 0L);

            struct curl_slist *pList = NULL;
            pList = curl_slist_append(pList, "Content-Type:application/json");
            curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, pList);
            curl_res = curl_easy_perform(curl_handle);
            if (curl_res != CURLE_OK) {
                PRINT_ERR_HEAD;
                print_err("curl_easy_perform error, err_msg:[%ld]:%s", curl_res, curl_easy_strerror(curl_res));
                curl_easy_cleanup(curl_handle);
                return DBSYNC_TASK_FAILED;
            }
            curl_easy_cleanup(curl_handle);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("CURL ERROR : %s", curl_easy_strerror(curl_res));
        return DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool  http json info :%s->%s", param, st);
    return DBSYNC_TASK_SUCCESS;
}
/*******************************************************************************************
*功能:    新增策略请求
*参数:
*    param   JSON参数
*    st      http返回状态信息
*    返回值 0成功 其他失败
*注释:
*******************************************************************************************/
static bool dbsync_insert_task(pchar param, pchar st)
{
    bool ret = false;
    cJSON *root = NULL;
    memset(st, 0, DBSYNC_HTTPBUF_MAX);
    ret = dbsync_send_post(DBSYNC_INSERT_URL, param, st);
    if (ret != DBSYNC_TASK_SUCCESS) {
        dbsync_tash_state(ret, DBSYNC_INSERT_ERROR);
        return DBSYNC_TASK_FAILED;
    }
    root = cJSON_Parse(st);
    if (root != NULL) {
        cJSON *item = NULL;
        item = cJSON_GetObjectItem(root, "success");
        if (item != NULL) {
            ret = item->valueint;
        } else {
            ret = DBSYNC_TASK_FAILED;
        }
        item = cJSON_GetObjectItem(root, "message");
        if (item != NULL) {
            memset(st, 0, DBSYNC_HTTPBUF_MAX);
            snprintf(st, DBSYNC_HTTPBUF_MAX - 1, "%s", item->valuestring);
        }
        cJSON_Delete(root);
    } else {
        ret = DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool insert http status:%s", st);
    return ret;
}
/*******************************************************************************************
*功能:    修改策略json
*参数:
*    list    列表
*    param   JSON参数
*    run_st  运行状态信息，DBSYNC_TASK_DEFAULT默认值(配置是什么就设置什么)
*    返回值 JSON字符串地址
*注释:
*******************************************************************************************/
static pchar dbsync_update_json_info(dbsync_task list, char **param, int32 run_st = DBSYNC_TASK_DEFAULT)
{
    cJSON *root = NULL;
    cJSON *tables = NULL;
    cJSON *array = NULL;
    root =  cJSON_CreateObject();
    if (root == NULL) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool update_task cJSON_CreateObject failse");
        *param = NULL;
        return NULL;
    }

    cJSON_AddNumberToObject(root, "delTmpTbl", list.tmptable);
    cJSON_AddNumberToObject(root, "direction", list.direction);
    cJSON_AddNumberToObject(root, "doubleDirect", list.doublesided);
    cJSON_AddNumberToObject(root, "lId", list.id);
    cJSON_AddNumberToObject(root, "nStatus", run_st == DBSYNC_TASK_DEFAULT ? list.enable : run_st);

    cJSON_AddStringToObject(root, "sCharset", list.sdbcharset);
    cJSON_AddStringToObject(root, "sDataBase", list.sdatabase);
    cJSON_AddStringToObject(root, "sDbType", list.sdbtype);
    cJSON_AddStringToObject(root, "sDbmsIp", list.sdbmsip);
    cJSON_AddStringToObject(root, "sPassword", list.spassword);
    cJSON_AddNumberToObject(root, "sPort", list.sport);
    cJSON_AddStringToObject(root, "sUserName", list.susername);

    cJSON_AddStringToObject(root, "strategyName", list.name);

    cJSON_AddStringToObject(root, "tCharset", list.tdbcharset);
    cJSON_AddStringToObject(root, "tDataBase", list.tdatabase);
    cJSON_AddStringToObject(root, "tDbType", list.tdbtype);
    cJSON_AddStringToObject(root, "tDbmsIp", list.tdbmsip);
    cJSON_AddStringToObject(root, "tPassword", list.tpassword);
    cJSON_AddNumberToObject(root, "tPort", list.tport);
    cJSON_AddStringToObject(root, "tUserName", list.tusername);

    cJSON_AddStringToObject(root, "sOwner", list.sowner);
    cJSON_AddStringToObject(root, "objAlias", list.objalias);
    cJSON_AddStringToObject(root, "tOwner", list.towner);
    cJSON_AddStringToObject(root, "tempTableName", list.tempTableName);

    array =  cJSON_CreateArray();
    if (array == NULL) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool update_task cJSON_CreateObject failse");
        *param = NULL;
        return NULL;
    }
    for (int i = 0; i < list.tables_num; i++) {
        tables = cJSON_Parse(list.tables[i]);
        if (tables != NULL)
            cJSON_AddItemToArray(array, tables);
    }
    cJSON_AddItemToObject(root, "strategyTableModelVos", array);

    *param = cJSON_Print(root);
    cJSON_Delete(root);
    return *param;
}
/*******************************************************************************************
*功能:    修改策略请求
*参数:
*    param   JSON参数
*    st      http返回状态信息
*    返回值 0成功 其他失败
*注释:
*******************************************************************************************/
static bool dbsync_update_task(pchar param, pchar st)
{
    bool ret = false;
    cJSON *root = NULL;
    memset(st, 0, DBSYNC_HTTPBUF_MAX);
    ret = dbsync_send_post(DBSYNC_UPDATE_URL, param, st);
    if (ret != DBSYNC_TASK_SUCCESS) {
        dbsync_tash_state(ret, DBSYNC_UPDATE_ERROR);
        return DBSYNC_TASK_FAILED;
    }
    root = cJSON_Parse(st);
    if (root != NULL) {
        cJSON *item = NULL;
        item = cJSON_GetObjectItem(root, "success");
        if (item != NULL) {
            ret = item->valueint;
        } else {
            ret = DBSYNC_TASK_FAILED;
        }
        item = cJSON_GetObjectItem(root, "message");
        if (item != NULL) {
            memset(st, 0, DBSYNC_HTTPBUF_MAX);
            snprintf(st, DBSYNC_HTTPBUF_MAX - 1, "%s", item->valuestring);
        }
        cJSON_Delete(root);
    } else {
        ret = DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool  update http status:%s", st);
    return ret;
}


/*******************************************************************************************
*功能:    定时同步json
*参数:
*    timer    定时同步参数
*    param   JSON参数
*    返回值 JSON字符串地址
*注释:
*******************************************************************************************/
static pchar dbsync_timer_info(dbsync_time timer, char **param)
{
    cJSON *root = NULL;
    cJSON *tables = NULL;
    root =  cJSON_CreateObject();
    if (root == NULL) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool dbsync_timer_info cJSON_CreateObject failse");
        *param = NULL;
        return NULL;
    }

    cJSON_AddNumberToObject(root, "openTask", timer.chsyncday);
    cJSON_AddNumberToObject(root, "syncSpe", timer.syncspe);
    cJSON_AddStringToObject(root, "syncTimer", timer.sysnctimer);

    *param = cJSON_Print(root);
    cJSON_Delete(root);
    return *param;
}
/*******************************************************************************************
*功能:    定时同步请求
*参数:
*    param   JSON参数
*    st      http返回状态信息
*    返回值 0成功 其他失败
*注释:
*******************************************************************************************/
static bool dbsync_timer(pchar param, pchar st)
{
    bool ret = false;
    cJSON *root = NULL;
    memset(st, 0, DBSYNC_HTTPBUF_MAX);
    ret = dbsync_send_post(DBSYNC_TIME_URL, param, st);
    if (ret != DBSYNC_TASK_SUCCESS) {
        dbsync_tash_state(ret, DBSYNC_TIME_ERROR);
        return DBSYNC_TASK_FAILED;
    }
    root = cJSON_Parse(st);
    if (root != NULL) {
        cJSON *item = NULL;
        item = cJSON_GetObjectItem(root, "success");
        if (item != NULL) {
            ret = item->valueint;
        } else {
            ret = DBSYNC_TASK_FAILED;
        }
        item = cJSON_GetObjectItem(root, "message");
        if (item != NULL) {
            memset(st, 0, DBSYNC_HTTPBUF_MAX);
            snprintf(st, DBSYNC_HTTPBUF_MAX - 1, "%s", item->valuestring);
        }
        cJSON_Delete(root);
    } else {
        ret = DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool  dbsync_timer status:%s", st);
    return ret;
}


/*******************************************************************************************
*功能:    写系统日志
*参数:
*    stat    状态信息
*注释:
*******************************************************************************************/

static void dbsync_tash_state(bool status, pchar stat)
{
#if 1
    CLOGMANAGE logmgr;
    char st_gbk[DBSYNC_HTTPBUF_MAX] = {0};
    if (stat == NULL || stat[0] == '\0')
        return;
    logmgr.Init();
    if (get_sucharset(stat) == CHARSET_UTF8) {
        if (strconv(DBSYNC_CHARSET_UTF8, stat, "GBK", st_gbk) == NULL) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool  charset = %s failed", stat);
            strcpy(st_gbk, stat);
        }
    } else {
        strcpy(st_gbk, stat);
    }

    logmgr.WriteSysLog(DBSYNC_INFO, status ? DBSYNC_SUCCESS : DBSYNC_FAIL, st_gbk);
    logmgr.DisConnect();
#else
    CLOGMANAGE logmgr;
    if (stat == NULL || stat[0] == '\0')
        return;
    logmgr.Init();

    logmgr.WriteSysLog(DBSYNC_INFO, DBSYNC_STATUS, stat);
    logmgr.DisConnect();
#endif
}
/*******************************************************************************************
*功能:    策略处理
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    timre          定时任务信息
*    返回值  成功(DBSYNC_TASK_SUCCESS) 失败(DBSYNC_TASK_FAILED) 目前不使用
*注释:
*******************************************************************************************/
bool dbsync_task_check_debug(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, dbsync_time timer)
{
    pchar param = NULL, param_bak = NULL;
    char st[DBSYNC_HTTPBUF_MAX];
    bool code_st = true;

    //定时器开启
    dbsync_timer_info(timer, &param);
    dbsync_timer(param, st);
    DBSYNC_FREE(param);

    //检测策略新增/修改/删除状态
    for (int i = 0; i < taskcnt; i++) {
        int j = 0;
        for (j = 0; j < taskcnt_bak; j++) {
            if (tasks[i].id == tasks_bak[j].id) {
                en_dbsyncuse(tasks_bak[j]);
                tasks[i].bak_num = j;//记录备份策略编号，防重复写备份信息
                break;
            }
        }
        if (j >= taskcnt_bak) { //新增策略
            en_dbsyncinsert(tasks[i]);
        } else {
            dbsync_update_json_info(tasks[i], &param);
            dbsync_update_json_info(tasks_bak[j], &param_bak);

            if (param != NULL && param_bak != NULL && strcmp(param, param_bak) == 0) { //策略无修改
                PRINT_DBG_HEAD;
                print_dbg("dbsync_tool not update task");
                DBSYNC_FREE(param);
                DBSYNC_FREE(param_bak);
                continue;
            } else {//策略已修改
                en_dbsyncupdate(tasks[i]);

                DBSYNC_FREE(param);
                DBSYNC_FREE(param_bak);
            }
        }
    }
    //删除的策略
    for (int j = 0; j < taskcnt_bak; j++) {
        if (exit_flag) {
            PRINT_INFO_HEAD;
            print_info("dbsync_tool exit sig");
            goto exit_finish;
        }
        if (!is_endbsyncuse(tasks_bak[j])) {
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool del task");

            dbsync_del(&tasks_bak[j]);
        }
    }

    //修改和新增策略
    for (int i = 0; i < taskcnt; i++) {

        if (exit_flag) {
            PRINT_INFO_HEAD;
            print_info("dbsync_tool exit sig");
            goto exit_finish;
        }

        if (is_endbsyncinsert(tasks[i])) { //新增策略
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool new task");
            tasks[i].update_flag = false;
            dbsync_update(&tasks[i]);
        } else if (is_endbsyncupdate(tasks[i])) { //策略已修改
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool update task");
            tasks[i].update_flag = true;
            dbsync_update(&tasks[i]);
        }
    }
exit_finish:
    return code_st;
}

/*******************************************************************************************
*功能:    策略处理 线程
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    timre          定时任务信息
*    thread_num     开启线程个数
*    返回值  成功(DBSYNC_TASK_SUCCESS) 失败(DBSYNC_TASK_FAILED) 目前不使用
*注释:
*******************************************************************************************/
bool dbsync_task_check_thread_debug(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, dbsync_time timer, uint32 thread_num)
{
    pchar param = NULL, param_bak = NULL;
    char st[DBSYNC_HTTPBUF_MAX];
    bool code_st = true;
    uint32 open_thread_num = 0;

    //定时器开启
    dbsync_timer_info(timer, &param);
    dbsync_timer(param, st);
    DBSYNC_FREE(param);
    //检测策略新增/修改/删除状态
    for (int i = 0; i < taskcnt; i++) {
        int j = 0;
        for (j = 0; j < taskcnt_bak; j++) {
            if (tasks[i].id == tasks_bak[j].id) {
                en_dbsyncuse(tasks_bak[j]);
                tasks[i].bak_num = j;//记录备份策略编号，防重复写备份信息
                break;
            }
        }
        if (j >= taskcnt_bak) { //新增策略
            en_dbsyncinsert(tasks[i]);
        } else {
            dbsync_update_json_info(tasks[i], &param);
            dbsync_update_json_info(tasks_bak[j], &param_bak);

            if (param != NULL && param_bak != NULL && strcmp(param, param_bak) == 0) { //策略无修改
                PRINT_DBG_HEAD;
                print_dbg("dbsync_tool not update task");
                DBSYNC_FREE(param);
                DBSYNC_FREE(param_bak);
                continue;
            } else {//策略已修改
                en_dbsyncupdate(tasks[i]);

                DBSYNC_FREE(param);
                DBSYNC_FREE(param_bak);
            }
        }
    }
    //删除的策略
    for (int j = 0; j < thread_num; j++) {
        if (j >= taskcnt_bak)
            break;
        if (pthread_create(&tasks_bak[j].tid, NULL, dbsync_del, tasks_bak + j) != 0) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool del create pthread failed!!");
        }
        usleep(1000);
    }

    for (int j = 0; j < thread_num; j++) {
        if (tasks_bak[j].tid != 0) {
            PRINT_INFO_HEAD;
            print_info("dbsync_tool del pthread quit!!");
            pthread_join(tasks_bak[j].tid, NULL);
        }
    }

    //修改和新增策略
    for (int i = 0; i < taskcnt; i++) {

        if (is_endbsyncinsert(tasks[i])) { //新增策略
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool new task");
            tasks[i].update_flag = false;
        } else if (is_endbsyncupdate(tasks[i])) { //策略已修改
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool update task");
            tasks[i].update_flag = true;
        }
    }
    //修改和新增策略
    for (int i = 0; i < thread_num; i++) {

        if (i >= taskcnt)
            break;
        //开启线程
        if (pthread_create(&(tasks[i].tid), NULL, dbsync_update, tasks + i) != 0) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool update create pthread failed!!");
        }
        usleep(1000);
    }

    for (int i = 0; i < thread_num; i++) {
        if (tasks[i].tid != 0) {
            PRINT_INFO_HEAD;
            print_info("dbsync_tool update pthread quit!!");
            pthread_join(tasks[i].tid, NULL);
        }
    }
    return code_st;
}
/*******************************************************************************************
*功能:    更新源文件策略信息
* 参数：
*    taskcnt        新策略个数
*    tasks          新策略列表
*    cfg            文件名字
*    返回值  成功(0) 失败(-1)
*注释:
*******************************************************************************************/
int32 dbsync_update_taskinfo_debug(int32 taskcnt, pdbsync_task tasks, pchar cfg)
{

    //修改和新增策略
    for (int i = 0; i < taskcnt; i++) {
        if (is_endbsyncsuccess(tasks[i])) {

            cJSON *tables_json = NULL;
            pchar tables_str = NULL;
            char tmptable_tmp[64] = {0};

            sprintf(tmptable_tmp, "%llu_TMPTABLE", tasks[i].id);
            dbsync_udate_file(cfg, tmptable_tmp, "0", 1);
            //int32 linenum = dbsync_udate_file(cfg, "TABLE0", NULL, i + 1, true);
            for (int j = 0; j < tasks[i].tables_num; j++) {
                char tables_tmp[64] = {0};
                sprintf(tables_tmp, "%llu_TABLE%d", tasks[i].id, j);

                //if (tasks[i].tables[j][0] != '\0') {
                cJSON *tables_json = cJSON_Parse(tasks[i].tables[j]);
                if (tables_json != NULL) {
                    cJSON *item = cJSON_GetObjectItem(tables_json, "delTrigger");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭重建触发器
                    }
                    item = cJSON_GetObjectItem(tables_json, "tableCopy");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭表卡拷贝
                    }
                    item = cJSON_GetObjectItem(tables_json, "rebuildTmpTb");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭重建临时表
                    }
                    pchar tables_str = cJSON_PrintUnformatted(tables_json);
                    cJSON_Delete(tables_json);
                    if (tables_str != NULL) {
                        dbsync_udate_file(cfg, tables_tmp, tables_str, 1);
                        //dbsync_udate_file(cfg, tables_tmp, tables_str, i + 1, false, linenum + j);
                        free(tables_str);
                    }
                }
                // }
            }
        }
    }

    return 0;
}
/*******************************************************************************************
*功能:   写策略信息
*参数:
*    taskcnt        当前策略数
*    bakfile        备份文件
*    TOTAL          标记策略信息还是策略总数(TRUE)
*    file           CFILEOP类数据
*    tasks          策略信息
*注释:
*******************************************************************************************/
static void dbsync_write_task_info(uint32 taskcnt, pchar bakfile, bool TOTAL, CFILEOP &file, pdbsync_task tasks = NULL)
{
    pchar SYSROOT[2] = {"MAIN", "TaskNum"};
    pchar TASKCFG = "Task";
    char tasktmp[64] = {0};
    char tmptable_tmp[64] = {0};

    if (TOTAL) {
        file.WriteCfgFileInt(SYSROOT[0], SYSROOT[1], taskcnt);
    } else {
        sprintf(tasktmp, "%s%d", TASKCFG, taskcnt);
        file.WriteCfgFile(tasktmp, "Name", tasks->name);

        char tmp[64] = {0};
        snprintf(tmp, sizeof(tmp) - 1, "%llu", tasks->id);
        file.WriteCfgFile(tasktmp, "ID", tmp);

        file.WriteCfgFileInt(tasktmp, "DIRECTION", tasks->direction);
        file.WriteCfgFileInt(tasktmp, "DOUBLESIDED", tasks->doublesided);
        sprintf(tmptable_tmp, "%llu_TMPTABLE", tasks->id);
        file.WriteCfgFileInt(tasktmp, tmptable_tmp, 0);//策略下发成功，关闭重建触发器
        //file.WriteCfgFileInt(tasktmp, "TMPTABLE", tasks->tmptable);//策略下发成功，关闭重建触发器
        file.WriteCfgFileInt(tasktmp, "ENABLE", tasks->enable == DBSYNC_TASK_START ? 1 : 0); //1开启，0关闭

        file.WriteCfgFile(tasktmp, "SDBTYPE", tasks->sdbtype);
        file.WriteCfgFile(tasktmp, "SCHARSET", tasks->sdbcharset);
        file.WriteCfgFile(tasktmp, "SDATABASE", tasks->sdatabase);
        file.WriteCfgFile(tasktmp, "SDBMSIP", tasks->sdbmsip);
        file.WriteCfgFileInt(tasktmp, "SPORT", tasks->sport);
        file.WriteCfgFile(tasktmp, "SUSERNAME", tasks->susername);
        file.WriteCfgFile(tasktmp, "SPASSWORD", tasks->spassword);

        file.WriteCfgFile(tasktmp, "TDBTYPE", tasks->tdbtype);
        file.WriteCfgFile(tasktmp, "TCHARSET", tasks->tdbcharset);
        file.WriteCfgFile(tasktmp, "TDATABASE", tasks->tdatabase);
        file.WriteCfgFile(tasktmp, "TDBMSIP", tasks->tdbmsip);
        file.WriteCfgFileInt(tasktmp, "TPORT", tasks->tport);
        file.WriteCfgFile(tasktmp, "TUSERNAME", tasks->tusername);
        file.WriteCfgFile(tasktmp, "TPASSWORD",  tasks->tpassword);
        file.WriteCfgFileInt(tasktmp, "TABLENUM", tasks->tables_num);

        file.WriteCfgFile(tasktmp, "SOWNER", tasks->sowner);
        file.WriteCfgFile(tasktmp, "OBJALIAS",  tasks->objalias);
        file.WriteCfgFile(tasktmp, "TOWNER", tasks->towner);
        file.WriteCfgFile(tasktmp, "tempTableName", tasks->tempTableName);

        for (int i = 0; i < tasks->tables_num; i++) {
            char tables_tmp[64] = {0};
            sprintf(tables_tmp, "%llu_TABLE%d", tasks->id, i);
            file.WriteCfgFile(tasktmp, tables_tmp,  tasks->tables[i]);
#if 1
            if (tasks->tables[i][0] != '\0') {
                cJSON *tables_json = cJSON_Parse(tasks->tables[i]);
                if (tables_json != NULL) {
                    cJSON *item = cJSON_GetObjectItem(tables_json, "delTrigger");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭重建触发器
                    }
                    item = cJSON_GetObjectItem(tables_json, "tableCopy");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭表卡拷贝
                    }
                    item = cJSON_GetObjectItem(tables_json, "rebuildTmpTb");
                    if (item && item->valueint == 1) {
                        cJSON_SetIntValue(item, 0);//策略下发成功，关闭重建临时表
                    }
                    pchar tables_str = cJSON_PrintUnformatted(tables_json);
                    cJSON_Delete(tables_json);
                    if (tables_str != NULL) {
                        file.WriteCfgFile(tasktmp, tables_tmp, tables_str);
                        free(tables_str);
                    }
                } else {
                    file.WriteCfgFile(tasktmp, tables_tmp,  tasks->tables[i]);
                }
            }
#endif
        }
    }
}
/*******************************************************************************************
*功能:   备份策略信息
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    bakfile        备份策略成功信息文件
*    返回值          0成功 -1失败
*注释:
*******************************************************************************************/
int32 dbsync_back_task_info_debug(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, pchar bakfile)
{
    uint32 count = 0;
    CFILEOP file;
    if (file.CreateNewFile(bakfile) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_back_task_info CFG(%s) ERROR!!", bakfile);
        return -1;
    }
    //修改和新增策略
    for (int i = 0; i < taskcnt; i++) {
        if (is_endbsyncsuccess(tasks[i])) {
            if (tasks[i].update_flag) {
                en_dbsyncsuccess(tasks_bak[tasks[i].bak_num]);//不重复备份
                PRINT_INFO_HEAD;
                print_info("dbsync_back_task_info update task:%d", i);
            } else {
                PRINT_INFO_HEAD;
                print_info("dbsync_back_task_info insert task:%d", i);
            }
            dbsync_write_task_info(count, bakfile, false, file, tasks + i);
            count++;
        }
    }
    //删除的策略
    for (int i = 0; i < taskcnt_bak; i++) {
        if (!is_endbsyncsuccess(tasks_bak[i])) {
            PRINT_INFO_HEAD;
            print_info("dbsync_back_task_info del task:%d", i);
            dbsync_write_task_info(count, bakfile, false, file, tasks_bak + i);
            count++;
        }
    }
    if (count != 0) {
        dbsync_write_task_info(count, bakfile, true, file);
    }
    file.WriteFileEnd();
    return 0;
}
/*******************************************************************************************
*功能:   更新/新增策略
*参数:
*    arg             策略信息
*    返回值          无
*注释:
*******************************************************************************************/
static void *dbsync_update(void *arg)
{
    pdbsync_task tasks;
    pchar param = NULL;
    char st[DBSYNC_HTTPBUF_MAX];
    bool code_st = true;
    uint32 i = 0;
    tasks = (pdbsync_task)arg;
    pthread_setself(NULL);
    do {

        code_st = true;

        if (!is_endbsyncinsert(tasks[i]) && !is_endbsyncupdate(tasks[i])) { //新增策略
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool not task");
            continue;
        }

        //编辑/新增策略停用策略
        dbsync_update_json_info(tasks[i], &param, DBSYNC_TASK_STOP);
        code_st &= dbsync_update_task(param, st);
        DBSYNC_FREE(param);

        //启/停用策略(已配置文件为准)
        dbsync_update_json_info(tasks[i], &param);
        code_st &= dbsync_update_task(param, st);
        DBSYNC_FREE(param);

#if 1
        //add by wjl 20210609
        if (code_st != DBSYNC_TASK_SUCCESS) {
            code_st = DBSYNC_TASK_SUCCESS;
            PRINT_INFO_HEAD
            print_info("set codest to %d", code_st);
        }
#endif

        //写系统日志(记录策略启动状态)
        if (code_st == DBSYNC_TASK_SUCCESS) {
            en_dbsyncsuccess(tasks[i]);
            //dbsync_tash_state(code_st, st);
        }
        dbsync_tash_state(code_st, st);
    } while (tasks[i].thread_num && (i += tasks[i].thread_num) &&  (i < DBSYNC_TASKMAX) && tasks[i].thread_num && (!exit_flag));
    return NULL;
}
/*******************************************************************************************
*功能:   删除策略
*参数:
*    arg             策略信息
*    返回值          无
*注释:
*******************************************************************************************/
static void *dbsync_del(void *arg)
{
    pdbsync_task tasks;
    pchar param = NULL;
    char st[DBSYNC_HTTPBUF_MAX];
    bool code_st = true;
    uint32 i = 0;
    tasks = (pdbsync_task)arg;

    do {

        code_st = true;
        if (is_endbsyncuse(tasks[i])) {
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool use task");
            continue;
        }
        //停用策略
        dbsync_update_json_info(tasks[i], &param, DBSYNC_TASK_STOP);
        code_st &= dbsync_update_task(param, st);
        DBSYNC_FREE(param);

        //删除策略
        dbsync_update_json_info(tasks[i], &param, DBSYNC_TASK_DEL);
        code_st &= dbsync_update_task(param, st);
        DBSYNC_FREE(param);

        if (code_st == DBSYNC_TASK_SUCCESS) {
            en_dbsyncsuccess(tasks[i]);
            //dbsync_tash_state(code_st, st);
        }
        dbsync_tash_state(code_st, st);
    } while (tasks[i].thread_num && (i += tasks[i].thread_num) &&  (i < DBSYNC_TASKMAX) && tasks[i].thread_num && (!exit_flag));

    return NULL;
}
/*******************************************************************************************
*功能:   对双引号转义
*参数:
*    src        源字符串
*    dst        目的字符串
*    返回值     目的字符串
*注释:
*******************************************************************************************/
static pchar dbsync_insert_ch(pchar src, pchar dst)
{
    pchar src_p = NULL, dst_p = NULL;
    if (src == NULL || dst == NULL)
        return NULL;
    src_p = src;
    dst_p = dst;
    while (*src_p) {
        if (*src_p == '\"') {
            *(dst_p++) = '\\';
        } else if (*src_p == '\\') {
            /*转移\字符*/
            *(dst_p++) = '\\';
            *(dst_p++) = '\\';
            *(dst_p++) = '\\';
        }
        *(dst_p++) = *src_p;
        src_p++;
    }
    return dst;
}
/*******************************************************************************************
*功能:   更新策略文件
*参数:
*    filename        策略配置文件
*    item            更改策略key值
*    value           更改策略value值
*    num             第几个数据
*    line_flag       是否只获取行号，默认false
*    line            需要替换的行号, 默认为-1，已获取为准
*    返回值          行号
*注释:
*******************************************************************************************/
static int32 dbsync_udate_file(pchar filename, pchar item, pchar value, uint32 num, bool line_flag, int32 line)
{
    int32 linenum = 0;
    char cmd[DBSYNC_TABLES_MAX + 128] = {0};
    char table_value[DBSYNC_TABLES_MAX] = {0};
    char buff[64] = {0};
    snprintf(cmd, sizeof(cmd) - 1, "sed -n \"/^%s=/=\" %s |sed -n %dp", item, filename, num);
    sysinfo(cmd, buff, sizeof(buff));
    if (buff[0] != '\0') {
        linenum = atoi(buff);
    }
    if (line_flag) {
        return linenum;
    } else {
        if (line != -1)
            linenum = line;
    }
    if (value != NULL && linenum >= 0) {
        dbsync_insert_ch(value, table_value);
        snprintf(cmd, sizeof(cmd) - 1, "sed -i \"%d c\\%s=\'%s\'\" %s", linenum, item, table_value, filename);
        PRINT_DBG_HEAD;
        print_dbg("dbsync_tool sed :%s", cmd);
        sysinfo(cmd, buff, sizeof(buff));
    }
    return linenum;
}

/*******************************************************************************************
*功能:    开启/关闭日志参数
*参数:
*    logdata    log参数
*    param      JSON参数
*    返回值 JSON字符串地址
*注释:
*******************************************************************************************/
static pchar dbsync_log_json_info(dbsync_log logdata, char **param)
{
    cJSON *root = NULL;
    root =  cJSON_CreateObject();
    if (root == NULL) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool log cJSON_CreateObject failse");
        *param = NULL;
        return NULL;
    }

    cJSON_AddNumberToObject(root, "sysLogFlag", logdata.syslog);
    cJSON_AddNumberToObject(root, "useLogFlag", logdata.userlog);

    *param = cJSON_Print(root);
    cJSON_Delete(root);
    return *param;
}
/*******************************************************************************************
*功能:    日志是否开启请求
*参数:
*    param   JSON参数
*    st      http返回状态信息
*    返回值 0成功 其他失败
*注释:
*******************************************************************************************/
static bool dbsync_log_request(pchar param, pchar st)
{
    bool ret = false;
    cJSON *root = NULL;
    memset(st, 0, DBSYNC_HTTPBUF_MAX);
    ret = dbsync_send_post(DBSYNC_SETLOG_URL, param, st);
    if (ret != DBSYNC_TASK_SUCCESS) {
        dbsync_tash_state(ret, DBSYNC_FLAG_ERROR);
        return DBSYNC_TASK_FAILED;
    }
    root = cJSON_Parse(st);
    if (root != NULL) {
        cJSON *item = NULL;
        item = cJSON_GetObjectItem(root, "success");
        if (item != NULL) {
            ret = item->valueint;
        } else {
            ret = DBSYNC_TASK_FAILED;
        }
        item = cJSON_GetObjectItem(root, "message");
        if (item != NULL) {
            memset(st, 0, DBSYNC_HTTPBUF_MAX);
            snprintf(st, DBSYNC_HTTPBUF_MAX - 1, "%s", item->valuestring);
        }
        cJSON_Delete(root);
    } else {
        ret = DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool  dbsync_log status:%s", st);
    return ret;
}
/*******************************************************************************************
*功能:    设置日志是否开启
*参数:
*    logdata   日志参数
*注释:
*******************************************************************************************/
void dbsync_set_log_debug(dbsync_log logdata)
{
    pchar param = NULL;
    char st[DBSYNC_HTTPBUF_MAX];
    //设置日志信息打印
    dbsync_log_json_info(logdata, &param);
    dbsync_log_request(param, st);
    DBSYNC_FREE(param);
}
/*******************************************************************************************
*功能:    服务状态
*参数:
*    param   JSON参数
*    st      http返回状态信息
*    返回值 true成功 其他失败
*注释:
*******************************************************************************************/
static bool dbsync_status_repuest(pchar st)
{
    bool ret = DBSYNC_TASK_FAILED;
    cJSON *root = NULL;
    memset(st, 0, DBSYNC_HTTPBUF_MAX);
    ret = dbsync_send_post(DBSYNC_STATUS_URL, NULL, st);
    if (ret != DBSYNC_TASK_SUCCESS) {
        dbsync_tash_state(ret, DBSYNC_FLAG_ERROR);
        return DBSYNC_TASK_FAILED;
    }
    root = cJSON_Parse(st);
    if (root != NULL) {
        cJSON *item = NULL;
        item = cJSON_GetObjectItem(root, "success");
        if (item != NULL) {
            ret = item->valueint;
        } else {
            ret = DBSYNC_TASK_FAILED;
        }
        item = cJSON_GetObjectItem(root, "message");
        if (item != NULL) {
            memset(st, 0, DBSYNC_HTTPBUF_MAX);
            snprintf(st, DBSYNC_HTTPBUF_MAX - 1, "%s", item->valuestring);
        }
        cJSON_Delete(root);
    } else {
        ret = DBSYNC_TASK_FAILED;
    }
    PRINT_DBG_HEAD;
    print_dbg("dbsync_tool  dbsync_status_repuest status:%s", st);
    return ret;
}
/*******************************************************************************************
*功能:    服务状态
*注释:
*******************************************************************************************/
void dbsync_status_debug(void)
{
    bool ret = DBSYNC_TASK_FAILED;
    char st[DBSYNC_HTTPBUF_MAX];
    while (1) {
        if (exit_flag) {
            PRINT_INFO_HEAD;
            print_info("dbsync_tool exit status sig");
            break;
        }
        //获取服务状态
        ret = dbsync_status_repuest(st);
        if (ret == DBSYNC_TASK_SUCCESS) {
            PRINT_DBG_HEAD;
            print_dbg("dbsync_tool  dbsync_status success");
            //dbsync_tash_state(st);
            break;
        }
        sleep(5);
    }
}
/*******************************************************************************************
*功能:   分割字符串(,)
*参数:
*    src        源字符串
*    返回值      分割好的json数据
*注释:
*******************************************************************************************/
static cJSON *dnsync_tok_str(pchar src, pchar pri, uint64 id)
{
    if (src == NULL)
        return NULL;
    cJSON *array_tmp = NULL, *object_tmp = NULL;
    uint32 count = 0;
    object_tmp = cJSON_CreateObject();
    if ((object_tmp == NULL)) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool dnsync_tok_str cJSON_CreateObject failse");
        return NULL;
    }
    char src_tmp[255] = {0};
    char *result = NULL;
    memcpy(src_tmp, src, strlen(src));
    if (strcmp(src_tmp, "*") != 0) {
        result = strtok(src_tmp, ",");
        while ( result != NULL ) {
            char tables_tmp[64] = {0};
            sprintf(tables_tmp, "%llu", id + 1 + count);

            array_tmp = cJSON_CreateArray();
            if ((array_tmp == NULL)) {
                PRINT_ERR_HEAD;
                print_err("dbsync_tool dnsync_tok_str cJSON_CreateObject failse");
                return NULL;
            }
            cJSON_AddItemToArray(array_tmp, cJSON_CreateString(result));
            cJSON_AddItemToObject(object_tmp, tables_tmp, array_tmp);
            result = strtok(NULL, ",");
            count++;
        }
    } else {
        char tables_tmp[64] = {0};
        sprintf(tables_tmp, "%llu", id + 1 + count);

        array_tmp = cJSON_CreateArray();
        if ((array_tmp == NULL)) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool dnsync_tok_str cJSON_CreateObject failse");
            return NULL;
        }
        cJSON_AddItemToArray(array_tmp, cJSON_CreateString(pri));
        cJSON_AddItemToObject(object_tmp, tables_tmp, array_tmp);
        count++;

        array_tmp = cJSON_CreateArray();
        if ((array_tmp == NULL)) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool dnsync_tok_str cJSON_CreateObject failse");
            return NULL;
        }
        sprintf(tables_tmp, "%llu", id + 1 + count);
        cJSON_AddItemToArray(array_tmp, cJSON_CreateString(src));
        cJSON_AddItemToObject(object_tmp, tables_tmp, array_tmp);
    }
    return object_tmp;
}
/*******************************************************************************************
*功能:   分割字符串(,)
*参数:
*    src        源字符串
*    pri        主键
*    返回值      分割好的cols json数据
*注释:
*******************************************************************************************/
static cJSON *dnsync_dealcols_str(pchar src, pchar pri, uint64 id)
{
    if (src == NULL)
        return NULL;
    cJSON *array_tmp = NULL, *object_tmp = NULL;
    uint32 count = 0;
    array_tmp = cJSON_CreateObject();

    if ((array_tmp == NULL)) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool dnsync_tok_str cJSON_CreateObject failse");
        return NULL;
    }
    char src_tmp[255] = {0};
    char *result = NULL;
    memcpy(src_tmp, src, strlen(src));

    if (strcmp(src_tmp, "*") != 0) {
        result = strtok(src_tmp, ",");
        while ( result != NULL ) {
            char tables_tmp[64] = {0};
            sprintf(tables_tmp, "%llu", id + 1 + count);
            object_tmp = cJSON_CreateObject();
            if ((object_tmp == NULL)) {
                break;
            }
            cJSON_AddStringToObject(object_tmp, "src_col", result);
            cJSON_AddStringToObject(object_tmp, "src_desc", "");
            if (strcmp(result, pri) == 0) {
                cJSON_AddTrueToObject(object_tmp, "src_pri");
                cJSON_AddTrueToObject(object_tmp, "dst_pri");
            } else {
                cJSON_AddFalseToObject(object_tmp, "src_pri");
                cJSON_AddFalseToObject(object_tmp, "dst_pri");
            }
            cJSON_AddStringToObject(object_tmp, "dst_col", result);
            cJSON_AddStringToObject(object_tmp, "dst_desc", "");
            cJSON_AddTrueToObject(object_tmp, "status");

            cJSON_AddItemToObject(array_tmp, tables_tmp, object_tmp);
            //cJSON_AddItemToArray(array_tmp, object_tmp);
            result = strtok(NULL, ",");
            count++;
        }
    } else {
        char tables_tmp[64] = {0};
        sprintf(tables_tmp, "%llu", id + 1 + count);
        object_tmp = cJSON_CreateObject();
        if ((object_tmp == NULL)) {
            return NULL;
        }
        cJSON_AddStringToObject(object_tmp, "src_col", pri);
        cJSON_AddStringToObject(object_tmp, "src_desc", "");
        cJSON_AddTrueToObject(object_tmp, "src_pri");
        cJSON_AddTrueToObject(object_tmp, "dst_pri");
        cJSON_AddStringToObject(object_tmp, "dst_col", pri);
        cJSON_AddStringToObject(object_tmp, "dst_desc", "");
        cJSON_AddTrueToObject(object_tmp, "status");

        cJSON_AddItemToObject(array_tmp, tables_tmp, object_tmp);

        count++;
        sprintf(tables_tmp, "%llu", id + 1 + count);
        object_tmp = cJSON_CreateObject();
        if ((object_tmp == NULL)) {
            return NULL;
        }
        cJSON_AddStringToObject(object_tmp, "src_col", src);
        cJSON_AddStringToObject(object_tmp, "src_desc", "");
        cJSON_AddFalseToObject(object_tmp, "src_pri");
        cJSON_AddFalseToObject(object_tmp, "dst_pri");
        cJSON_AddStringToObject(object_tmp, "dst_col", src);
        cJSON_AddStringToObject(object_tmp, "dst_desc", "");
        cJSON_AddTrueToObject(object_tmp, "status");



        cJSON_AddItemToObject(array_tmp, tables_tmp, object_tmp);
    }
    return array_tmp;
}
/*******************************************************************************************
*功能:   info 处理函数
*参数:
*    tasks        策略信息
*    src_dst      内到外->外到内
*    返回值      分割好的cols json数据
*注释:
*******************************************************************************************/
static cJSON *dnsync_info_str(pdbsync_task tasks, bool src_dst)
{
    cJSON *object_tmp = NULL;
    object_tmp = cJSON_CreateObject();
    if ((object_tmp == NULL)) {
        return NULL;
    }
    cJSON_AddStringToObject(object_tmp, "sCharset", src_dst ? tasks->tdbcharset : tasks->sdbcharset);
    cJSON_AddStringToObject(object_tmp, "sDataBase", src_dst ? tasks->tdatabase : tasks->sdatabase);
    cJSON_AddStringToObject(object_tmp, "sDbType", src_dst ? tasks->tdbtype : tasks->sdbtype);
    cJSON_AddStringToObject(object_tmp, "sDbmsIp", src_dst ? tasks->tdbmsip : tasks->sdbmsip);
    cJSON_AddStringToObject(object_tmp, "sPassword", src_dst ? tasks->tpassword : tasks->spassword);
    cJSON_AddNumberToObject(object_tmp, "sPort", src_dst ? tasks->tport : tasks->sport);
    cJSON_AddStringToObject(object_tmp, "sUserName", src_dst ? tasks->tusername : tasks->susername);
    cJSON_AddStringToObject(object_tmp, "sOwner", src_dst ? tasks->towner : tasks->sowner);
    return object_tmp;
}
/*******************************************************************************************
*功能:   写策略信息
*参数:
*    taskcnt        当前策略数
*    bakfile        备份文件
*    TOTAL          标记策略信息还是策略总数(TRUE)
*    file           CFILEOP类数据
*    tasks          策略信息
*注释:
*******************************************************************************************/
static void dbsync_write_task_info_old_debug(uint32 taskcnt, pchar bakfile, bool TOTAL, CFILEOP &file, dbsync_time timer, pdbsync_task tasks = NULL)
{
    pchar SYSROOT[2] = {"MAIN", "TaskNum"};
    pchar TASKCFG = "Task";
    char tasktmp[64] = {0};
    char tmptable_tmp[64] = {0};
    pchar info_tmp = NULL;
    info_tmp = (char *)malloc(MAX_VALUE_LEN);
    if (info_tmp == NULL) {
        PRINT_ERR_HEAD;
        print_err("dbsync_tool dbsync_write_task_info_old malloc faild");
        return ;
    }
    cJSON *dst_tabs = NULL, *dst_cols = NULL, *all_tabs = NULL, *all_cols = NULL, *src_info = NULL, *dst_info = NULL;
    pchar data = NULL;

    if (TOTAL) {
        ADD_CH_INT(info_tmp, timer.chsyncday);
        file.WriteCfgFile(SYSROOT[0], "CKSyncDay", info_tmp);
        ADD_CH_STR(info_tmp, timer.sysnctimer);
        file.WriteCfgFile(SYSROOT[0], "Synctimer", info_tmp);

        ADD_CH_INT(info_tmp, timer.syncspe);
        file.WriteCfgFile(SYSROOT[0], "Syncspe", info_tmp);

        ADD_CH_INT(info_tmp, taskcnt);
        file.WriteCfgFile(SYSROOT[0], SYSROOT[1], info_tmp);
    } else {
        sprintf(tasktmp, "%s%d", TASKCFG, taskcnt);

        ADD_CH_STR(info_tmp, tasks->name);
        file.WriteCfgFile(tasktmp, "Name", info_tmp);

        char tmp[64] = {0};
        snprintf(tmp, sizeof(tmp) - 1, "\'%llu\'", tasks->id);
        file.WriteCfgFile(tasktmp, "ID", tmp);

        ADD_CH_INT(info_tmp, tasks->direction);
        file.WriteCfgFile(tasktmp, "DIRECTION", info_tmp);

        ADD_CH_INT(info_tmp, tasks->doublesided);
        file.WriteCfgFile(tasktmp, "DOUBLESIDED", info_tmp);

        sprintf(tmptable_tmp, "%llu_TMPTABLE", tasks->id);
        ADD_CH_INT(info_tmp, tasks->tmptable);
        file.WriteCfgFile(tasktmp, tmptable_tmp, info_tmp);//策略下发成功，关闭重建触发器

        ADD_CH_INT(info_tmp, tasks->enable);
        file.WriteCfgFile(tasktmp, "ENABLE", info_tmp); //1开启，0关闭

        ADD_CH_STR(info_tmp, tasks->sdbtype);
        file.WriteCfgFile(tasktmp, "SDBTYPE", info_tmp);
        ADD_CH_STR(info_tmp, tasks->sdbcharset);
        file.WriteCfgFile(tasktmp, "SCHARSET", info_tmp);
        ADD_CH_STR(info_tmp, tasks->sdatabase);
        file.WriteCfgFile(tasktmp, "SDATABASE", info_tmp);
        ADD_CH_STR(info_tmp, tasks->sdbmsip);
        file.WriteCfgFile(tasktmp, "SDBMSIP", info_tmp);
        ADD_CH_INT(info_tmp, tasks->sport);
        file.WriteCfgFile(tasktmp, "SPORT", info_tmp);
        ADD_CH_STR(info_tmp, tasks->susername);
        file.WriteCfgFile(tasktmp, "SUSERNAME", info_tmp);
        ADD_CH_STR(info_tmp, tasks->spassword);
        file.WriteCfgFile(tasktmp, "SPASSWORD", info_tmp);

        ADD_CH_STR(info_tmp, tasks->tdbtype);
        file.WriteCfgFile(tasktmp, "TDBTYPE", info_tmp);
        ADD_CH_STR(info_tmp, tasks->tdbcharset);
        file.WriteCfgFile(tasktmp, "TCHARSET", info_tmp);
        ADD_CH_STR(info_tmp, tasks->tdatabase);
        file.WriteCfgFile(tasktmp, "TDATABASE", info_tmp);
        ADD_CH_STR(info_tmp, tasks->tdbmsip);
        file.WriteCfgFile(tasktmp, "TDBMSIP", info_tmp);
        ADD_CH_INT(info_tmp, tasks->tport);
        file.WriteCfgFile(tasktmp, "TPORT", info_tmp);
        ADD_CH_STR(info_tmp, tasks->tusername);
        file.WriteCfgFile(tasktmp, "TUSERNAME", info_tmp);
        ADD_CH_STR(info_tmp, tasks->tpassword);
        file.WriteCfgFile(tasktmp, "TPASSWORD",  info_tmp);
        ADD_CH_INT(info_tmp, tasks->tables_num);
        file.WriteCfgFile(tasktmp, "TABLENUM", info_tmp);

        ADD_CH_STR(info_tmp, tasks->sowner);
        file.WriteCfgFile(tasktmp, "SOWNER", info_tmp);
        ADD_CH_STR(info_tmp, tasks->objalias);
        file.WriteCfgFile(tasktmp, "OBJALIAS",  info_tmp);
        ADD_CH_STR(info_tmp, tasks->towner);
        file.WriteCfgFile(tasktmp, "TOWNER", info_tmp);

        ADD_CH_STR(info_tmp, tasks->tempTableName);
        file.WriteCfgFile(tasktmp, "tempTableName", info_tmp);

        dst_tabs = cJSON_CreateObject();
        dst_cols =  cJSON_CreateObject();
        all_tabs =  cJSON_CreateArray();
        all_cols =  cJSON_CreateObject();
        if ((dst_tabs == NULL) || (dst_cols == NULL) || (all_tabs == NULL) || (all_cols == NULL)) {
            PRINT_ERR_HEAD;
            print_err("dbsync_tool dbsync_write_task_info_old cJSON_CreateArray failse");
            return ;
        }

        for (int i = 0; i < tasks->tables_num; i++) {
            char tables_tmp[64] = {0};
            sprintf(tables_tmp, "%llu_TABLE%d", tasks->id, i);

            cJSON *root = NULL, *tmp = NULL;
            char keytmp[255] = {0};

            root =  cJSON_CreateObject();
            tmp =  cJSON_CreateObject();
            if ((root == NULL) || (tmp == NULL)) {
                PRINT_ERR_HEAD;
                print_err("dbsync_tool dbsync_write_task_info_old cJSON_CreateObject failse");
                return ;
            }
            cJSON_AddStringToObject(root, "sTableName", tasks->table[i].SrcTblName);
            cJSON_AddStringToObject(root, "tTableName", tasks->table[i].DstTblName);
            cJSON_AddNumberToObject(root, "rebuildTmpTb", atoi(tasks->table[i].CKTmpTbl));
            cJSON_AddNumberToObject(root, "delTrigger", atoi(tasks->table[i].CKTrigger));
            cJSON_AddNumberToObject(root, "tableCopy", atoi(tasks->table[i].CKCopy));
            cJSON_AddStringToObject(root, "upsert", tasks->table[i].CKUpsert);
            cJSON_AddStringToObject(root, "filter", tasks->table[i].Filter);
            cJSON_AddNumberToObject(root, "synInsert", atoi(tasks->table[i].CKInsert));
            cJSON_AddNumberToObject(root, "synUpdate", atoi(tasks->table[i].CKUpdate));
            cJSON_AddNumberToObject(root, "synDelete", atoi(tasks->table[i].CKDelete));
            cJSON_AddStringToObject(root, "sKeyField", tasks->table[i].SrcKey);
            cJSON_AddStringToObject(root, "tKeyField", tasks->table[i].DstKey);
            cJSON_AddStringToObject(root, "sFieldList", tasks->table[i].SrcField);
            cJSON_AddStringToObject(root, "tFieldList", tasks->table[i].DstField);

            //dst_tabs
            {
                char tables_tmp[64] = {0};
                sprintf(tables_tmp, "%llu", tasks->id + 1);//id1
                cJSON_AddStringToObject(dst_tabs, tables_tmp, tasks->table[i].DstTblName);
            }


            //all_tabs
            {
                cJSON *array_tmp = NULL;
                array_tmp = cJSON_CreateArray();
                if ((array_tmp == NULL)) {
                    PRINT_ERR_HEAD;
                    print_err("dbsync_tool dbsync_write_task_info_old cJSON_CreateObject failse");
                    return ;
                }
                char tables_tmp[64] = {0};
                sprintf(tables_tmp, "%llu", tasks->id + 1);//id1
                if (atoi(tasks->table[i].CKInsert) == 1)
                    cJSON_AddItemToArray(array_tmp, cJSON_CreateString("insert"));
                if (atoi(tasks->table[i].CKUpdate) == 1)
                    cJSON_AddItemToArray(array_tmp, cJSON_CreateString("update"));
                if (atoi(tasks->table[i].CKDelete) == 1)
                    cJSON_AddItemToArray(array_tmp, cJSON_CreateString("del"));
                cJSON_AddStringToObject(tmp, "src_tab", tasks->table[i].SrcTblName);
                cJSON_AddItemToObject(tmp, "meds", array_tmp);
                cJSON_AddStringToObject(tmp, "filter_str", tasks->table[i].Filter);
                if (atoi(tasks->table[i].CKCopy) == 0) {
                    cJSON_AddFalseToObject(tmp, "tab_copy");
                } else {
                    cJSON_AddTrueToObject(tmp, "tab_copy");
                }
                if (tasks->enable == 0) {
                    cJSON_AddFalseToObject(tmp, "status");
                } else {
                    cJSON_AddTrueToObject(tmp, "status");
                }
                if (atoi(tasks->table[i].CKTrigger) == 0) {
                    cJSON_AddFalseToObject(tmp, "is_refresh_trigger");
                } else {
                    cJSON_AddTrueToObject(tmp, "is_refresh_trigger");
                }
                if (atoi(tasks->table[i].CKTmpTbl) == 0) {
                    cJSON_AddFalseToObject(tmp, "is_rebuild_tmptab");
                } else {
                    cJSON_AddTrueToObject(tmp, "is_rebuild_tmptab");
                }
                cJSON_AddStringToObject(tmp, "dst_tab", tasks->table[i].DstTblName);
                cJSON_AddStringToObject(tmp, "tab_id", tables_tmp);//id1
                cJSON_AddItemToArray(all_tabs, tmp);
            }
            //dst_cols
            {
                cJSON *array_tmp = NULL;
                array_tmp = dnsync_tok_str(tasks->table[i].DstField, tasks->table[i].DstKey, tasks->id + 2);//id2
                if ((array_tmp != NULL)) {
                    sprintf(keytmp, "%s_dst_cols", tasks->table[i].DstTblName);
                    cJSON_AddItemToObject(dst_cols, keytmp, array_tmp);
                }
            }
            //all_cols
            {
                cJSON *array_tmp = NULL;
                array_tmp = dnsync_dealcols_str(tasks->table[i].SrcField, tasks->table[i].SrcKey, tasks->id + 2);//id2
                if ((array_tmp != NULL)) {
                    cJSON_AddItemToObject(all_cols, tasks->table[i].SrcTblName, array_tmp);
                }
            }
            data = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
            if (data != NULL) {
                ADD_CH_STR(info_tmp, data);
                file.WriteCfgFile(tasktmp, tables_tmp,  info_tmp);
                free(data);
                data = NULL;
            }
        }
        //src_info
        {
            src_info = dnsync_info_str(tasks, tasks->direction);
        }
        //dst_info
        {
            dst_info = dnsync_info_str(tasks, !(tasks->direction));
        }
        ADD_CH_INT(info_tmp, tasks->direction);
        file.WriteCfgFile(tasktmp, "area",  info_tmp);
        ADD_CH_STR(info_tmp, "1");
        file.WriteCfgFile(tasktmp, "manual",  info_tmp);
        ADD_CH_STR(info_tmp, "0");;
        file.WriteCfgFile(tasktmp, "upsert",  info_tmp);
        ADD_CH_INT(info_tmp, tasks->enable);;
        file.WriteCfgFile(tasktmp, "status",  info_tmp);

        data = cJSON_PrintUnformatted(dst_tabs);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "dst_tabs",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(dst_tabs);

        data = cJSON_PrintUnformatted(dst_cols);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "dst_cols",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(dst_cols);

        data = cJSON_PrintUnformatted(all_tabs);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "all_tabs",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(all_tabs);

        data = cJSON_PrintUnformatted(all_cols);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "all_cols",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(all_cols);

        data = cJSON_PrintUnformatted(src_info);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "src_info",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(src_info);

        data = cJSON_PrintUnformatted(dst_info);
        if (data != NULL) {
            ADD_CH_STR(info_tmp, data);
            file.WriteCfgFile(tasktmp, "dst_info",  info_tmp);
            free(data);
            data = NULL;
        }
        cJSON_Delete(dst_info);

        file.WriteCfgFile(tasktmp, "dst_desc",  "\'{}\'");
    }
    free(info_tmp);
}
/*******************************************************************************************
*功能:   备份策略信息
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    bakfile        备份策略成功信息文件
*    返回值          0成功 -1失败
*注释:
*******************************************************************************************/
int32 dbsync_back_task_info_old_debug(int32 taskcnt, pdbsync_task tasks, dbsync_time timer, pchar bakfile)
{
    uint32 count = 0;
    CFILEOP file;
    if (file.CreateNewFile(bakfile) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("dbsync_back_task_info CFG(%s) ERROR!!", bakfile);
        return -1;
    }

    for (int i = 0; i < taskcnt; i++) {

        dbsync_write_task_info_old_debug(count, bakfile, false, file, timer, tasks + i);
        count++;
    }
    if (count != 0) {
        dbsync_write_task_info_old_debug(count, bakfile, true, file, timer);
    }
    file.WriteFileEnd();
    return 0;
}