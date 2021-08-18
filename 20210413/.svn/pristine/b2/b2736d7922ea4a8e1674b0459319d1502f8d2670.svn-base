/*******************************************************************************************
*文件:    fileclient.cpp
*描述:
*作者:    张昆鹏
*日期:    2016-12-02
*修改:    创建文件                                          ------>     2016-12-02
*         修改bug和不规范代码                                ------>     2016-12-27
*         修改用户数量限制处理
*         去除向SFILE表写入创建文件夹记录
*         修改上传移走文件的处理方式                           ------>     2017-02-16
*         增加对路径的判断处理
*         修改记录本地日志时bug,
*         修改“去除向SFILE表写入创建文件夹记录”的方式            ------>     2017-02-20
*         添加验证用户名功能
*         修改获取文件大小方式                                ------>     2017-02-23
*         修改CreateProcess函数逻辑                         ------>     2017-02-27
*         修改读取文件列表获取文件信息方式                      ------>     2017-03-18
*         增加UDP和TCP与服务器通信模式                        ------>     2017-07-29
*         增加文件传输校验功能                                ------>     2017-08-01
*         增加并发文件功能                                   ------>     2017-09-08
*         增加保留指定深度目录功能                             ------>     2017-10-21
*         增加从数据库领取文件清单功能                          ------>     2017-11-13
*         修改数据库处理bug和文件判断bug                       ------>     2017-11-16
*         新增长文件名处理功能                                ------>     2017-12-06
*         修改因并发引起的文件传输bug                          ------>     2017-12-14
*         修改长文件名处理逻辑                                ------>     2018-01-05
*
*作者：    宋宇
*日期：    2018-08-15
*修改：    增加增量传输功能                                   ------>     2018-08-15
*          增加服务器间文件同步功能                           ------>     2018-09-10
*          增加关键字过滤功能                                ------>     2018-11-03
*          增加编码格式转换函数                              ------>     2018-11-06
*          增加文件同步中的多线程功能                          ------>     2018-11-16
*          修改bug，精简代码                                ------>     2018-11-21
*          增加创建多级目录函数                              ------>     2018-12-07
*          解决增量传输时对于文件夹的创建的bug（目的端为windows时）
*          增加id表字段,增大文件大小字段上限                   ------>     2018-12-10
*          添加增量传输时写文件夹信息表                        ------>     2018-12-11
*          优化函数执行顺序                                 ------>     2018-12-12
*          增加TranFile函数及有关函数的错误处理
*          修改由于空指针引起的bug                           ------>     2018-12-18
*          去除PutDirParent函数中空指针处理，在外部判断         ------>     2018-12-28
*          简化PutDirParent函数中的逻辑
*          增加文件同步后与目的端的校验                        ------>    2019-02-18
*          增加编译开关，在V6和V8版本延迟时间增加8小时         ------>    2019-06-06
*          增加无后缀类型文件过滤功能                          ------>    2019-06-25
*          增加挂载失败日志和过滤日志策略名                    ------>    2019-06-28
*          增加utf8文件内容过滤                             ------>    2021-04-11
*******************************************************************************************/
#include "fileclient.h"
#include "stringex.h"

static const pchar  HAVEKEYWORD_GBK = "禁止通过的关键字(私有文件交换)";   //build时会将该cpp转码为gbk

/*******************************************************************************************
*功能:       读取配置文件，获取共用信息
*参数:       config                       ---->  配置文件
*            返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool ReadConfig(pchar config)
{
    CSYSCFG fg;
    bool bret = false;

    if (fg.open(config, true, true)) {

        pchar tmp;
        int32 k;
        cfgmsg.port = DEF_PORT;
        bret = true;
        if (bret && ((tmp = fg.getitem("SYS", "MODEL")) != NULL)) strcpy(cfgmsg.model, tmp);
        else bret = false;

        if (strcmp(cfgmsg.model, "TRAN") == 0) { //songyu start
            bret = true;
            //修改用户数量限制
            if (bret && (bret = fg.getitem("SYS", "DIRNUM", k))) {
                if (k > MAX_DIRNUM) {
                    cfgmsg.dirnum = MAX_DIRNUM;
                    PRINT_INFO_HEAD;
                    print_info("CFG The maximum number of users is only %d", MAX_DIRNUM);
                } else {
                    cfgmsg.dirnum = k;
                }
            }

            strcpy(cfgmsg.tmppath, "/tmp");
            strcpy(cfgmsg.logpath, "/tmp");
            strcpy(cfgmsg.dbpath, "/var/lib/sqlite/");
            mkdir(cfgmsg.dbpath, S_IRWXO | S_IRWXG | S_IRWXU);

        } else {    //songyu end
            if ((bret = fg.getitem("SYS", "PORT", k))) cfgmsg.port = k;
            else cfgmsg.port = DEF_PORT;
            //修改用户数量限制
            if (bret && (bret = fg.getitem("SYS", "DIRNUM", k))) {
                if (k > MAX_DIRNUM) {
                    cfgmsg.dirnum = MAX_DIRNUM;
                    PRINT_INFO_HEAD;
                    print_info("CFG The maximum number of users is only %d", MAX_DIRNUM);
                } else {
                    cfgmsg.dirnum = k;
                }
            }

            if (bret && ((tmp = fg.getitem("SYS", "LOGPATH")) != NULL)) strcpy(cfgmsg.logpath, tmp);
            else bret = false;
            if (bret && ((tmp = fg.getitem("SYS", "TMPPATH")) != NULL)) strcpy(cfgmsg.tmppath, tmp);
            else bret = false;
            // songyu start
            if (bret && ((tmp = fg.getitem("SYS", "DBPATH")) == NULL)) {
                tmp = fg.getitem("SYS", "TMPPATH");
                strcpy(cfgmsg.dbpath, tmp);
                make_filepath(tmp, "DBfile", cfgmsg.dbpath);
            } else if (bret && ((tmp = fg.getitem("SYS", "DBPATH")) != NULL)) {
                strcpy(cfgmsg.dbpath, tmp);
            } else {
                bret = false;
            }
            // songyu end

            //增加配置文件中路径判断
            if (bret) {
                mkdir(cfgmsg.logpath, S_IRWXO | S_IRWXG | S_IRWXU);
                mkdir(cfgmsg.tmppath, S_IRWXO | S_IRWXG | S_IRWXU);
                mkdir(cfgmsg.dbpath, S_IRWXO | S_IRWXG | S_IRWXU);
                if ((!accesspath(cfgmsg.tmppath)) || (!accesspath(cfgmsg.logpath)) || (!accesspath(cfgmsg.dbpath))) bret = false;   //songyu add
                if ((strcmp(cfgmsg.model, "PUT") != 0) && (strcmp(cfgmsg.model, "GET") != 0)) bret = false;
            }

            PRINT_DBG_HEAD;
            print_dbg("CFG Config dirnum=%d, port=%d, logpath=%s, tmppath=%s, model=%s", cfgmsg.dirnum,
                      cfgmsg.port, cfgmsg.logpath, cfgmsg.tmppath, cfgmsg.model);
        }

    }
    if (!bret) {
        PRINT_ERR_HEAD;
        print_err("CFG Config failed!");
    }

    fg.close();
    return bret;
}

/*******************************************************************************************
*功能:       读取配置文件，获取用户任务信息
*参数:       dirmsg                     ---->  存储任务信息
*            config                     ---->  配置文件
*            返回值                     ---->  false失败
*注释:
*******************************************************************************************/
bool ReadConfig_(DIRMSG *dirmsg, pchar config)
{
    CSYSCFG fg;
    bool bret = true;

    if (fg.open(config, true, true)) {

        pchar tmp = NULL;
        CHAR dirkey[MAX_USERLEN] = {0};
        for (int32 i = 0; i < cfgmsg.dirnum; i++) {

            if (strcmp(cfgmsg.model, "TRAN") == 0) { //songyu start
                sprintf(dirkey, "DIR%d", i);
                dirmsg[i].id = i;
                int32 k;

                dirmsg[i].sync = 3;                                                 //默认3秒一个周期
                fg.getitem(dirkey, "SYNC", dirmsg[i].sync);

                fg.getitem(dirkey, "AFTER", dirmsg[i].deadline);
                if (dirmsg[i].deadline <= 0) dirmsg[i].deadline = 1;                 //时间期限默认最小为1秒
#ifdef UTC0
                dirmsg[i].deadline += 8 * 60 * 60;
#endif
                dirmsg[i].mode = MODE_TCP;                                      //获取传输方式，默认为MODE_TCP模式

                fg.getitem(dirkey, "PARNUM", k);                                     //获取并行文件数，默认为0
                if (k <= 0) {
                    dirmsg[i].parnum = 1;
                } else if (k > PARMAXNUM) {
                    dirmsg[i].parnum = PARMAXNUM;
                } else {
                    dirmsg[i].parnum = k;
                }


                if (fg.getitem(dirkey, "PORT", k)) dirmsg[i].port = k;               //端口号
                else dirmsg[i].port = cfgmsg.port;
                if (fg.getitem(dirkey, "PORT2", k)) dirmsg[i].port2 = k;               //端口号2
                else dirmsg[i].port2 = cfgmsg.port;

                if (fg.getitem(dirkey, "INSVRPORT", k)) dirmsg[i].intport = k;               //端口号
                else dirmsg[i].port = cfgmsg.port;
                if (fg.getitem(dirkey, "OUTSVRPORT", k)) dirmsg[i].outport2 = k;               //端口号2
                else dirmsg[i].port2 = cfgmsg.port;

                k = 0;
                dirmsg[i].iflog = false ;
                if (cfgmsg.blogswitch) {
                    fg.getitem(dirkey, "IFLOG", k);
                    if (k != 0) dirmsg[i].iflog = true;
                } else {
                    dirmsg[i].iflog = false;
                }

                fg.getitem(dirkey, "Area", k);
                dirmsg[i].area = k;
                if ((dirmsg[i].area != 0) && (dirmsg[i].area != 1)) {
                    PRINT_ERR_HEAD;
                    print_err("Area is errno !");
                    return false;
                }

                if ((fg.getitem(dirkey, "CKFILTERFILES", dirmsg[i].ckfilterfiles)) &&
                    ((tmp = fg.getitem(dirkey, "FILTERFILES")) != NULL)) {
                    strcpy(dirmsg[i].filterfiles, tmp);
                    //防止配置文件中过滤规则后未加'/'
                    if (strlen(dirmsg[i].filterfiles) != 0)  strcat(dirmsg[i].filterfiles, ",");
                    else dirmsg[i].ckfilterfiles = 0;
                } else {
                    dirmsg[i].ckfilterfiles = 0;
                }

                if ((tmp = fg.getitem(dirkey, "TaskName")) != NULL) {
                    strcpy(dirmsg[i].taskname, tmp);
                    PRINT_DBG_HEAD;
                    print_dbg("taskname = %s", dirmsg[i].taskname);
                } else {
                    PRINT_ERR_HEAD;
                    print_err("TaskName is NULL");
                    return false;
                }


                //zkp 获取优先级参数
                k = 0;
                fg.getitem(dirkey, "PRIORITY", k);
                if ((k < 0) || (k > 4)) {
                    dirmsg[i].priority = 0;
                } else {
                    dirmsg[i].priority = k;          //默认优先级0
                }

                //增加保留指定目录深度功能
                dirmsg[i].retdir = 0;               //默认为0是遵循处理本地文件逻辑

                //增加根据数据库方式领取传送文件路径
                fg.getitem(dirkey, "SQLMODE", k);
                dirmsg[i].sqlmode = 0;               //默认为0不开启

                if (bret && ((tmp = fg.getitem(dirkey, "TOIP")) != NULL)) strcpy(dirmsg[i].ip, tmp);
                else bret = false;
                if (bret && ((tmp = fg.getitem(dirkey, "TOIP2")) != NULL)) strcpy(dirmsg[i].ip2, tmp);
                else bret = false;

                if (bret && ((tmp = fg.getitem(dirkey, "INSVRIP")) != NULL)) strcpy(dirmsg[i].intip, tmp);
                else bret = false;
                if (bret && ((tmp = fg.getitem(dirkey, "OUTSVRIP")) != NULL)) strcpy(dirmsg[i].outip, tmp);
                else bret = false;

                strcpy(dirmsg[i].dirpath, "/tmp");    //must have
                if (bret && ((tmp = fg.getitem(dirkey, "USER")) != NULL)) strcpy(dirmsg[i].user, tmp);
                else bret = false;

                //临时文件名
                strcpy(dirmsg[i].tmpfile, ".tmp");
                if (bret) if (!accesspath(dirmsg[i].dirpath)) bret = false;

                fg.getitem(dirkey, "OVERTO",  dirmsg[i].dellcl);
                PRINT_DBG_HEAD;
                print_dbg("CFG config dir=%s, sync=%d, iflog=%d, deadline=%d, ip=%s, ip2=%s, dirpath=%s, dellcl=%d",
                          dirkey, dirmsg[i].sync, dirmsg[i].iflog, dirmsg[i].deadline, dirmsg[i].ip, dirmsg[i].ip2,
                          dirmsg[i].dirpath, dirmsg[i].dellcl);
                if (!bret) break;

            } else {

                sprintf(dirkey, "DIR%d", i);
                dirmsg[i].id = i;
                int32 k;

                dirmsg[i].sync = 3;                                                 //默认3秒一个周期
                fg.getitem(dirkey, "SYNC", dirmsg[i].sync);

                dirmsg[i].deadline = 1;
                fg.getitem(dirkey, "AFTER", dirmsg[i].deadline);
                if (dirmsg[i].deadline <= 0) dirmsg[i].deadline = 1;                 //时间期限默认最小为1秒

                if (fg.getitem(dirkey, "MODE", k)) dirmsg[i].mode = k;               //获取传输方式，默认为MODE_SUTCP模式
                else dirmsg[i].mode = MODE_SUTCP;

                k = 0;
                fg.getitem(dirkey, "PARNUM", k);                                     //获取并行文件数，默认为0
                if (k < 0) {
                    dirmsg[i].parnum = 1;
                } else if (k > PARMAXNUM) {
                    dirmsg[i].parnum = PARMAXNUM;
                } else {
                    dirmsg[i].parnum = k;
                }

                if (dirmsg[i].mode == MODE_UDP) {
                    if (fg.getitem(dirkey, "SENDDLY", k)) dirmsg[i].senddly = k;     //读取延时设置
                    else dirmsg[i].senddly = 50;                                     //默认50
                    if (fg.getitem(dirkey, "SENDNUM", k)) dirmsg[i].sendnum = k;     //读取重复发包次数
                    else dirmsg[i].sendnum = 2;                                      //默认2
                }
                if (fg.getitem(dirkey, "SENDCHK", k)) dirmsg[i].sendchk = k;         //文件校验控制
                else dirmsg[i].sendchk = 0;                                          //默认不检测

                if (fg.getitem(dirkey, "PORT", k)) dirmsg[i].port = k;               //端口号
                else dirmsg[i].port = cfgmsg.port;

                k = 0;
                fg.getitem(dirkey, "IFLOG", k);
                if (k == 0) dirmsg[i].iflog = false;
                else dirmsg[i].iflog = true;

                if ((fg.getitem(dirkey, "CKFILTERFILES", dirmsg[i].ckfilterfiles)) &&
                    ((tmp = fg.getitem(dirkey, "FILTERFILES")) != NULL)) {
                    strcpy(dirmsg[i].filterfiles, tmp);
                    //防止配置文件中过滤规则后未加'/'
                    if (strlen(dirmsg[i].filterfiles) != 0)  strcat(dirmsg[i].filterfiles, _SYSSUFFIXFLAG);
                    else dirmsg[i].ckfilterfiles = 0;
                } else {
                    dirmsg[i].ckfilterfiles = 0;
                }

                //zkp 获取优先级参数
                k = 0;
                fg.getitem(dirkey, "PRIORITY", k);
                dirmsg[i].priority = k;               //默认优先级0

                //增加保留指定目录深度功能
                k = 0;
                fg.getitem(dirkey, "RETDIR", k);
                dirmsg[i].retdir = k;               //默认为0是遵循处理本地文件逻辑

                //增加根据数据库方式领取传送文件路径
                k = 0;
                fg.getitem(dirkey, "SQLMODE", k);
                dirmsg[i].sqlmode = k;               //默认为0不开启
                if (dirmsg[i].sqlmode == 1) {
                    if (bret && ((tmp = fg.getitem(dirkey, "SQLADDR")) != NULL)) strcpy(dirmsg[i].sqladdr, tmp);
                    else bret = false;
                    if (bret && ((tmp = fg.getitem(dirkey, "SQLNAME")) != NULL)) strcpy(dirmsg[i].sqlname, tmp);
                    else bret = false;
                    if (bret && ((tmp = fg.getitem(dirkey, "SQLPWD")) != NULL)) strcpy(dirmsg[i].sqlpwd, tmp);
                    else bret = false;
                    if (bret && ((tmp = fg.getitem(dirkey, "SQLDB")) != NULL)) strcpy(dirmsg[i].sqldb, tmp);
                    else bret = false;
                    k = 0;
                    fg.getitem(dirkey, "SQLPORT", k);
                    dirmsg[i].sqlport = k;               //默认为0不开启
                }

                if (bret && ((tmp = fg.getitem(dirkey, "TOIP")) != NULL)) strcpy(dirmsg[i].ip, tmp);
                else bret = false;

                if (bret && ((tmp = fg.getitem(dirkey, "DIRPATH")) != NULL)) strcpy(dirmsg[i].dirpath, tmp);
                else bret = false;
                if (bret && ((tmp = fg.getitem(dirkey, "USER")) != NULL)) strcpy(dirmsg[i].user, tmp);
                else bret = false;

                //临时文件名
                if (bret && ((tmp = fg.getitem(dirkey, "TMPFILE")) != NULL)) strcpy(dirmsg[i].tmpfile, tmp);
                if (bret) if (!accesspath(dirmsg[i].dirpath)) bret = false;

                if (bret && (strcmp(cfgmsg.model, "PUT") == 0)) {

                    if (bret && (fg.getitem(dirkey, "OVERTO",  dirmsg[i].dellcl))
                        && ((tmp = fg.getitem(dirkey, "BAKPATH")) != NULL)) strcpy(dirmsg[i].bakpath, tmp);
                    else bret = false;
                    if (bret) {
                        mkdir(dirmsg[i].bakpath, S_IRWXO | S_IRWXG | S_IRWXU);
                        if (!accesspath(dirmsg[i].bakpath)) bret = false;
                    }
                }

                if ((strcmp(cfgmsg.logpath, dirmsg[i].dirpath) == 0) || (strcmp(cfgmsg.tmppath, dirmsg[i].dirpath) == 0)) {
                    PRINT_ERR_HEAD;
                    print_err("CFG config Path conflict!");
                }
                PRINT_DBG_HEAD;
                print_dbg("CFG config dir=%s, sync=%d, iflog=%d, deadline=%d, ip=%s, dirpath=%s, dellcl=%d, bakpath=%s",
                          dirkey, dirmsg[i].sync, dirmsg[i].iflog, dirmsg[i].deadline, dirmsg[i].ip,
                          dirmsg[i].dirpath, dirmsg[i].dellcl, dirmsg[i].bakpath);
                if (!bret) break;
            }
        }
    }
    if (!bret) {
        PRINT_ERR_HEAD;
        print_err("CFG config failed!");
    }

    fg.close();
    return bret;
}

#define SUOPEN(dirmsg) {                                                                  \
     if (!dirmsg->cli_p.suopen(dirmsg->ip, dirmsg->port, SOCKET_CLIENT, SOCKET_TCP)){     \
         RecordFileLog(dirmsg,"Socket","Connect To Server",false);                        \
         return false;                                                                    \
     }                                                                                    \
}
static const pchar  SUCCESS = "success";
static const pchar  FAIL = "failed";
/*******************************************************************************************
*功能:        建立客户端连接，发送信息，接收信息
*参数:        dirmsg                       ---->  任务信息
*             msg                          ---->  存储信息
*             recvmsg                      ---->  应回复信息，NULL无回复信息
*             返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool SuSendRecv(DIRMSG *dirmsg, pchar msg, pchar recvmsg, CSUSOCKET *tmp)
{
    if (is_strempty(msg)) return false;
    PRINT_DBG_HEAD;
    print_dbg("Send msg = %s", msg);

    if (dirmsg->mode == MODE_UDP) {
        dirmsg->cli_p.suwriteq(msg, strlen(msg));
        return true;
    } else {

        PRINT_DBG_HEAD;
        print_dbg("Send ip:port = %s:%d", dirmsg->ip, dirmsg->port);

        if (tmp == NULL) {
            SUOPEN(dirmsg);
            dirmsg->cli_p.settimeout(TIMEOUT);
            int32 len = dirmsg->cli_p.writesocket(msg, strlen(msg));
            if (len != strlen(msg)) {
                PRINT_ERR_HEAD;
                print_err("Send msg(%s) failed!", msg);
            }
            if (recvmsg != NULL) {

                CHAR recv[MAX_MSGSIZE] = {0};
                dirmsg->cli_p.readsocket(recv, sizeof(recv));
                PRINT_DBG_HEAD;
                print_dbg("Recv msg = %s", recv);
                if (strcmp(recv, recvmsg) != 0) return false;
            }
        } else {

            if (!tmp->suopen(dirmsg->ip, dirmsg->port, SOCKET_CLIENT, SOCKET_TCP)) {
                RecordFileLog(dirmsg, "Socket", "Connect To Server", false);
                return false;
            }

            tmp->settimeout(TIMEOUT);
            int32 len = tmp->writesocket(msg, strlen(msg));
            if (len != strlen(msg)) {
                PRINT_ERR_HEAD;
                print_err("Send msg(%s) failed!", msg);
            }
            if (recvmsg != NULL) {

                CHAR recv[MAX_MSGSIZE] = {0};
                tmp->readsocket(recv, sizeof(recv));
                PRINT_DBG_HEAD;
                print_dbg("Recv msg = %s", recv);
                if (strcmp(recv, recvmsg) != 0) return false;
            }
        }
        return true;
    }
}

//并发
typedef struct PARTASK {
    int32 id;                           //任务号
    volatile int32 state;               //并发状态，0未使用，1使用中
    CHAR taskpath[_FILEPATHMAX];
    CHAR filepath[_FILEPATHMAX];
    CHAR bakpath[_FILEPATHMAX];
    CHAR guid[100];
} PARTASK;
PARTASK  partask[PARMAXNUM];
DIRMSG dirmsg[MAX_DIRNUM];
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
/*******************************************************************************************
*功能:       调用上传下载函数
*参数:       param                       ---->  任务信息
*            返回值                      ---->  NULL结束
*注释:
*******************************************************************************************/
void *ParFile(void *param)
{
    int64 k = (int64)param;
    PRINT_DBG_HEAD;
    print_dbg("ParFile start task(%d) state=%d, partask(%lld) taskpath=%s, filepath=%s, bakpath=%s", partask[k].id, partask[k].state, k,
              partask[k].taskpath, partask[k].filepath, partask[k].bakpath);
    //资源自动回收
    pthread_setself("put_down_th");
    int32 filter = 0;
    bool bret = false;
    if (dirmsg[partask[k].id].sqlmode == 1) {
#ifndef __CYGWIN__
        CSYSDB db;
        db.opendb(dirmsg[partask[k].id].sqladdr, dirmsg[partask[k].id].sqlport, dirmsg[partask[k].id].sqlname, dirmsg[partask[k].id].sqlpwd, dirmsg[partask[k].id].sqldb, NULL);
        CHAR sqlcmd[MAX_MSGSIZE] = {0};
        sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstarttime=NOW(), etstatus=2 WHERE ettaskid='%s'", partask[k].guid);
        db.runsql(sqlcmd, NULL);

        SYSDBSQL tmpsql;
        tmpsql.sql = &db;
        strcpy(tmpsql.guid, partask[k].guid);
        bret = PutFile(&dirmsg[partask[k].id], partask[k].taskpath, partask[k].filepath, &filter, &tmpsql);
        if (!bret) {
            sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstatus=99, etmemo='Put file failed' WHERE ettaskid='%s'", partask[k].guid);
            db.runsql(sqlcmd, NULL);
        }
        db.closedb();
#endif
    } else {
        bret = PutFile(&dirmsg[partask[k].id], partask[k].taskpath, partask[k].filepath, &filter);
        PRINT_DBG_HEAD;
        print_dbg("Send file finish(%s)", (bret ? SUCCESS : FAIL));
    }

    if (bret) {                 //发送文件
        if ((dirmsg[partask[k].id].dellcl == DELALL) || (dirmsg[partask[k].id].dellcl == DELSAVE)) {
            if (filter == 1) {
                PRINT_ERR_HEAD;
                print_err("PutFile %s failed, file is filter!", partask[k].filepath);
                rename(partask[k].filepath, partask[k].bakpath);
            } else {
                remove(partask[k].filepath);
            }
        } else if ((dirmsg[partask[k].id].dellcl == MVALL) || (dirmsg[partask[k].id].dellcl == MVSAVE)) {
            rename(partask[k].filepath, partask[k].bakpath);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("PutFile %s failed!", partask[k].filepath);
    }
    PRINT_DBG_HEAD;
    print_dbg("ParFile end task(%d) partask(%lld) taskpath=%s, filepath=%s", partask[k].id, k, partask[k].taskpath, partask[k].filepath);
    pthread_mutex_lock(&mut);
    memset(&partask[k], 0, sizeof(PARTASK));
    pthread_mutex_unlock(&mut);
    return NULL;
}

/*******************************************************************************************
*功能:        并行传输文件
*参数:        dirmsg                       ---->  任务信息
*             remotepath                   ---->  任务账号
*             localpath                    ---->  上传文件路径
*             bakpath                      ---->  备份路径
*             返回值                       ---->  true 上传文件  false不上传
*注释:
*******************************************************************************************/
bool PutFile_(DIRMSG *dirmsg, pchar remotepath, pchar localpath, pchar bakpath, pchar guid = NULL)
{
    int32 i = 0;
    while (1) {

        for (int j = 0; j < dirmsg->parnum; ++j) {
            if (strcmp(partask[j].filepath, localpath) == 0) {

                PRINT_DBG_HEAD;
                print_dbg("Par file(%s) is transferring", localpath);
                return false;
            }
        }

        bool bret = false;
        pthread_mutex_lock(&mut);
        for (i = 0; i < dirmsg->parnum; ++i) {
            if (partask[i].state == 0) {

                partask[i].state = 1;
                partask[i].id = dirmsg->id;
                strcpy(partask[i].taskpath, remotepath);
                strcpy(partask[i].filepath, localpath);
                strcpy(partask[i].bakpath, bakpath);
                if (guid != NULL)strcpy(partask[i].guid, guid);

                PRINT_DBG_HEAD;
                print_dbg("Par task(%d) state=%d, filepath=%s, localpath=%s, taskpath=%s, remotepath=%s, bakpath=%s, bakpath=%s", i, partask[i].state, partask[i].filepath,
                          localpath, partask[i].taskpath, remotepath, partask[i].bakpath,  bakpath);

                pthread_t tid;
                if (pthread_create(&tid, NULL, ParFile, (void *)i) != 0) {

                    PRINT_ERR_HEAD;
                    print_err("Par file failed(%s)!", strerror(errno));
                    memset(&partask[i], 0, sizeof(PARTASK));

                } else {

                    // while (ESRCH == pthread_kill(tid, 0))   usleep(1);       //是否运行
                    PRINT_DBG_HEAD;
                    print_dbg("Par file %d Rrunning...", tid);
                    bret = true;
                }
                if (bret) break;
            }
        }
        pthread_mutex_unlock(&mut);
        if (bret) break;
        usleep(100);
    }
    return true;
}


/*******************************************************************************************
*功能:        发送文件
*参数:        dirmsg                       ---->  任务信息
*             remotepath                   ---->  任务账号
*             filename                     ---->  上传文件路径
*             bakpath                      ---->  备份路径
*             返回值                       ---->  false 失败
*注释:
*******************************************************************************************/
bool PutFileX(DIRMSG *dirmsg, pchar remotepath, pchar filename, pchar bakpath)
{
    bool bret = true;
    time_t nowtime = time(NULL);
    struct stat filetime;
    stat(filename, &filetime);
    CHAR tmpname[_FILENAMEMAX] = {0};
    split_filepath(filename, NULL, tmpname);
    if ((difftime(nowtime, filetime.st_mtime) >= dirmsg->deadline)
        || (difftime(filetime.st_mtime, nowtime) >= dirmsg->deadline)) {

        //songyu start
        if ((dirmsg->dellcl == SAMEFILE)
            && SelectData(DBCOMMONFILE, filename, filetime.st_mtime, filetime.st_size, dirmsg->user, dirmsg->db)) {      //表中此条数据存在
            return bret;
        }
        //songyu end

        CHAR chcmd[_FILEPATHMAX] = {0};
        make_filepath(bakpath, tmpname, chcmd);//移走文件
        if (dirmsg->parnum > 0) {
            PutFile_(dirmsg, remotepath, filename, chcmd);
        } else {
            int32 filter = 0;
            if (PutFile(dirmsg, remotepath, filename, &filter)) {                 //发送文件

                if ((dirmsg->dellcl == DELALL) || (dirmsg->dellcl == DELSAVE)) {
                    if (filter == 1) {
                        PRINT_ERR_HEAD;
                        print_err("PutFile %s failed, file is filter!", filename);
                        renames(filename, chcmd);
                    } else {

                        remove(filename);
                    }
                } else if ((dirmsg->dellcl == MVALL) || (dirmsg->dellcl == MVSAVE)) {
                    renames(filename, chcmd);
                } else if (dirmsg->dellcl == SAMEFILE) {    //songyu start
                    InsertData(DBCOMMONFILE, filename, filetime.st_mtime, filetime.st_size, dirmsg->user, dirmsg->db);   //插入数据到数据库表中
                }                                       //songyu end
            } else {
                PRINT_ERR_HEAD;
                print_err("PutFile %s  failed!", filename);
                bret = false;
            }
        }
    } else {

        PRINT_DBG_HEAD;
        print_dbg("Difftime=%f", difftime(nowtime, filetime.st_mtime));
    }
    return bret;
}

/*******************************************************************************************
*功能:        读取本地目录，发送文件，本地文件处理
*参数:        dirmsg                       ---->  任务信息
*             remotepath                   ---->  任务账号
*             localpath                    ---->  本地上传路径
*             bakpath                      ---->  备份路径
*             返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool ReadDir(DIRMSG *dirmsg, pchar remotepath, pchar localpath, pchar bakpath)
{
    CHAR filename[_FILEPATHMAX] = {0};
    bool bret  = true;

    struct dirent *ent = NULL;
    DIR *dir = NULL;
    dir = opendir(localpath);
    if (dir == NULL) {

        PRINT_ERR_HEAD;
        print_err("Failed in opendir!");
        return false;
    }
    dirmsg->dirdepth++;

    while ((ent = readdir(dir)) != NULL) {
        if (!is_sysdir(ent->d_name)) {

            make_filepath(localpath, ent->d_name, filename);
            if (is_file(filename)) {

                bret = PutFileX(dirmsg, remotepath, filename, bakpath);
            } else if (is_dir(filename)) {

                CHAR bakdir[_FILEPATHMAX] = {0};
                CHAR newremotepath[_FILEPATHMAX] = {0};
                make_filepath(remotepath, ent->d_name, newremotepath);
                bret = PutDir(dirmsg, newremotepath);                               //发送创建目录命令

                make_filepath(bakpath, ent->d_name, bakdir);
                if ((dirmsg->dellcl == MVALL) || (dirmsg->dellcl == MVSAVE))  mkdir(bakdir, S_IRWXO | S_IRWXG | S_IRWXU);
                bret = ReadDir(dirmsg, newremotepath, filename, bakdir);            //回调
            } else {

                PRINT_ERR_HEAD;
                print_err("Don't know whether the path(%s) is a file or a directory!", filename);
                RecordFileLog(dirmsg, "DIRORFILE", filename, false);


                if (opendir(filename) == NULL) {
                    bret = PutFileX(dirmsg, remotepath, filename, bakpath);
                } else {

                    CHAR bakdir[_FILEPATHMAX] = {0};
                    CHAR newremotepath[_FILEPATHMAX] = {0};
                    make_filepath(remotepath, ent->d_name, newremotepath);
                    bret = PutDir(dirmsg, newremotepath);                               //发送创建目录命令

                    make_filepath(bakpath, ent->d_name, bakdir);
                    if ((dirmsg->dellcl == MVALL) || (dirmsg->dellcl == MVSAVE))  mkdir(bakdir, S_IRWXO | S_IRWXG | S_IRWXU);
                    bret = ReadDir(dirmsg, newremotepath, filename, bakdir);            //回调
                }
            }
        }
    }
    closedir(dir);

    if ((dirmsg->retdir == 0) || (dirmsg->retdir < dirmsg->dirdepth)) {

        if ((dirmsg->dellcl == DELALL) || (dirmsg->dellcl == MVALL)) {
            if (strlen(localpath) != strlen(dirmsg->dirpath)) rmdir(localpath);
        }
    }
    dirmsg->dirdepth--;
    return bret;
}

/*******************************************************************************************
*功能:        上传文件
*参数:        dirmsg                     ---->  任务信息
*             remotepath                 ---->  任务账号
*             filepath                   ---->  文件路径
*             is_filter                  ---->  默认是0， 1:文件被过滤
*             返回值                     ---->  false失败
*注释:
*******************************************************************************************/
bool PutFile(DIRMSG *dirmsg, pchar remotepath, pchar filepath, pint32 is_filter, SYSDBSQL *dbsql)
{
    bool bret = false;
    CHAR filename[_FILENAMEMAX] = {0};
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    split_filepath(filepath, NULL, filename);

    //过滤处理 1：白名单    2：黑名单
    if ((dirmsg->ckfilterfiles == 1) || (dirmsg->ckfilterfiles == 2)) {         //进入过滤处理

        CHAR suffix[_FILENAMEMAX] = {0};

        bool filter = true;
        bool bret = (get_filesuffix(filename, suffix) > 0);
        if (dirmsg->ckfilterfiles == 1) {
            if (!filter_filesuffix(dirmsg->filterfiles, (bret ? suffix : _SYSSUFFIXNULL))) filter = false; //白名单中未找到
        } else {
            if (filter_filesuffix(dirmsg->filterfiles,  (bret ? suffix : _SYSSUFFIXNULL))) filter = false; //黑名单中存在
        }
        if (!filter) {
            PRINT_DBG_HEAD;
            print_dbg("Sendfile ckfilter=%d,filter=%s,filepath=%s", dirmsg->ckfilterfiles, dirmsg->filterfiles, sendmsg);
            *is_filter = 1;
            return true;
        }
    }
    if (dirmsg->mode == MODE_SUTCP) {
        MySprintf(sendmsg, strcmd_(LSFILE), remotepath, filename);
    } else {
        MySprintf(sendmsg, strcmd_(SFILE), remotepath, filename);
    }

    if ((dirmsg->mode == MODE_TCP) && (dirmsg->parnum > 0)) {
        PRINT_DBG_HEAD;
        print_dbg("Sendfile remotepath=%s,filepath=%s", remotepath, filepath);

        CSUSOCKET tmp;

        if (!SuSendRecv(dirmsg, sendmsg, RET_PREPARE_OK, &tmp)) {

            PRINT_ERR_HEAD;
            print_err("PutFile %s  failed!", sendmsg);
            return false;
        }
        bret = SendFile(&tmp, filepath, false, false, dirmsg->sendchk, dbsql); //发送文件
        SHUTDOWN(tmp);
    } else {
        if (!SuSendRecv(dirmsg, sendmsg, RET_PREPARE_OK)) {

            PRINT_ERR_HEAD;
            print_err("PutFile %s  failed!", sendmsg);
            return false;
        }

        MySprintf(sendmsg, "上传", remotepath, filename);

        if (dirmsg->mode == MODE_UDP) {
            bret = dirmsg->cli_p.susendfile(filepath);
        } else {
            if (dirmsg->mode == MODE_SUTCP) {
                bret = SendFile(&dirmsg->cli_p, filepath, false, false); //发送文件
                if (bret) {

                    //修改获取文件大小方式，防止文件过大导致的出错
                    struct stat filestat;
                    stat(filepath, &filestat);
                    bret = RecordSFileX(dirmsg, remotepath, filename, filestat.st_size, FILESYMBOL);
                } else {
                    SHUTDOWN(dirmsg->cli_p);
                }
                RecordCallLOG(dirmsg, (bret ? SUCCESS : FAIL), sendmsg);
            } else {
                bret = SendFile(&dirmsg->cli_p, filepath, false, false, dirmsg->sendchk, dbsql); //发送文件
                SHUTDOWN(dirmsg->cli_p);
            }

        }
    }
    RecordFileLog(dirmsg, "PutFile", filepath, bret);
    return bret;
}

/*******************************************************************************************
*功能:        发送创建目录命令
*参数:        dirmsg                      ---->  任务信息
*             filepath                    ---->  远端路径
*             返回值                      ---->  false失败
*注释:
*******************************************************************************************/
bool PutDir(DIRMSG *dirmsg, pchar filepath)
{
    CHAR recvmsg[MAX_MSGSIZE] = {0};
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    bool bret;
    MySprintf(recvmsg, strcmd_(MKDIR), MKDIROK);
    MySprintf(sendmsg, strcmd_(MKDIR), filepath);
    bret = SuSendRecv(dirmsg, sendmsg, recvmsg);
    SHUTDOWN(dirmsg->cli_p);

    RecordFileLog(dirmsg, "PutDir", filepath, bret);
    if (dirmsg->mode == MODE_SUTCP) {
        RecordCallLOG(dirmsg, (bret ? SUCCESS : FAIL), filepath);

        //向SFILE表写入文件夹记录
        RecordSFile(dirmsg, filepath, "", 0, FLODERSYMBOL);
    }

    return bret;
}

/*******************************************************************************************
*功能:        写本地日志
*参数:        dirmsg                      ---->  任务信息
*             event                       ---->  处理事件
*             process                     ---->  处理信息
*             bret                        ---->  结果 true成功 false失败
*             返回值                      ---->  false失败
*注释:
*******************************************************************************************/
bool RecordFileLog(DIRMSG *dirmsg, pchar event, pchar process, bool bret)
{
    if (!dirmsg->iflog) return false;
    bool ret = false;

    if (dirmsg->fp == NULL) {

        time2str(-1, dirmsg->logdate, sizeof(dirmsg->logdate), "%Y-%m-%d");
        ret = true;
    } else {
        CHAR logdatebak[MAX_TIME] = {0};
        time2str(-1, logdatebak, sizeof(logdatebak), "%Y-%m-%d");
        if (strcmp(logdatebak, dirmsg->logdate) != 0) {

            fclose(dirmsg->fp);
            ret = true;
            memset(dirmsg->logdate, 0, sizeof(dirmsg->logdate));
            memcpy(dirmsg->logdate, logdatebak, sizeof(dirmsg->logdate));
        }
    }

    if (ret) {
        CHAR logfile[_FILEPATHMAX] = {0};
        CHAR logfilepath[_FILEPATHMAX] = {0};
        sprintf(logfile, "dir%d_%s.log", dirmsg->id, dirmsg->logdate);
        make_filepath(cfgmsg.logpath, logfile, logfilepath);
        dirmsg->fp = fopen(logfilepath, "a+");
        if (dirmsg->fp == NULL) {
            PRINT_ERR_HEAD;
            print_err("Open logfilepath failed, logfilepath=%s", logfilepath);
            dirmsg->iflog = false;
        }
    }

    CHAR chmsg[_FILEPATHMAX] = {0};
    CHAR optime[MAX_TIME] = {0};
    time2str(-1, optime, sizeof(optime));
    sprintf(chmsg, "%s\t%s\t%s\t%s\n", optime, event, process, (bret ? SUCCESS : FAIL));
    fwrite(chmsg, strlen(chmsg), 1, dirmsg->fp);
    return true;
}

/*******************************************************************************************
*功能:        写远端访问日志
*参数:        dirmsg                      ---->  任务信息
*             result                      ---->  结果
*             info                        ---->  处理任务
*             返回值                      ---->  false失败
*注释:
*******************************************************************************************/
bool RecordCallLOG(DIRMSG *dirmsg, pchar result, pchar info)
{
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    CHAR localip[IPSIZE] = {0};
    uint32 ip = 0;
    uint16 port = 0;

    SUOPEN(dirmsg);
    dirmsg->cli_p.getaddress(&ip, &port, true);
    ip2str(ip, localip);
    sprintf(sendmsg, "%s:%s','%s','%s','%d','%s','%s',0)", strcmd_(RECORDLOG), dirmsg->user, localip, dirmsg->ip,
            cfgmsg.port, result, info);

    PRINT_DBG_HEAD;
    print_dbg("Sendmsg=%s", sendmsg);
    if (strlen(sendmsg) != dirmsg->cli_p.writesocket(sendmsg, strlen(sendmsg))) {
        PRINT_ERR_HEAD;
        print_err("Send CallLOG(%s) failed!", sendmsg);
        RecordFileLog(dirmsg, "CallLOG", sendmsg, false);
        return false;
    }
    SHUTDOWN(dirmsg->cli_p);
    return true;
}

/*******************************************************************************************
*功能:       写远端SFILE日志
*参数:        dirmsg                      ---->  任务信息
*             filepath                    ---->  路径
*             filename                    ---->  文件名
*             size                        ---->  文件大小
*             ifdir                       ---->  是否为文件 1:文件； 0:文件夹
*             返回值                      ---->  false失败
*注释:
*******************************************************************************************/
bool RecordSFile(DIRMSG *dirmsg, pchar filepath, pchar filename, int64 size, CHAR ifdir)
{
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    CHAR localip[IPSIZE] = {0};
    uint32 ip = 0;
    uint16 port = 0;

    SUOPEN(dirmsg);
    dirmsg->cli_p.getaddress(&ip, &port, true);
    ip2str(ip, localip);
    sprintf(sendmsg, "%s:%s','%s%s/','%s','%lld','%s','用户','%c')", strcmd_(RECORDSFILE), dirmsg->user,
            ModleDIR[DDIR_CLIENT].path, filepath, filename, size, localip, ifdir);

    PRINT_DBG_HEAD;
    print_dbg("Sendmsg=%s", sendmsg);
    if (strlen(sendmsg) != dirmsg->cli_p.writesocket(sendmsg, strlen(sendmsg))) {
        PRINT_ERR_HEAD;
        print_err("Send SFILE(%s) failed!", sendmsg);
        RecordFileLog(dirmsg, "SFILE", sendmsg, false);
        return false;
    }
    SHUTDOWN(dirmsg->cli_p);
    return true;
}

bool RecordSFileX(DIRMSG *dirmsg, pchar filepath, pchar filename, int64 size, CHAR ifdir)
{
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    CHAR localip[IPSIZE] = {0};
    uint32 ip = 0;
    uint16 port = 0;

    dirmsg->cli_p.getaddress(&ip, &port, true);
    ip2str(ip, localip);
    sprintf(sendmsg, "'%s','%s%s/','%s','%lld','%s','用户','%c'", dirmsg->user,
            ModleDIR[DDIR_CLIENT].path, filepath, filename, size, localip, ifdir);

    PRINT_DBG_HEAD;
    print_dbg("Sendmsg=%s", sendmsg);
    if (strlen(sendmsg) != dirmsg->cli_p.writesocket(sendmsg, strlen(sendmsg))) {
        PRINT_ERR_HEAD;
        print_err("Send SFILE(%s) failed!", sendmsg);
        RecordFileLog(dirmsg, "SFILE", sendmsg, false);
        return false;
    }

    memset(sendmsg, 0, sizeof(sendmsg));
    dirmsg->cli_p.readsocket(sendmsg, sizeof(sendmsg));
    PRINT_DBG_HEAD;
    print_dbg("Recv msg = %s", sendmsg);
    if (strcmp(sendmsg, RET_PREPARE_OK) != 0) return false;

    SHUTDOWN(dirmsg->cli_p);
    return true;
}


/*******************************************************************************************
*功能:        获取列表
*参数:        dirmsg                         ---->  任务信息
*             remotepath                     ---->  任务账号
*             vector                         ---->  vector
*             返回值                         ---->  false失败
*注释:
*******************************************************************************************/
int32 GetList(DIRMSG *dirmsg, pchar remotepath, vector<FILELIST> *vec)
{
    CHAR linebuf[_FILEPATHMAX] = {0};
    CHAR tmppath[_FILEPATHMAX] = {0};
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    MySprintf(sendmsg, strcmd_(LPDIR), remotepath);
    if (!SuSendRecv(dirmsg, sendmsg)) return -1;

    CHAR tmpname[_FILENAMEMAX] = {0};
    sprintf(tmpname, "dir%d.lst", dirmsg->id);
    make_filepath(cfgmsg.tmppath, tmpname, tmppath);
    RecvFile(&dirmsg->cli_p, tmppath, false, false);

    FILE *fp = fopen(tmppath, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD;
        print_err("GetList open (%s) file failed!", tmppath);
        return -1;
    }
    while (fgets(linebuf, sizeof(linebuf) - 1, fp) != NULL) {           //解析列表文件到vec
        if ((linebuf[0] != FILESYMBOL) && (linebuf[0] != FLODERSYMBOL)) {

            PRINT_ERR_HEAD;
            print_err("This line does not recognize! linebuf=%s", linebuf);
        } else {

            //修改读取文件列表获取文件信息方式
            FILELIST node;
            pchar const delim = "\r";
            memset(&node, 0, sizeof(node));
            pchar buf = linebuf;
            pchar p;
            p = strsep(&buf, delim);
            memcpy(&(node.ifdir), p, strlen(p));
            p = strsep(&buf, delim);
            memcpy(node.filename, p, strlen(p));
            p = strsep(&buf, delim);
            str2long((const pchar)p,  (puint64)(&node.filesize));
            p = strsep(&buf, delim);
            memcpy(node.shortname, p, strlen(p));
            p = strsep(&buf, delim);
            //node.lastchangetime = atoll(p);
            str2long((const pchar)p,  (puint64)(&node.lastchangetime));

            CHAR formattime[MAX_TIME] = {0};
            time2str(node.lastchangetime, formattime, sizeof(formattime));

            PRINT_DBG_HEAD;
            print_dbg("GetList ifdir=%c, filename=%s, filesize=%lld, shortname=%s, formattime=%s, lastchangetime=%lld, linebuf=%s",
                      node.ifdir, node.filename, node.filesize, node.shortname, formattime, node.lastchangetime, linebuf);
            vec->push_back(node);
        }
    }
    fclose(fp);
    remove(tmppath);
    return vec->size();
}

/*******************************************************************************************
*功能:       下载文件处理
*参数:       dirmsg                         ---->  任务信息
*            dirpath                        ---->  下载本地目录
*            remotepath                     ---->  任务账号
*            返回值                         ---->  false失败
*注释:
*******************************************************************************************/
bool GetFile(DIRMSG *dirmsg, pchar dirpath, pchar remotepath)
{
    vector<FILELIST> vec;
    vector<FILELIST>::iterator it;
    int32 k = GetList(dirmsg, remotepath, &vec);
    if (k < 0) {
        return false;
    } else if (k == 0) {
        return true; //空目录
    }

    bool bret = false;
    CHAR newdirpath[_FILEPATHMAX] = {0};
    CHAR newremotepath[_FILEPATHMAX] = {0};
    for (it = vec.begin(); it < vec.end(); it++) {
        if (it->ifdir == FLODERSYMBOL) {

            make_filepath(dirpath, it->filename, newdirpath);
            mkdir(newdirpath, S_IRWXO | S_IRWXG | S_IRWXU);                           //创建本地目录
            make_filepath(remotepath, it->filename, newremotepath);
            bret = GetFile(dirmsg, newdirpath, newremotepath);                               //回调

            CHAR sendmsg[MAX_MSGSIZE] = {0};
            MySprintf(sendmsg, strcmd_(DEL), newremotepath);
            bret = SuSendRecv(dirmsg, sendmsg, RET_PREPARE_OK);                              //删除对端文件
        } else {

            CHAR tmpbuf[MAX_MSGSIZE] = {0};
            MySprintf(newremotepath, strcmd_(RFILE), remotepath, it->shortname);

            PRINT_DBG_HEAD;
            print_dbg("GetFileX newremotepath=%s  pshortname=%s", newremotepath, it->shortname);

            MySprintf(tmpbuf, "下载", remotepath, it->filename);
            make_filepath(dirpath,  it->filename, newdirpath);
            if (SuSendRecv(dirmsg, newremotepath)) {

                //临时文件名
                CHAR tmpname[_FILEPATHMAX] = {0};
                if (!is_strempty(dirmsg->tmpfile)) {
                    sprintf(tmpname, "%s%s", newdirpath, dirmsg->tmpfile);
                } else {
                    CHAR nowtime[30] = {0};
                    time2str(-1, nowtime, sizeof(nowtime), "%Y%m%d%H%M%S");
                    sprintf(tmpname, "%s.su%s", newdirpath, nowtime);
                }

                if (dirmsg->mode == MODE_SUTCP) {
                    bret = RecvFile(&dirmsg->cli_p, tmpname, false, false);      //接收文件
                } else {
                    bret = RecvFile(&dirmsg->cli_p, tmpname, false, false, dirmsg->sendchk); //接收文件
                }

                RecordFileLog(dirmsg, "GetFile", newdirpath, bret);
                if (dirmsg->mode == MODE_SUTCP) RecordCallLOG(dirmsg, (bret ? SUCCESS : FAIL), tmpbuf);

                if (bret) {

                    //更名临时文件
                    if (rename(tmpname, newdirpath) != 0) {
                        PRINT_ERR_HEAD;
                        print_err("GetFile Failed rename %s ", tmpname);
                        remove(tmpname);
                    }

                    MySprintf(tmpbuf, strcmd_(DEL), remotepath, it->shortname);
                    bret = SuSendRecv(dirmsg, tmpbuf, RET_PREPARE_OK);                      //删除对端文件
                }
            } else  {
                PRINT_ERR_HEAD;
                print_err("GetFile failed! filepath=%s", newremotepath);
            }
        }
    }
    return bret;
}

/*******************************************************************************************
*功能:        发送验证用户名是否存在命令
*参数:        dirmsg                      ---->  任务信息
*             返回值                      ---->  false不存在
*注释:
*******************************************************************************************/
bool UserLogin(DIRMSG *dirmsg)
{
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    bool bretin = false;
    bool bretout = false;
    sprintf(sendmsg, "%s:%s%s", strcmd_(USERLOGIN), LINUX_LOGIN, dirmsg->user);
    bretin = SuSendRecv(dirmsg, sendmsg, RET_PREPARE_OK);

    if (!bretin) {
        PRINT_ERR_HEAD;
        print_err("UserLogin failed,taskname=%s user=%s sendmsg=%s", dirmsg->taskname, dirmsg->user, sendmsg);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("UserLogin success,taskname=%s user=%s sendmsg=%s", dirmsg->taskname, dirmsg->user, sendmsg);
    }

    if ((strcmp(cfgmsg.model, "TRAN") == 0)) {    //在TRAN模式下登陆收文件的服务器端
        bretout = SuSendRecvT(dirmsg, sendmsg, RET_PREPARE_OK, &(dirmsg->cli_t));
        if (!bretout) {
            PRINT_ERR_HEAD;
            print_err("Server2 UserLogin failed,taskname=%s user=%s sendmsg=%s", dirmsg->taskname , dirmsg->user , sendmsg);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("Server2 UserLogin success,taskname=%s user=%s sendmsg=%s", dirmsg->taskname , dirmsg->user, sendmsg);
        }

        if (dirmsg->iflog) {
            CLOGMANAGE logsql;
            logsql.Init();
            if (bretin) {
                logsql.WriteFileSyncLog(dirmsg->id, dirmsg->taskname, dirmsg->intip, dirmsg->outip, "", "", "", PRI_SUCCESS, CONNECTINSUCCESS, false);
            } else {
                logsql.WriteFileSyncLog(dirmsg->id, dirmsg->taskname, dirmsg->intip, dirmsg->outip, "", "", "", PRI_FAILED, CONNECTINFAIL, false);
            }
            if (bretout) {
                logsql.WriteFileSyncLog(dirmsg->id, dirmsg->taskname, dirmsg->intip, dirmsg->outip, "", "", "", PRI_SUCCESS, CONNECTOUTSUCCESS, true);
            } else {
                logsql.WriteFileSyncLog(dirmsg->id, dirmsg->taskname, dirmsg->intip, dirmsg->outip, "", "", "", PRI_FAILED, CONNECTOUTFAIL, true);
            }
            logsql.DisConnect();
        }
        return (bretin && bretout);
    } else {
        return bretin;
    }

}

/*******************************************************************************************
*功能:        移走文件
*参数:        srcpath                      ---->  源路径
*             dstpath                      ---->  目的路径
*             返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool renames(pchar srcpath, pchar dstpath)
{
    CHAR tmppath[_FILEPATHMAX] = {0};
    split_filepath(dstpath, tmppath);
    if (is_dir(tmppath)) {
        rename(srcpath, dstpath);
    } else {
        CHAR cmd[_FILEPATHMAX] = {0};
        sprintf(cmd, "mkdir '%s' -p", tmppath);
        system(cmd);
        rename(srcpath, dstpath);
    }
    return true;
}

static const pchar SQL_TASK_UPDATE = "SELECT d.ettaskid,d.etfilepath,d.etsize,e.eddirpath,e.eddirstatus "
                                     "FROM nt_exchange_task as d, nt_exchange_dir as e WHERE d.etdirid = e.eddirid and d.etstatus=1 ORDER BY d.etpriority desc, d.etcreatetime";
/*******************************************************************************************
*功能:        通过数据库获取发送目录，发送文件，本地文件处理
*参数:        dirmsg                       ---->  任务信息
*             remotepath                   ---->  任务账号
*             localpath                    ---->  本地上传路径
*             bakpath                      ---->  备份路径
*             返回值                       ---->  false失败
*注释:
*******************************************************************************************/
bool ReadDirSql(DIRMSG *dirmsg, pchar remotepath, pchar localpath, pchar bakpath)
{
    bool bret  = true;
#ifndef __CYGWIN__
    CSYSDB db;
    if (!db.opendb(dirmsg->sqladdr, dirmsg->sqlport, dirmsg->sqlname, dirmsg->sqlpwd, dirmsg->sqldb, NULL)) {
        PRINT_ERR_HEAD;
        print_err("Open sql failed, sqladdr=%s, sqlname=%s, sqlpwd=%s,sqldb=%s!", dirmsg->sqladdr, dirmsg->sqlname, dirmsg->sqlpwd, dirmsg->sqldb);
        return false;
    }
    CHAR sqlcmd[MAX_MSGSIZE] = {0};
    uint32 col;
    MYSQL_ROW one = NULL;
    CHAR filename[_FILEPATHMAX] = {0};
    CHAR filebakpath[_FILEPATHMAX] = {0};
    CHAR newremotepath[_FILEPATHMAX] = {0};
    CHAR tmppath[_FILEPATHMAX] = {0};
    CHAR etfilepath[_FILEPATHMAX] = {0};

    if (bret && (db.querysave(SQL_TASK_UPDATE, col))) {

        PRINT_DBG_HEAD;
        print_dbg("Sql  tasknum = %d", db.queryresultcnt());
        while ((one = (MYSQL_ROW)db.queryresult()) != NULL) {

            PRINT_DBG_HEAD;
            print_dbg("Sql, ettaskid=%s, etfilepath=%s, etsize=%s,eddirpath=%s, eddirstatus=%s",  one[0], one[1], one[2], one[3], one[4]);

            memset(filename, 0, sizeof(filename));
            memset(filebakpath, 0, sizeof(filebakpath));
            memset(etfilepath, 0, sizeof(etfilepath));

            strcpy(etfilepath, one[1]);
            Checkwinpath(etfilepath);
            //make_filepath(one[3], one[1], filename);
            make_filepath(dirmsg->dirpath, etfilepath, filename);
            make_filepath(dirmsg->bakpath, etfilepath, filebakpath);
            split_filepath(etfilepath, tmppath);
            make_filepath(remotepath, tmppath, newremotepath);


            if (dirmsg->parnum > 0) {
                PutFile_(dirmsg, newremotepath, filename, filebakpath, one[0]);
            } else {
                int32 filter = 0;

                sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstarttime=NOW(), etstatus=2 WHERE ettaskid='%s'", one[0]);
                db.runsql(sqlcmd, NULL);
                SYSDBSQL tmpsql;
                tmpsql.sql = &db;
                strcpy(tmpsql.guid, one[0]);

                if (PutFile(dirmsg, newremotepath, filename, &filter, &tmpsql)) {                 //发送文件
                    if ((dirmsg->dellcl == DELALL) || (dirmsg->dellcl == DELSAVE)) {
                        if (filter == 1) {
                            PRINT_ERR_HEAD;
                            print_err("PutFile %s failed, file is filter!", filename);
                            renames(filename, filebakpath);
                        } else {
                            remove(filename);
                        }
                    } else if ((dirmsg->dellcl == MVALL) || (dirmsg->dellcl == MVSAVE)) {
                        renames(filename, filebakpath);
                    }
                } else {
                    PRINT_ERR_HEAD;
                    print_err("PutFile %s  failed!", filename);
                    sprintf(sqlcmd, "UPDATE nt_exchange_task SET etstatus=99, etmemo='Put file failed' WHERE ettaskid='%s'", one[0]);
                    db.runsql(sqlcmd, NULL);
                    bret = false;
                }
            }
        }
        db.queryend();
    }
    db.closedb();
#endif
    return bret;
}

/*******************************************************************************************
*功能:       调用上传下载函数
*参数:       param                       ---->  任务信息
*            返回值                      ---->  NULL结束
*注释:
*******************************************************************************************/
void *PutorGetProcess(void *param)
{
    DIRMSG *dirmsg = (DIRMSG *)param;
    //songyu start
    if ((dirmsg->dellcl == SAMEFILE) || cfgmsg.bkeywordswitch) {
        if (CreateDB(cfgmsg.dbpath, dirmsg, &(dirmsg->db))) {
            PRINT_DBG_HEAD;
            print_dbg("Create db file:user_%s.db success", dirmsg->user);
            if (dirmsg->dellcl == SAMEFILE) {
                CreateTable(DBCOMMONFILE, dirmsg->user, dirmsg->db);
                CreateTable(DBFOLDER, dirmsg->user, dirmsg->db);
            }
            if (cfgmsg.bkeywordswitch) CreateTable(DBKEYFILE, dirmsg->user, dirmsg->db);
        } else {
            PRINT_ERR_HEAD;
            print_err("Create db file:user_%s.db failed", dirmsg->user);
        }
    }
    //songyu end

    bool login = false;
    if (strcmp(cfgmsg.model, "PUT") == 0) {
        while (1) {
            if (login) {
                dirmsg->dirdepth = 0;
                if (dirmsg->sqlmode == 1) {
                    login = ReadDirSql(dirmsg, dirmsg->user, dirmsg->dirpath, dirmsg->bakpath);
                } else {
                    login = ReadDir(dirmsg, dirmsg->user, dirmsg->dirpath, dirmsg->bakpath);
                }

                if ((dirmsg->mode == MODE_SUTCP) && (!login)) RecordCallLOG(dirmsg, (login ? SUCCESS : FAIL), "Logout(Put)");
            } else {
                if (UserLogin(dirmsg)) login = true;                               //验证用户名是否匹配
                if (dirmsg->mode == MODE_SUTCP) RecordCallLOG(dirmsg, (login ? SUCCESS : FAIL), "Login(Put)");
            }
            sleep(dirmsg->sync);
        }
    } else if (strcmp(cfgmsg.model, "GET") == 0) {
        while (1) {
            if (login) {
                login =  GetFile(dirmsg, dirmsg->dirpath, dirmsg->user);
                if ((dirmsg->mode == MODE_SUTCP) && (!login)) RecordCallLOG(dirmsg, (login ? SUCCESS : FAIL), "Logout(Get)");
            } else {
                if (UserLogin(dirmsg)) login = true;                               //验证用户名是否匹配
                if (dirmsg->mode == MODE_SUTCP) RecordCallLOG(dirmsg, (login ? SUCCESS : FAIL), "Login(Get)");
            }
            sleep(dirmsg->sync);
        }
    } else if (strcmp(cfgmsg.model, "TRAN") == 0) {       //songyu start
        sem_init(&(cfgmsg.sem[dirmsg->id]), 0 , dirmsg->parnum);
        pthread_mutex_init(&cfgmsg.tranmut, NULL);

        while (1) {
            if (login) {
                login = TranFile(dirmsg, dirmsg->user);
            } else {
                if (UserLogin(dirmsg)) login = true;    //验证用户名是否匹配
            }
            sleep(dirmsg->sync);
        }

        sem_destroy(&(cfgmsg.sem[dirmsg->id]));
        pthread_mutex_destroy(&cfgmsg.tranmut);
    } else {
        PRINT_ERR_HEAD;
        print_err("Don't have this model");
    }   //songyu end

    //轮询任务结束数据包数量清零
    //priority_end(pthread_self());

    if (dirmsg->fp != NULL) fclose(dirmsg->fp);
    //songyu start
    if (dirmsg->dellcl == SAMEFILE) {
        sqlite3_close(dirmsg->db);
    }
    //songyu end
    return NULL;
}

void *PutorGetProcess_UDP(void *param)
{
    DIRMSG *dirmsg = (DIRMSG *)param;

    //songyu start
    if (dirmsg->dellcl == SAMEFILE) {
        if (CreateDB(cfgmsg.dbpath, dirmsg, &(dirmsg->db))) {
            PRINT_DBG_HEAD;
            print_dbg("Create db file:user_%s.db success", dirmsg->user);
        } else {
            PRINT_ERR_HEAD;
            print_err("Create db file:user_%s.db failed", dirmsg->user);
        }
        if (CreateTable(DBCOMMONFILE, dirmsg->user, dirmsg->db)) {
            PRINT_DBG_HEAD;
            print_dbg("Create table:user_%s success", dirmsg->user);
        } else {
            PRINT_ERR_HEAD;
            print_err("Create table:user_%s failed", dirmsg->user);
        }
    }
    //songyu end

    if (!dirmsg->cli_p.suopen(dirmsg->ip, dirmsg->port, SOCKET_CLIENT, SOCKET_UDP)) {
        RecordFileLog(dirmsg, "Socket", "Connect To Server", false);
        return NULL;
    } else {
        dirmsg->cli_p.susetopt(K_OPTDLY, &dirmsg->senddly);
        dirmsg->cli_p.susetopt(K_OPTRPT, &dirmsg->sendnum);
        dirmsg->cli_p.susetopt(K_OPTCHK, &dirmsg->sendchk);
    }

    while (1) {

        ReadDir(dirmsg, dirmsg->user, dirmsg->dirpath, dirmsg->bakpath);
        sleep(dirmsg->sync);
    }

    if (dirmsg->fp != NULL) fclose(dirmsg->fp);
    //songyu start
    sqlite3_close(dirmsg->db);
    //songyu end
    return NULL;
}

/*******************************************************************************************
*功能:       读取配置文件，创建多任务线程
*参数:       config                      ---->  配置文件
*           logswitch                   ---->  全局日志开关
*           keyfile                     ---->  关键字文件路径名
*            返回值                      ---->  1 成功, -1配置文件出错
*注释:
*******************************************************************************************/
int32 CreateProcess(pchar config, pchar logswitch, pchar keyfile)
{
    memset(&cfgmsg, 0, sizeof(cfgmsg));
    pthread_t tid;

    cfgmsg.blogswitch = atoi(logswitch);

    if (!ReadConfig(config)) return -1;
    if (!ReadConfig_(dirmsg, config)) return -1;

    if (strcmp(keyfile, "NULL") == 0) {
        cfgmsg.bkeywordswitch = false;
        PRINT_DBG_HEAD;
        print_dbg("Unable filter keywords !\n");
    } else {
        if (!is_file(keyfile)) {
            cfgmsg.bkeywordswitch = false;
            PRINT_ERR_HEAD;
            print_err("keyword filepath = %s is errno !", keyfile);
        } else {
            cfgmsg.bkeywordswitch = ReadKey(keyfile, KEYUTF8, &(cfgmsg.keyvec));
            PRINT_DBG_HEAD;
            print_dbg("Enable filter keywords !\n");
        }
    }
    //zkp 初始化   暂不同时支持并行文件功能和文件优先级功能
    int32 j = 0;
    bool  bret = true;
    for (j = 0; j < cfgmsg.dirnum; ++j) {
        if (dirmsg[j].parnum > 0) {
            bret = false;
            break;
        }
    }
    if (bret) priority_init(cfgmsg.dirnum);

    if (strcmp(cfgmsg.model, "TRAN") == 0) {        //创建优先级调度线程
        if (pthread_create(&tid, NULL, ChkSndPri, NULL) != 0) {
            PRINT_ERR_HEAD;
            print_err("Create ChkSndPri thread failed");
        } else {
            PRINT_DBG_HEAD;
            print_dbg("Detach ChkSndPri thread, tid = %d\n", tid);
        }
    }


    for (int32 i = 0; i < cfgmsg.dirnum; i++) {         //创建线程 ，调用上传或下载函数

        if (dirmsg[i].mode == MODE_UDP) {

            if (pthread_create(&tid, NULL, PutorGetProcess_UDP, &dirmsg[i]) != 0) {   //创建线程失败

                PRINT_ERR_HEAD;
                print_err("Usersrv client failed(%s)!", strerror(errno));
            } else {
                while (ESRCH == pthread_kill(tid, 0))   usleep(1);

                PRINT_DBG_HEAD;
                print_dbg("Usersrv client %d Rrunning...", tid);


                priority_task_init(tid, dirmsg[i].priority);
            }

        } else {

            if (pthread_create(&tid, NULL, PutorGetProcess, &dirmsg[i]) != 0) {

                PRINT_ERR_HEAD;
                print_err("Usersrv client failed(%s)!", strerror(errno));
            } else {
                while (ESRCH == pthread_kill(tid, 0))   usleep(1);

                PRINT_DBG_HEAD;
                print_dbg("Usersrv client %d Rrunning...", tid);

                priority_task_init(tid, dirmsg[i].priority);
            }
        }
    }
    //创建优先级处理线程
    priority_createpthread();

    return 1;
}

/*******************************************************************************************
*功能:       创建或打开数据库文件
*参数:       dbpath                     ----> 数据库文件存储路径
*           user                       ----> 用户名
*           db                         ----> 数据库文件句柄
*           返回值                      ----> true 成功, false 创建或者打开数据库文件出错
*注释:
*******************************************************************************************/
bool CreateDB(const pchar dbpath, DIRMSG *dirmsg, sqlite3 **db)
{
#ifdef USE_SQLITE
    CHAR db_name[_FILENAMEMAX] = {0};
    CHAR sql_path[_FILEPATHMAX] = {0};

    sprintf(db_name, "user_%s_%s_%u_%s_%u.db", dirmsg->user, dirmsg->ip, dirmsg->port, dirmsg->ip2, dirmsg->port2);
    make_filepath(dbpath, db_name, sql_path);

    if (sqlite3_open(sql_path, db) == SQLITE_OK) {  //判断创建/打开数据库是否成功
        PRINT_DBG_HEAD;
        print_dbg("USER:%s create/Open %s success", dirmsg->user, db_name);
        return true;
    } else {
        char *errmsg = (char *)sqlite3_errmsg(*db);
        PRINT_ERR_HEAD;
        print_err("USER:%s create/open %s failed,%s", dirmsg->user, db_name, errmsg);
        sqlite3_free(errmsg);
        return false;
    }
#else
    return true;
#endif
}

/*******************************************************************************************
*功能:       创建表
*参数:       filetype                    ---->文件类型（不同类型文件记录在不同的表中）
*           user                        ---->用户名
*           db                          ---->数据库文件句柄
*           返回值                       ---->true 成功, false 创建数据表时出错
*注释:
*******************************************************************************************/
bool CreateTable(const pchar filetype, const pchar user, sqlite3 *db)
{
#ifdef USE_SQLITE
    pchar errmsg = NULL;
    CHAR sqlbuf[2048] = {0};
    snprintf(sqlbuf, sizeof(sqlbuf), "CREATE TABLE user_%s_%s(path_name TEXT NOT NULL,file_size INTEGER,file_time TIMESTAMP NOT NULL)", user, filetype);

    if (sqlite3_exec(db, sqlbuf, NULL, NULL, &errmsg) == SQLITE_OK) {          //创建表是否成功
        PRINT_DBG_HEAD;
        print_dbg("USER:%s create table user_%s_%s success", user, user, filetype);

        snprintf(sqlbuf, sizeof(sqlbuf), "CREATE INDEX search ON user_%s_%s(file_time)", user, filetype);
        if (sqlite3_exec(db, sqlbuf, NULL, NULL, &errmsg) == SQLITE_OK) {      //创建索引是否成功
            PRINT_DBG_HEAD;
            print_dbg("USER:%s create index file_time success", user);
        } else {
            PRINT_ERR_HEAD;
            print_err("USER:%s create index file_time failed,%s", user, errmsg);
            sqlite3_free(errmsg);
            return false;
        }
        return true;

    } else {
        PRINT_ERR_HEAD;
        print_err("USER:%s create table user_%s_%s fail! %s", user, user, filetype, errmsg);
        sqlite3_free(errmsg);
        return false;
    }
#else
    CHAR str_sql[2048] = {0};
    CHAR errmsg[1024] = {0};
    bool bret = false;
    CSYSDB mysqllog;
    mysqllog.opendb();
    snprintf(str_sql, sizeof(str_sql), "CREATE TABLE IF NOT EXISTS user_%s_%s(id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,\
             path_name TEXT NOT NULL,file_size BIGINT(50),file_time TIMESTAMP NOT NULL)", user, filetype);
    bret = mysqllog.runsql(str_sql, errmsg);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("create table user_%s_%s success", user, filetype);

        snprintf(str_sql, sizeof(str_sql), "ALTER  TABLE user_%s_%s ADD  INDEX index_name(file_time)", user, filetype);
        bret = mysqllog.runsql(str_sql, errmsg);
        if (bret) {
            PRINT_DBG_HEAD;
            print_dbg("table user_%s_%s create index file_time success", user, filetype);
        } else {
            PRINT_ERR_HEAD;
            print_err("table user_%s_%s create index file_time failed(%s)", user, filetype, errmsg);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("create table user_%s_%s failed (%s)", user, filetype, errmsg);
    }

    mysqllog.closedb();
    return bret;
#endif
}

/*******************************************************************************************
*功能:        插入数据
*参数:        filetype                    ---->文件类型（不同类型文件记录在不同的表中）
*            fname                       ---->路径+文件名
*            lastchangetime              ---->文件最后修改时间
*            size                        ---->文件大小
*            user                        ---->用户名
*            db                          ---->数据库文件句柄
*            返回值                       ---->true 成功, false 插入数据出错
*注释:
*******************************************************************************************/
bool InsertData(const pchar filetype, const pchar fname, int64 lastchangetime, int64 size, const pchar user, sqlite3 *db)
{
#ifdef USE_SQLITE
    pchar errmsg = NULL;
    CHAR tmp_fname[_FILEPATHMAX + 50] = {0};               //临时缓冲区
    CHAR tmp_user[MAX_USERLEN + 50] = {0};
    CHAR file_time[MAX_TIME] = {0};                     //文件最后修改时间缓冲区
    CHAR str_sql[2048] =  {0};                          //sqlite语句缓冲区

    //将时间转换为Timestamp
    time2str(lastchangetime, file_time, sizeof(file_time));

    ReplaceChar(user, tmp_user);                                     //替换字符串中的 ' 为 ''
    ReplaceChar(fname, tmp_fname);

    snprintf(str_sql, sizeof(str_sql), "INSERT INTO user_%s_%s(path_name,file_size,file_time) VALUES('%s',%lld,'%s')",
             tmp_user, filetype, tmp_fname, size, file_time);

    if (sqlite3_exec(db, str_sql, NULL, NULL, &errmsg) == SQLITE_OK) {       //判断数据是否插入成功
        PRINT_DBG_HEAD;
        print_dbg("USER:%s Insert %s,%lld,%s to table user_%s_%s success",
                  user, fname, size, file_time,  user, filetype);
        return true;
    } else {
        PRINT_ERR_HEAD;
        print_err("USER:%s Insert %s,%lld,%s to table user_%s_%s failed! %s",
                  user, fname, size, file_time, user, filetype, errmsg);
        sqlite3_free(errmsg);
        return false;
    }
#else
    CHAR str_sql[2048] =  {0};
    CHAR errmsg[1024] = {0};
    CHAR file_time[MAX_TIME] = {0};
    bool bret = false;
    time2str(lastchangetime, file_time, sizeof(file_time));

    CSYSDB mysqllog;
    mysqllog.opendb();
    snprintf(str_sql, sizeof(str_sql), "INSERT INTO user_%s_%s(path_name,file_size,file_time) VALUES('%s',%lld,'%s');",
             user, filetype, fname, size, file_time);
    bret = mysqllog.runsql(str_sql, errmsg);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("Insert %s,%lld,%s to table user_%s_%s success!", fname, size, file_time, user, filetype);
    } else {
        PRINT_ERR_HEAD;
        print_err("Insert %s,%lld,%s to table user_%s_%s failed! (%s)", fname, size, file_time, user, filetype, errmsg);
    }
    mysqllog.closedb();
    return bret;
#endif
}
/*******************************************************************************************
*功能:       查询数据
*参数:       filetype            ---->文件类型（不同类型文件记录在不同的表中）
*           fname               ---->路径+文件名
*           lastchangetime      ---->文件最后修改时间
*           size                ---->文件大小
*           user                ---->用户名
*           db                  ---->数据库文件句柄
*           返回值               ---->  true 在数据表中查询到消息, false 查询出错或未查询到
*
*注释:
*******************************************************************************************/
bool SelectData(const pchar filetype, const pchar fname, int64 lastchangetime, int64 size, const pchar user, sqlite3 *db)
{
#ifdef USE_SQLITE
    pchar errmsg = NULL;
    char **presult = NULL;
    int32 nrow = 0;
    int32 ncol = 0;
    CHAR tmp_fname[_FILEPATHMAX + 50] = {0};
    CHAR tmp_user[MAX_USERLEN + 50] = {0};
    CHAR file_time[MAX_TIME] = {0};
    CHAR sql_buf[2048] = {0};

    //将时间转换为Timestamp
    time2str(lastchangetime, file_time, sizeof(file_time));

    ReplaceChar(user, tmp_user);
    ReplaceChar(fname, tmp_fname);

    snprintf(sql_buf, sizeof(sql_buf) , "SELECT * FROM user_%s_%s WHERE file_time='%s' AND file_size=%lld AND path_name='%s'",
             tmp_user, filetype, file_time, size, tmp_fname);

    if (sqlite3_get_table(db, sql_buf, &presult, &nrow, &ncol, &errmsg) == SQLITE_OK) {
        PRINT_DBG_HEAD;
        print_dbg("USER:%s select table user_%s_%s success!", user, user, filetype);

        if (nrow >= 1) {            //查询到了数据
            PRINT_DBG_HEAD;
            print_dbg("USER:%s table name user_%s_%s,%s,%lld,%s existed,not send",
                      user, user, filetype, fname, size, file_time);
            sqlite3_free_table(presult);
            return true;
        } else {                    //未查询到
            PRINT_DBG_HEAD;
            print_dbg("USER:%s table name user_%s_%s,%s,%lld,%s not existed,will send",
                      user, user, filetype, fname, size, file_time);
            sqlite3_free_table(presult);
            return false;
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("USER:%s select table user_%s_%s failed! %s", user, user, filetype, errmsg);
        sqlite3_free(errmsg);
        return false;
    }
#else
    CHAR str_sql[2048] = {0};
    CHAR errmsg[1024] = {0};
    uint32 columns = 0;
    bool bret = false;
    CHAR file_time[MAX_TIME] = {0};

    time2str(lastchangetime, file_time, sizeof(file_time));

    CSYSDB mysqllog;
    mysqllog.opendb();
    snprintf(str_sql, sizeof(str_sql), "SELECT * FROM user_%s_%s WHERE file_time='%s' AND file_size=%lld AND path_name='%s';",
             user, filetype, file_time, size, fname);
    bret = mysqllog.querysave(str_sql, columns, errmsg);
    if (!bret) {
        PRINT_ERR_HEAD;
        print_err("SELECT %s,%lld,%s to table user_%s_%s failed! %s", fname, size, file_time, user, filetype, errmsg);
        return false;
    }
    if (mysqllog.queryresultcnt() >= 1) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("table name user_%s_%s,%s,%lld,%s existed,not send", user, filetype, fname, size, file_time);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("table name user_%s_%s,%s,%lld,%s not existed,will send", user, filetype, fname, size, file_time);
        bret = false;
    }
    mysqllog.closedb();
    return bret;
#endif
}
/*******************************************************************************************
*功能:       替换字符串中的 ' 为 ''
*参数:       str_old              ---->原字符串
*            str_new              ---->替换后的新字符串存储区
*            返回值               ---->  void
*注释:
*******************************************************************************************/
void ReplaceChar(pchar strold, pchar strnew)
{
    while (*strold) {
        *strnew = *strold;
        if (*strold == '\'') {
            strnew++;
            *strnew = '\'' ;
        }
        strold++;
        strnew++;
    }
    *strnew = *strold;
}

/*******************************************************************************************
*功能:        和目的端建立客户端连接，发送信息，接收信息（中转模式下）
*参数:         dirmsg                       ---->  任务信息
*             msg                          ---->  存储信息
*             recvmsg                      ---->  应回复信息，NULL无回复信息
*             clidest                      ---->  目的端socket类对象指针
*             返回值                        ---->  false失败
*注释:
*******************************************************************************************/
bool SuSendRecvT(DIRMSG *dirmsg, pchar msg, pchar recvmsg, CSUSOCKET *clidest)
{
    if (is_strempty(msg)) return false;
    PRINT_DBG_HEAD;
    print_dbg("Send msg = %s", msg);

    if (!clidest->suopen(dirmsg->ip2, dirmsg->port2, SOCKET_CLIENT, SOCKET_TCP)) {
        return false;
    }

    clidest->settimeout(TIMEOUT);
    int32 len = clidest->writesocket(msg, strlen(msg));
    if (len != strlen(msg)) {
        PRINT_ERR_HEAD;
        print_err("Send msg(%s) failed!", msg);
        return false;
    }
    if (recvmsg != NULL) {

        CHAR recv[MAX_MSGSIZE] = {0};
        clidest->readsocket(recv, sizeof(recv));
        PRINT_DBG_HEAD;
        print_dbg("Recv msg = %s", recv);
        if (strcmp(recv, recvmsg) != 0) return false;
    }
    return true;

}


/*******************************************************************************************
*功能:       中转文件处理
*参数:       dirmsg                         ---->  任务信息
*            dirpath                        ---->  下载目录
*            返回值                         ---->  false失败
*注释:
*******************************************************************************************/

bool TranFile(DIRMSG *dirmsg, pchar dirpath)
{
    vector<FILELIST> vec;
    vector<FILELIST>::iterator it;
    int32 k = GetList(dirmsg, dirpath, &vec);
    if (k < 0) {
        return false;
    } else if (k == 0) {    //空目录
        return true;
    }

    bool bret = true;
    CHAR newdirpath[_FILEPATHMAX] = {0};
    for (it = vec.begin(); it != vec.end(); it++) {
        if (it->ifdir == FLODERSYMBOL) {

            make_filepath(dirpath, it->filename, newdirpath);
            if (dirmsg->dellcl != SAMEFILE) {
                bret = PutDirT(dirmsg, newdirpath);                               //创建服务器2端目录
            } else {
                if (!SelectData(DBFOLDER, newdirpath, 1ULL, it->filesize, dirmsg->user, dirmsg->db)) {
                    PutDirParent(dirmsg, strchr(newdirpath, '/'));
                    //bret = PutDirT(dirmsg, newdirpath);
                    InsertData(DBFOLDER, newdirpath, 1ULL, it->filesize, dirmsg->user, dirmsg->db);
                }
            }
            bret = TranFile(dirmsg, newdirpath);        //回调

            CHAR sendmsg[MAX_MSGSIZE] = {0};
            MySprintf(sendmsg, strcmd_(DEL), newdirpath);
            if (dirmsg->dellcl != SAMEFILE) {
                bret = SuSendRecv(dirmsg, sendmsg, RET_PREPARE_OK);        //删除对端文件
            }
        } else {
            make_filepath(dirpath,  it->filename, newdirpath);

            if ((cfgmsg.bkeywordswitch)
                && (SelectData(DBKEYFILE, newdirpath, it->lastchangetime, it->filesize, dirmsg->user, dirmsg->db))) { //包含关键字文件检查
                PRINT_DBG_HEAD;
                print_dbg("%s have keyword, not send !\n", newdirpath);
                continue;
            }

            if (!FilterName(dirmsg, it->filename)) {           //文件后缀名过滤
                if (dirmsg->iflog) {
                    CHAR remarkinfo[_FILENAMEMAX] = {0};
                    snprintf(remarkinfo, sizeof(remarkinfo), "%s", strchr(newdirpath, '/'));
                    CLOGMANAGE filtersql;
                    filtersql.Init();
                    CHAR port[8] = {0};
                    CHAR port2[8] = {0};
                    sprintf(port, "%d", dirmsg->intport);
                    sprintf(port2, "%d", dirmsg->outport2);
                    filtersql.WriteFilterLog(dirmsg->taskname, it->filename, TRANFILTERFORBID, PRIVATEMOD, dirmsg->intip, dirmsg->outip, port, port2, "I");
                    filtersql.DisConnect();
                }
                continue;
            }
#if 0
            if ((time(NULL) - it->lastchangetime) < dirmsg->deadline) { //过滤文件最后修改时间和现在的时间差
                PRINT_DBG_HEAD;
                print_dbg("%s lead time:%lld < deadline:%d , not send !  \n", newdirpath, (time(NULL) - it->lastchangetime), dirmsg->deadline);
                continue;
            } else {
                PRINT_DBG_HEAD;
                print_dbg("%s lead time:%lld > deadline:%d , will send ! \n", newdirpath, (time(NULL) - it->lastchangetime), dirmsg->deadline);
            }
#endif
            if (dirmsg->dellcl == SAMEFILE) {
                if (SelectData(DBCOMMONFILE, newdirpath, it->lastchangetime, it->filesize, dirmsg->user, dirmsg->db)) { //增量传输检查
                    continue;
                } else {
                    pchar parentpath = strchr(dirpath, '/');
                    if (parentpath != NULL) {
                        PutDirParent(dirmsg, parentpath);
                        PRINT_DBG_HEAD;
                        print_dbg("PutDirParent = %s ", parentpath);
                    } else {
                        PRINT_DBG_HEAD;
                        print_dbg("dirpath = %s ", dirpath);
                    }
                }
            }

            //start  这几步关联性较强,如果需要从这几个步骤中返回，需要释放内存，清除文件池文件，释放信号量
            if (ChkSndingFile(dirmsg->id, newdirpath, true)) continue;        //防止多线程发送同一文件

            THDARG *threadmsg = CtrlThdNum(dirmsg , newdirpath , it->filename, it->filesize, it->lastchangetime); //控制线程数
            if (threadmsg == NULL) {
                ChkSndingFile(dirmsg->id, newdirpath, false);
                continue;
            }

            pthread_t tid;
            if (pthread_create(&tid, NULL, DealThread, threadmsg) != 0) {
                PRINT_ERR_HEAD;
                print_err("Create thread failed");
                sem_post(&cfgmsg.sem[dirmsg->id]);
                free(threadmsg);
                threadmsg = NULL;
                bret = false;
            } else {
                bret = true;
                PRINT_DBG_HEAD;
                print_dbg("Detach thread, tid = %d\n", tid);
            }
            //end
        }
    }
    return bret;
}
/*******************************************************************************************
*功能:       线程处理函数，把结构体指针中的数据传给中转处理函数
*参数:       arg                         ---->    结构体指针
*           返回值                        ---->    NULL
*注释:
*******************************************************************************************/
void *DealThread(void *arg)
{
    THDARG *threadmsg = (THDARG *)arg;
    bool bret = false;
    CSUSOCKET cli_p;                                              //服务器1端对象
    CSUSOCKET cli_t;                                              //服务器2端对象
    CHAR keywordvalret[128] = {0};
    CLOGMANAGE logsql;
    logsql.Init();

    pthread_mutex_lock(&cfgmsg.prithdmut);
    cfgmsg.pristat[threadmsg->dirmsg->priority] += 1;
    pthread_mutex_unlock(&cfgmsg.prithdmut);
    pthread_setself("sync_th");

    //接受服务器1端的消息并转发给服务器2端
    bret = RecvTranFile(threadmsg->dirmsg, &cli_p, &cli_t, threadmsg->newdirpath, keywordvalret);

    if (strlen(keywordvalret) != 0) {
        if (threadmsg->dirmsg->iflog) {
            CHAR port[8] = {0};
            CHAR port2[8] = {0};
            sprintf(port, "%d", threadmsg->dirmsg->intport);
            sprintf(port2, "%d", threadmsg->dirmsg->outport2);
            CHAR fname[_FILEPATHMAX] = {0};
            CHAR remarkinfo[_FILENAMEMAX] = {0};

            if ((get_sucharset(keywordvalret) == CHARSET_GBK)) snprintf(remarkinfo, sizeof(remarkinfo), "%s:%s", HAVEKEYWORD_GBK, keywordvalret);
            else snprintf(remarkinfo, sizeof(remarkinfo), "%s:%s", HAVEKEYWORD_UTF8, keywordvalret);

            logsql.WriteFilterLog(threadmsg->dirmsg->taskname, threadmsg->filename, remarkinfo, PRIVATEMOD,
                                  threadmsg->dirmsg->intip, threadmsg->dirmsg->outip, port, port2, "I");
        }
        InsertData(DBKEYFILE, threadmsg->newdirpath, threadmsg->filetime, threadmsg->filesize,
                   threadmsg->dirmsg->user, threadmsg->dirmsg->db);
        PRINT_DBG_HEAD;
        print_dbg("file=%s include keyword[%s] notsend", threadmsg->newdirpath, keywordvalret);
    } else if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("ip=%s to ip2=%s RecvTranFile of %s  success !",
                  threadmsg->dirmsg->ip, threadmsg->dirmsg->ip2, threadmsg->filename );
    }  else {
        PRINT_ERR_HEAD;
        print_err("ip=%s to ip2=%s RecvTranFile of %s  failed !",
                  threadmsg->dirmsg->ip, threadmsg->dirmsg->ip2, threadmsg->filename );
    }

    if (threadmsg->dirmsg->dellcl != SAMEFILE) {                         //判断模式，决定是否删除服务器1端文件
        if (bret) {
            CHAR tmpbuf[MAX_MSGSIZE] = {0};
            MySprintf(tmpbuf, strcmd_(DEL), threadmsg->newdirpath);
            if (SuSendRecv(threadmsg->dirmsg, tmpbuf, RET_PREPARE_OK, &cli_p)) {  //删除对端文件
                PRINT_DBG_HEAD;
                print_dbg("Delete source server file success filepath=%s", threadmsg->newdirpath);
            } else {
                PRINT_ERR_HEAD;
                print_err("Delete source server file failed! filepath=%s", threadmsg->newdirpath);
            }
        } else {
            PRINT_ERR_HEAD;
            print_err("DealThread Tranfunc failed! filepath=%s", threadmsg->newdirpath);
        }
    } else {
        if (bret) {
            InsertData(DBCOMMONFILE, threadmsg->newdirpath, threadmsg->filetime, threadmsg->filesize,
                       threadmsg->dirmsg->user, threadmsg->dirmsg->db);
        } else {
            PRINT_ERR_HEAD;
            print_err("DealThread Tranfunc failed! filepath=%s", threadmsg->newdirpath);
        }
    }

    if (threadmsg->dirmsg->iflog) {
        CHAR sqldirpath[_FILEPATHMAX] = {0};
        split_filepath(strchr(threadmsg->newdirpath, '/'), sqldirpath, NULL);
        logsql.WriteFileSyncLog(threadmsg->dirmsg->id, threadmsg->dirmsg->taskname, dirmsg->intip, dirmsg->outip,
                                sqldirpath, sqldirpath, threadmsg->filename, bret ? PRI_SUCCESS : PRI_FAILED, "", dirmsg->area);

    }

    logsql.DisConnect();
    SHUTDOWN(cli_p);
    SHUTDOWN(cli_t);

    if (sem_post(&cfgmsg.sem[threadmsg->dirmsg->id]) != 0) {
        PRINT_ERR_HEAD;
        print_err("sem_post failed(%s)", strerror(errno));
    }

    pthread_mutex_lock(&cfgmsg.prithdmut);
    cfgmsg.pristat[threadmsg->dirmsg->priority] -= 1;
    pthread_mutex_unlock(&cfgmsg.prithdmut);

    ChkSndingFile(threadmsg->dirmsg->id, threadmsg->newdirpath, false);   //从数组中剔除发送完成的文件
    free(threadmsg);
    threadmsg = NULL;
    return NULL;
}
/*******************************************************************************************
*功能:       接收并转发消息
*参数:        dirmsg                     ---->    任务信息
*            cli_p                      ---->    源服务器端对象指针
*            cli_t                      ---->    目的服务器端对象指针
*            userfilename               ---->    用户名+下载路径+文件名
*            keywordvalret              ---->    关键字过滤返回值
*            返回值                      ---->    true 成功
*注释:
*******************************************************************************************/
bool RecvTranFile(DIRMSG *dirmsg, CSUSOCKET *cli_p, CSUSOCKET *cli_t, const pchar userfilename, pchar keywordvalret)
{

    CHAR sendmsg[MAX_MSGSIZE] = {0};
    uint8 filebuf[MAX_FILESIZE] = {0};
    int32 len = 0;
    uint64 filesize = 0;
    uint64 readcnt = 0;
    bool bret = false;

    MySprintf(sendmsg, strcmd_(RFILE), userfilename);
    bret = SuSendRecv(dirmsg, sendmsg, NULL, cli_p);                                 //发送下载命令到服务器源端

    if (bret) {
        len = cli_p->readsocket(filebuf, sizeof(filebuf));                           //读取源服务器发来文件的大小信息

        if (len != -1) {                                                             //重组从源服务器接收到的文件大小信息
            filesize = atoll((const pchar)filebuf);
            len = sizeof(filesize);
            memcpy(filebuf, &filesize, len);
            bret = true;
            PRINT_DBG_HEAD;
            print_dbg("Recv filesize = %lld,len = %d", filesize, len);
        } else {
            PRINT_ERR_HEAD;
            print_err("Recv filesize = -1 ,failed!");
            bret = false;
        }
    }


    MySprintf(sendmsg, strcmd_(SFILE), userfilename);                                //拼接发送文件命令
    if (bret && (!SuSendRecvT(dirmsg, sendmsg, RET_PREPARE_OK, cli_t))) {            //发送创建文件消息到目的服务器端
        PRINT_ERR_HEAD;
        print_err("TranFile %s  failed!", sendmsg);
        bret = false;
    }

    if (bret && (cli_t->writesocket(filebuf, len) == len)) {                          //把文件大小信息转发给目的服务器
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("Send len=%d filesize=%lld to server2 success", len, filesize);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("Send len=%d filesize=%lld to server2 failed!", len, filesize);
    }

    if (bret && ((len = cli_t->readsocket(filebuf, sizeof(filebuf))) > 0)) {          //检测空文件
        bret = (memcmp((const pchar)filebuf, RET_FILE_OK, strlen(RET_FILE_OK)) == 0);
        if (filesize == 0) {
            PRINT_DBG_HEAD;
            print_dbg("Send null file %s", userfilename);
            cli_p->writesocket(RET_FILE_END, strlen(RET_FILE_END));
            return true;
        }
    }

    if (bret) {
        uint32 packcnt = 0;
        len = cli_p->writesocket(RET_FILE_OK, strlen(RET_FILE_OK));                   //向源服务器发送接收数据的消息
        int32 i, k;

        vector<string>::iterator it;
        while (bret && ((i = cli_p->readsocket(filebuf, sizeof(filebuf))) > 0)) {     //接收文件数据

            if (cfgmsg.bkeywordswitch) {                                              //关键字过滤功能
                for (it = cfgmsg.keyvec.begin(); it != cfgmsg.keyvec.end(); it++) {
                    if (FindStr((pchar)filebuf, (pchar)(*it).c_str(), 0, i)) {
                        strcpy(keywordvalret, (*it).c_str());
                        PRINT_DBG_HEAD;
                        print_dbg("have keyword %s,will return", (*it).c_str());
                        return false;
                    }
                }
            }

            k = cli_t->writesocket(filebuf, i);                                       //把数据发送给目的服务器

            if (k != i) {
                PRINT_ERR_HEAD;
                print_err("RecvTranFile failed, readsize = %d writesize = %d!", i, k);
                bret = false;
            }

            readcnt += i;
            if (readcnt >= filesize)  break;

            if (cfgmsg.priswth != 0) {                                                //线程优先级控制
                packcnt++;
                if (CtrlThdPri(dirmsg, packcnt)) packcnt = 0;
            }
        }

        if (readcnt != filesize) {
            PRINT_ERR_HEAD;
            print_err("RecvTranFile failed, recvtransize = %lld filesize = %lld!", readcnt, filesize);
            bret = false;
        }

        if (bret) {
            if ((len = cli_t->readsocket(filebuf, sizeof(filebuf))) > 0) {
                bret = (memcmp((const pchar)filebuf, RET_FILE_END, len) == 0);
                PRINT_DBG_HEAD;
                print_dbg("Send file %s success", userfilename);
            } else {
                PRINT_ERR_HEAD;
                print_err("Send file %s failed", userfilename);
                bret = false;
            }
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("Tran file %s %s", userfilename, (bret ? "success" : "failed"));
    cli_p->writesocket(RET_FILE_END, strlen(RET_FILE_END));
    return bret;
}

/*******************************************************************************************
*功能:        发送创建目录命令
*参数:        dirmsg                      ---->  任务信息
*             filepath                    ---->  远端路径
*             返回值                      ---->  false失败
*注释:
*******************************************************************************************/
bool PutDirT(DIRMSG *dirmsg, pchar filepath)
{
    CHAR recvmsg[MAX_MSGSIZE] = {0};
    CHAR sendmsg[MAX_MSGSIZE] = {0};
    bool bret;
    MySprintf(recvmsg, strcmd_(MKDIR), MKDIROK);
    MySprintf(sendmsg, strcmd_(MKDIR), filepath);
    bret = SuSendRecvT(dirmsg, sendmsg, recvmsg, &(dirmsg->cli_t));
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("Makedir %s success !", filepath);
    } else {
        PRINT_ERR_HEAD;
        print_err("Makedir %s failed !", filepath);
    }
    SHUTDOWN(dirmsg->cli_t);

    return bret;
}
/*******************************************************************************************
*功能:         创建多级目录到目的端服务器（为了兼容windows）
*参数:         dirmsg                     ---->  任务信息
*             filepath                   ---->  路径
*             返回值                      ---->  true成功 false失败
*注释:
*******************************************************************************************/
void PutDirParent(DIRMSG *dirmsg, const pchar filepath)
{
    CHAR path[_FILEPATHMAX] = {0};                                //目标文件夹路径
    pchar p_path = NULL;                                          //目标文件夹路径指针
    CHAR tmp_path[_FILEPATHMAX] = {0};                            //存放临时文件夹路径
    pchar p_tmp = NULL;                                           //单级文件夹名称
    CHAR mkdircmd[_FILEPATHMAX] = {0};                            //创建文件夹的命令

    strcpy(path, filepath);
    p_path = path;

    while ((p_tmp = strsep(&p_path, "/")) != NULL) {             //拆分路径
        if (0 == *p_tmp) {
            continue;
        }
        strcat(tmp_path, "/");
        strcat(tmp_path, p_tmp);                                  //每次分割出的路径都要拼接在tmp_path后
        sprintf(mkdircmd, "%s%s", dirmsg->user, tmp_path);
        PutDirT(dirmsg, mkdircmd);
    }

}
/*******************************************************************************************
*功能:        过滤文件
*参数:        dirmsg                      ---->  任务信息
*            filename                    ---->  文件名
*            返回值                       ---->  true 发送 , false 不发送
*注释:
*******************************************************************************************/
bool FilterName(DIRMSG *dirmsg, const pchar filename)
{
    //过滤处理 1：白名单    2：黑名单
    if ((dirmsg->ckfilterfiles == 1) || (dirmsg->ckfilterfiles == 2)) {                //进入过滤处理
        CHAR suffix[_FILENAMEMAX] = {0};
        bool filter = true;
        pchar postfix = suffix;
        postfix++;
        int suffixlen = get_filesuffix(filename, suffix);

        bool nosuffix = false;
        if ((suffixlen == 0) && (strchr(dirmsg->filterfiles, '*') != NULL)) { //匹配无后缀名类型
            nosuffix = true;
        }

        if (dirmsg->ckfilterfiles == 1) {
            if ((!filter_filesuffix(dirmsg->filterfiles, postfix, ",")) && (!nosuffix)) filter = false; //白名单中未找到
        } else {
            if (filter_filesuffix(dirmsg->filterfiles,  postfix, ",") || nosuffix) filter = false; //黑名单中存在
        }
        if (filter) {
            PRINT_DBG_HEAD;
            print_dbg("Sendfile = %s , ckfilter=%d,filter=%s", filename, dirmsg->ckfilterfiles, dirmsg->filterfiles);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("Not Sendfile = %s ,ckfilter=%d,filter=%s", filename, dirmsg->ckfilterfiles, dirmsg->filterfiles);
        }
        return filter;

    } else {
        return true;
    }

}
/*******************************************************************************************
*功能:        检查是否为正在发送的文件，把此文件放入文件池或从文件池中剔除
*参数:        id                         ---->  任务号（策略号）
*            newdirpath                 ---->  文件路径名称
*            insertdelete               ---->  true 查询正在发送的文件（如果没有就插入newdirpath）
*                                       ---->  false 删除数组中和newdirpath相同的数据
*             返回值                     ---->  false失败
*注释:
*******************************************************************************************/
bool ChkSndingFile(uint32 id, pchar newdirpath, bool insertdelete)
{
#define THDNUM 1000
    static CHAR sendingfile[THDNUM][_FILEPATHMAX] = {{0}};
    CHAR iddirpath[_FILEPATHMAX] = {0};
    bool bret = false;
    int32 i = 0;
    int32 k = 0;

    snprintf(iddirpath, sizeof(iddirpath), "%d/%s", id, newdirpath);
    if (insertdelete) {                         //如果为查找模式
        pthread_mutex_lock(&(cfgmsg.tranmut));
        for (i = 0; i < THDNUM ; i++) {         //查找正在发送的文件池中是否有iddirpath文件
            if (strlen(sendingfile[i]) == 0) k = i;
            if (strcmp(sendingfile[i], iddirpath) == 0) {
                PRINT_DBG_HEAD;
                print_dbg("file = %s is sendingfile , not create thread", sendingfile[i]);
                bret = true;
                break;
            }
        }

        if (!bret) {                        //在文件池中没有找到iddirpath文件，把此文件放入文件池
            strcpy(sendingfile[k], iddirpath);
            PRINT_DBG_HEAD;
            print_dbg("file = %s not sendingfile,will create thread", iddirpath);
        }
        pthread_mutex_unlock(&(cfgmsg.tranmut));
        if (bret) sleep(1);
    } else {                                //如果为删除模式
        pthread_mutex_lock(&(cfgmsg.tranmut));
        for (i = 0; i < THDNUM; i++) {      //在文件池中查找iddirpath文件，把从文件从文件池中剔除
            if (strcmp(sendingfile[i], iddirpath) == 0) {
                memset(sendingfile[i], 0, sizeof(sendingfile[i]));
                bret = true;
                PRINT_DBG_HEAD;
                print_dbg("Delete file pond sendingfile = %s  success", iddirpath);
            }
        }
        pthread_mutex_unlock(&(cfgmsg.tranmut));
    }

    return bret;
}
/*******************************************************************************************
*功能:         控制线程数量，开辟堆内存存储数据
*参数:         dirmsg                     ---->  任务信息
*             newdirpath                 ---->  用户名/路径/文件名
*             filename                   ---->  文件名
*             filesize                   ---->  文件大小
*             filetime                   ---->  文件最后修改时间
*             返回值                      ---->  argmsg结构体指针
*注释:
*******************************************************************************************/
THDARG *CtrlThdNum(DIRMSG *dirmsg , pchar newdirpath , pchar filename , int64 filesize, int64 filetime)
{
    bool bret = false;
    THDARG *threadmsg = NULL;
    if (sem_wait(&cfgmsg.sem[dirmsg->id]) != 0) {                //通过信号量控制线程数量
        sem_destroy(&(cfgmsg.sem[dirmsg->id]));
        sem_init(&(cfgmsg.sem[dirmsg->id]), 0 , dirmsg->parnum);
        PRINT_ERR_HEAD;
        print_err("sem_wait failed(%s)", strerror(errno));
    } else {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("sem value sub 1");
    }
    if (bret) {
        threadmsg = (THDARG *)malloc(sizeof(THDARG));   //记录数据到堆区
        if (threadmsg == NULL) {
            bret = false;
            sem_post(&cfgmsg.sem[dirmsg->id]);
            PRINT_DBG_HEAD;
            print_dbg("Malloc(sizeof(THDARG)) failed");
        }
    }

    if (bret) {            //把传入的参数存储到堆内存中
        threadmsg->dirmsg = dirmsg;
        strcpy(threadmsg->newdirpath , newdirpath);
        strcpy(threadmsg->filename , filename);
        threadmsg->filesize = filesize;
        threadmsg->filetime = filetime;
        return threadmsg;
    } else {
        return NULL;
    }
}
/*******************************************************************************************
*功能:         控制线程效率
*参数:         dirmsg                     ---->  任务信息
*             packcnt                    ---->  发包数量
*
*             返回值                      ---->  true 成功
*                                        ---->  false 失败
*注释:
*******************************************************************************************/
bool CtrlThdPri(DIRMSG *dirmsg, uint32 packcnt)
{
    if (packcnt >= 500) {
        if (dirmsg->priority >= cfgmsg.priswth) {
            return true;
        } else {
            uint32 usleeptime =  (0 - ((dirmsg->priority) - 4)) * 100000;
            //uint32 sleeptime = (0 - ((dirmsg->priority) - 4));
            usleep(usleeptime);
            return true;
        }
    }
    return false;
}

/*******************************************************************************************
*功能:         优先级调度线程
*参数:         arg                        ---->  无
*             返回值                      ---->  NULL
*注释:
*******************************************************************************************/
void *ChkSndPri(void *arg)
{
    pthread_setself("priority_th");
    pthread_mutex_init(&cfgmsg.prithdmut, NULL);
    while (1) {
        uint8 sndprinum = 0;
        uint8 maxpri = 0;
        pthread_mutex_lock(&cfgmsg.prithdmut);
        for (int32 i = 0; i < (sizeof(cfgmsg.pristat) / sizeof(cfgmsg.pristat[0])); i++) {               //统计正在发送文件的线程的优先级分布
            if (cfgmsg.pristat[i] != 0) {
                sndprinum++;
                if (i > maxpri) maxpri = i;             //统计优先级最高的线程所处的等级
            }
        }
        pthread_mutex_unlock(&cfgmsg.prithdmut);

        if (sndprinum > 1) {                            //多个线程不在同一优先级，开关设置为优先级最高的线程等级
            cfgmsg.priswth = maxpri;
        } else {
            cfgmsg.priswth = 0;                         //如果线程优先级处于同一等级，关闭优先级开关
        }

        usleep(1000);
    }

    pthread_mutex_destroy(&cfgmsg.prithdmut);
    return NULL;
}

























/*******************************************************************************************
*功能:        读取文本中的关键字（以换行为一个关键字）
*参数:       keywordfilepath_gbk                 ---->  文件路径名称
*           keywordfilepath_utf8                ---->  文件路径名称
*           keyvec                              ---->  存储关键字的容器
*
*           返回值                                 ---->  true 成功
*                                                ----> false 失败
*注释:
*******************************************************************************************/
bool ReadKey(pchar keywordfilepath_gbk, pchar keywordfilepath_utf8, vector<string> *keyvec)
{
    //审查关键字最大长度
#define MAX_FILTER_KEY_LEN 90

    keyvec->clear();

    CHAR buf[1024] = {0};
    CHAR buf_o[1024] = {0};

    //打开文件
    FILE *fp_gbk = fopen(keywordfilepath_gbk, "rb");
    if (fp_gbk == NULL) {
        PRINT_ERR_HEAD;
        print_err("open keyword failed:(%s) error:(%s)", keywordfilepath_gbk, strerror(errno));
        return false;
    }

    //循环读取
    while ((fgets (buf, sizeof(buf), fp_gbk)) != NULL) {
        strstrip_(buf, NULL, buf_o);

        if (strlen(buf_o) > MAX_FILTER_KEY_LEN) {

        } else {
            keyvec->push_back(string(buf_o));
        }
        memset(buf, 0, sizeof(buf));
        memset(buf_o, 0, sizeof(buf_o));
    }

    //关闭文件
    fclose(fp_gbk);

    FILE *fp_utf8 = fopen(keywordfilepath_utf8, "rb");
    if (fp_utf8 == NULL) {
        PRINT_ERR_HEAD;
        print_err("open keyword failed:(%s) error:(%s)", keywordfilepath_utf8, strerror(errno));
        return false;
    }

    //循环读取
    while ((fgets (buf, sizeof(buf), fp_utf8)) != NULL) {
        strstrip_(buf, NULL, buf_o);

        if (strlen(buf_o) > MAX_FILTER_KEY_LEN) {

        } else {
            keyvec->push_back(string(buf_o));
        }
        memset(buf, 0, sizeof(buf));
        memset(buf_o, 0, sizeof(buf_o));
    }

    //关闭文件
    fclose(fp_utf8);

    return true;
}

/*******************************************************************************************
*功能:        判断str1从posbegin到posend之间是否存在str2
*参数:        str1                        ---->  字符串1
*            str2                        ---->  字符串2
*            posbegin                    ---->  开始比较的位置
*            posend                      ---->  结束比较的位置
*            返回值                       ---->  true 找到
*                                        ---->  false 没找到
*注释:
*******************************************************************************************/
bool FindStr(const pchar str1, const pchar str2, int32 posbegin, int32 posend)
{
    int32 len2 = strlen((pchar)str2);
    if (len2 == 0) {
        return true;
    }
    if (len2 > (posend - posbegin)) {
        return false;
    }
    for (int32 i = posbegin; i <= (posend - len2); i++) {
        if (strncasecmp((pchar)(str1 + i), (pchar)str2, len2) == 0) {
            return true;
        }
    }
    return false;
}
