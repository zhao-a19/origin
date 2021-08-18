/*******************************************************************************************
*文件:    fileclient.h
*描述:
*
*作者:    张昆鹏
*日期:    2016-12-02
*修改:    创建文件                            ------>     2016-12-02
*         修改代码规范                        ------>     2016-12-27
*         增加UDP和TCP与服务器通信模式        ------>     2017-07-29
*
*作者:    宋宇
*日期:    2018-08-15
*修改:    增加增量传输功能                    ------>     2018-08-15
*         增加服务器间文件同步功能             ------>     2018-09-10
*         增加关键字过滤功能                  ------>      2018-11-03
*         增加编码格式转换函数                 ------>     2018-11-06
*         增加文件同步中的多线程功能            ------>     2018-11-16
*         修改bug，精简代码                   ------>     2018-11-21
*         增加创建多级目录函数                  ----->     2018-12-07
*         解决增量传输时对于文件夹的创建的bug（目的端为windows时）
*         增加id表字段,增大文件大小字段上限      ------>     2018-12-10
*         添加增量传输时写文件夹信息表           ------>     2018-12-11
*         优化函数执行顺序                    ------>     2018-12-12
*         增加TranFile函数及有关函数的错误处理
*         修改由于空指针引起的bug              ------>     2018-12-18
*******************************************************************************************/

#ifndef FILECLIENT_H
#define FILECLIENT_H

#include <vector>
#include <semaphore.h>
#include <iostream>
#include <iconv.h>
#include "trandesc.h"
#include "../clientsec.h"
#include "./libsqlite/sqlite3.h"
#include "../../FCLogManage.h"
#ifdef __cplusplus
extern "C" {

#endif

#define MAX_DIRNUM 10
#define MODELSIZE 5
#define IPSIZE  64
#define PARMAXNUM  100                          //并发文件最大数量
#define DBCOMMONFILE "commonfile"
#define DBKEYFILE "keyfile"
#define DBFOLDER "folder"
#define KEYUTF8           "/var/self/rules/conf/KeyUTF.cfg"

struct {
    uint16 port;                                //目的端口
    uint8 dirnum;                               //用户数
    CHAR logpath[_FILEPATHMAX];                 //记录本地日志目录
    CHAR tmppath[_FILEPATHMAX];                 //存放临时文件目录
    CHAR model[MODELSIZE];                      //PUT上传, 其他下载
    CHAR dbpath[_FILEPATHMAX];                  //数据库路径   songyu
    sem_t sem[MAX_DIRNUM];                      //控制线程数信号量
    pthread_mutex_t tranmut;                    //控制正在发送文件池
    pthread_mutex_t prithdmut;                  //控制线程优先级
    bool blogswitch;                            //全局日志开关
    bool bkeywordswitch;                        //关键字过滤开关
    uint16 pristat[5];                          //记录线程优先级状态
    uint8 priswth;                              //线程优先级开关
    vector<string> keyvec;                      //关键字过滤类容器
} cfgmsg;

typedef struct DIRMSG {                         //任务信息
    uint8 id;                                   //标识符
    char taskname[256];                         //任务名
    CSUSOCKET cli_p;                            //源端服务器对象
    CSUSOCKET cli_t;                            //目的端服务器对象
    FILE *fp;
    int32 sync;                                 //检测周期
    bool iflog;                                 //是否记录本地日志    false不记录
    CHAR logdate[MAX_TIME];                     //日志记录日期
    int32 deadline;                             //期限   单位 秒 ， 默认最低为 1 秒
    CHAR ip[IPSIZE];                            //目的地址
    CHAR ip2[IPSIZE];                           //目的地址
    CHAR intip[IPSIZE];
    CHAR outip[IPSIZE];
    uint16 port;                                //目的端口
    uint16 port2;                               //目的端口
    uint16 intport;                                //目的端口
    uint16 outport2;                               //目的端口
    uint16 mode;                                //传输模式 0:tcp-光闸  1:udp模式   2:tcp-pc模式
    int32 senddly;                              //udp模式发送延时
    int16 sendnum;                              //udp模式发送包次数
    int32 sendchk;                              //udp模式校验参数
    CHAR user[MAX_USERLEN];                     //任务账号
    CHAR dirpath[_FILEPATHMAX];                 //本地上传/下载目录
    CHAR bakpath[_FILEPATHMAX];                 //备份目录
    int32 dellcl;                               //是否处理本地文件 参见DELLCL 0 1 2 3 4， 其它：保留所有
    int32 priority;                             //优先级0-8范围
    CHAR  tmpfile[_FILENAMEMAX];                //临时后缀名
    int32 ckfilterfiles;                        //黑白名单
    CHAR filterfiles[500];                      //后缀名
    int32 parnum;                               //并行文件数量  默认为0，为0不开启并行
    int32 retdir;                               //保留目录级数
    int32 dirdepth;                             //目录深度
    int32 sqlmode;                              //默认0关闭   仅有1开启查询数据库传输文件
    CHAR sqladdr[MAX_TIME];
    CHAR sqlname[MAX_TIME];
    CHAR sqlpwd[MAX_TIME];
    CHAR sqldb[MAX_TIME];
    int32 sqlport;
    sqlite3 *db ;                               //sqlite数据库文件句柄  songyu
    int32 area;                                 //同步方向      songyu
} DIRMSG;

enum DELLCL {
    DELALL = 0,                                 //删除所有
    MVALL,                                      //移走所有
    DELSAVE,                                    //删除文件但保留目录
    MVSAVE,                                     //移走文件但保留目录
    SAMEFILE                                    //增量传输
};

typedef struct FILELISTNODE {
    CHAR ifdir;                                 //是否为目录
    CHAR filename[_FILENAMEMAX];                //文件名
    int64 filesize;                             //文件大小
    CHAR shortname[_FILENAMEMAX];               //文件短文件名
    int64 lastchangetime;                      //文件最后修改时间
} FILELIST;

typedef struct {
    DIRMSG *dirmsg;
    CHAR newdirpath[_FILEPATHMAX];
    CHAR filename[_FILENAMEMAX];
    int64 filesize;
    int64 filetime;
} THDARG;

bool ReadConfig(pchar config);
bool ReadConfig_(DIRMSG *dirmsg, pchar config);
bool SuSendRecv(DIRMSG *dirmsg, pchar msg, pchar recvmsg = NULL, CSUSOCKET *tmp = NULL);
bool ReadDir(DIRMSG *dirmsg, pchar remotepath, pchar localpath, pchar bakpath);
bool PutFile(DIRMSG *dirmsg, pchar remotepath, pchar filename, pint32 is_filter, SYSDBSQL *dbsql = NULL);
bool PutDir(DIRMSG *dirmsg, pchar filepath);
bool RecordSFile(DIRMSG *dirmsg, pchar filepath, pchar filename, int64 size, CHAR ifdir);
bool RecordCallLOG(DIRMSG *dirmsg, const pchar result, pchar info);
bool RecordFileLog(DIRMSG *dirmsg, pchar event, pchar process, bool bret);
bool GetFile(DIRMSG *dirmsg, pchar dirpath, pchar remotepath);
int32 GetList(DIRMSG *dirmsg, pchar remotepath, vector<FILELIST> *vec);
bool RecordSFileX(DIRMSG *dirmsg, pchar filepath, pchar filename, int64 size, CHAR ifdir);
void *PutorGetProcess(void *param);
bool renames(pchar srcpath, pchar dstpath);
//songyu add start
bool CreateDB(const pchar dbpath, DIRMSG *dirmsg, sqlite3 **db);
bool CreateTable(const pchar filetype, const pchar user, sqlite3 *db);
bool InsertData(const pchar filetype, const pchar fname, int64 lastchangetime, int64 size, const pchar user, sqlite3 *db);
bool SelectData(const pchar filetype, const pchar fname, int64 lastchangetime, int64 size, const pchar user, sqlite3 *db);
void ReplaceChar(const pchar str_old, pchar str_new);

bool SuSendRecvT(DIRMSG *dirmsg, pchar msg, pchar recvmsg, CSUSOCKET *clidest);
bool PutDirT(DIRMSG *dirmsg, pchar filepath);
void PutDirParent(DIRMSG *dirmsg, const pchar filepath);
bool TranFile(DIRMSG *dirmsg, pchar dirpath);
void *DealThread(void *arg);
bool RecvTranFile(DIRMSG *dirmsg, CSUSOCKET *cli_p, CSUSOCKET *cli_t, const pchar userfilename, pchar keywordvalret = NULL);
bool FilterName(DIRMSG *dirmsg, const pchar filename);
bool ChkSndingFile(uint32 id, pchar newdirpath, bool insertdelete);
THDARG *CtrlThdNum(DIRMSG *dirmsg , pchar newdirpath , pchar filename , int64 filesize, int64 filetime);
bool CtrlThdPri(DIRMSG *dirmsg, uint32 packcnt);
void *ChkSndPri(void *arg);

bool ReadKey(pchar keywordfilepath_gbk, pchar keywordfilepath_utf8, vector<string> *keyvec);
bool FindStr(const pchar str1, const pchar str2, int32 posbegin, int32 posend);
//songyu end
#ifdef __cplusplus
}
#endif

#endif
