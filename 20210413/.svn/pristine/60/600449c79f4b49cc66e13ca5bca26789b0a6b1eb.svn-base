/*******************************************************************************************
*文件:  FCHotBakMain.h
*描述:  热备主程序类
*作者:  王君雷
*日期:  2016-03
*修改:
*       函数变量命名统一风格;全部使用zlog;热备停止业务时把fileclient进程也杀掉;
*       无参函数加void;使用友元函数;使用基于内存的信号量代替有名信号量  ------> 2018-08-29
*       读取设备ID为空时，会去读取设备唯一码当做设备ID使用              ------> 2018-11-08
*       双机热备协议修改，WEB可以展示更多热备通信状态信息               ------> 2018-11-27
*       联调测试修改后台的双机热备协议，修改策略同步包超长等问题        ------> 2018-12-11
*       设备ID缓冲区长度宏移动到critical.h中                            ------> 2020-02-05
*       添加通过HA工具恢复用户配置功能                                   ------> 2020-09-28
*******************************************************************************************/
#ifndef __FC_HOT_BAK_MAIN_H__
#define __FC_HOT_BAK_MAIN_H__

#include <semaphore.h>
#include "define.h"
#include "struct_info.h"
#include "FCThread.h"
#include "fcpacket.h"
#include "fileoperator.h"

#define HB_RESULT_NUM 10  //心跳结果缓存个数
#define HB_TIMEOUT(a, b) (abs(a - b) > 5) //两数相差5以上认为超时
#define HB_FILE_END   -1
#define HB_FILE_BEGIN 0

//热备结果类型
enum HB_RESULT {
    HB_INVALID = -1,//非法
    HB_OK = 0,      //不切机
    HB_FAIL,        //切机
    HB_TMOUT        //超时
};

#define STATUS_INDEX_NUM 32

//状态信息下标
enum STATUS_INDEX {
    NIC_INDEX = 0, //下标为0的表示网卡状态
};

//写双机热备WEB展示使用的配置文件 用到的信息
typedef struct _hb_conf_file_info {
    int timeout;                         //是否超时了
    char masterid[DEV_ID_LEN];           //主机ID
    int masterrun;                       //主机是否运行
    int masterstatus[STATUS_INDEX_NUM];  //主机状态信息
    char slaveid[DEV_ID_LEN];            //从机ID
    int slaverun;                        //从机是否运行
    int slavestatus[STATUS_INDEX_NUM];   //从机状态信息
} HB_CONF_FILE_INFO, *PHB_CONF_FILE_INFO;

#pragma pack(push, 1)
//热备心跳请求
typedef struct _heart_beat_req {
    char masterid[DEV_ID_LEN];           //主机ID
    char slaveid[DEV_ID_LEN];            //从机ID
    int seqid;                           //顺序号 为了标示心跳和响应的对应关系
    int slaverun;                        //从机是否在运行
    int slavestatus[STATUS_INDEX_NUM];   //从机状态信息
} HEART_BEAT_REQ, *PHEART_BEAT_REQ;

//热备心跳回应头部
typedef struct _heart_beat_res_head {
    HB_RESULT hb_result;                 //心跳结果 是否切机运行等
    int seqid;                           //顺序号 为了标示心跳和响应的对应关系
    int masterrun;                       //主机是否正在运行
    int masterstatus[STATUS_INDEX_NUM];  //主机状态信息
    int nicnum_in;                       //主机使用的内网网卡个数
    int nicnum_out;                      //主机使用的外网网卡个数
} HEART_BEAT_RES_HEAD, *PHEART_BEAT_RES_HEAD;

//主备策略同步时使用的协议头部
typedef struct _hb_rules_transfer {
    int seqnumber;
    int datalen;
    char buff[1000];
} HB_RULES_TRANSFER, *PHB_RULES_TRANSFER;
#pragma pack(pop)

class HotBakManager
{
public:
    HotBakManager(void);
    ~HotBakManager(void);
    int Start(void);
    bool LoadData(void);

private:
    friend void *RecvReport(void *param);
    friend void *ServerProcess(void *param);
    friend void *ClientProcess(void *param);
    friend void *RulesProcess(void *param);
    friend void *WRConfProcess(void *param);

    static bool ReadSerial(char *serial, int len);
    static int WriteSysLog(const char *logtype, const char *result, const char *remark);
    static int SetMac(const PNIC_MAC_STRUCT pnic, int num, bool isout);

    int StopBS(void);
    int StartBS(void);
    int SendRules(void);
    bool MakeInfoString(char *chout, int len);
    bool ReadVersion(const char *fname, char *ver, int size);
    bool HandleNicReport(const char *info, int len);
    void CollectHBConf(HB_CONF_FILE_INFO &info);
    bool WriteConf(void);
    bool HandleSearchDev(void);
    bool HandleInitDev(const char *buff, int len);
    bool HandleGetCtrl(void);
    bool HandleGetInfo(void);
    bool HandleGetRule(const char *buff, int len);
    bool HandleInitUserConf(const char *buff, int len);
    bool HandleHB(const char *buff, int len);
    bool HandleHBResult(const char *buff, int len);
    bool SlaveRulesRequest(void);
    bool SlaveHBRequest(int seqid);
    bool SlaveWaitHBResult(HB_RESULT &result, int seqid);
    void SlaveHandleHBResult(HB_RESULT &result, int &timeout_cnt);
    bool CheckRulesFile(const char *md5str32);
    bool CoverRulesFile(void);
    void PrintHBConfInfo(HB_CONF_FILE_INFO &info);
    bool HandleRulesPacket(HB_RULES_TRANSFER &ruledata, FILE **fd, int &nextid);
    bool SlaveSwitch(bool brun);
    void WriteMasterRunInfo(CFILEOP &fileop);
    void WriteSlaveRunInfo(CFILEOP &fileop);
    void WriteMasterStatusInfo(CFILEOP &fileop);
    void WriteSlaveStatusInfo(CFILEOP &fileop);
    void SetInRoute(void);

private:
    //同步策略不准改变的字段
    char m_csip[IP_STR_LEN];
    char m_csport[PORT_STR_LEN];
    char m_csmask[MASK_STR_LEN];
    char m_mgcliip[IP_STR_LEN];
    int m_ckweblogintx;
    int m_cklineswitch;

    //本机相关字段
    int m_status[STATUS_INDEX_NUM];      //本机状态
    char m_devid[DEV_ID_LEN];            //本机ID
    bool m_b_master;                     //本机是否为主机
    int m_run;                           //本机sys6是否被拉起运行了
    int m_nicnum_in;                     //本机内网使用的网卡数
    int m_nicnum_out;                    //本机外网使用的网卡数
    NIC_MAC_STRUCT m_nicin[MAX_NIC_NUM]; //本机内网使用的网卡详情
    NIC_MAC_STRUCT m_nicout[MAX_NIC_NUM];//本机外网使用的网卡详情
    time_t m_lasthb_req;                 //本机最后一次接收到心跳请求的时间
    time_t m_lasthb_res;                 //本机最后一次接收到心跳回应的时间

    //上级相关字段
    int m_masterstatus[STATUS_INDEX_NUM];       //上级状态
    char m_masterid[DEV_ID_LEN];                //上级主机的ID号
    int m_masterrun;                            //上级主机是否在运行
    int m_master_nicnum_in;                     //上级主机内网使用的网卡数
    int m_master_nicnum_out;                    //上级主机外网使用的网卡数
    NIC_MAC_STRUCT m_master_nicin[MAX_NIC_NUM]; //上级主机内网使用的网卡详情
    NIC_MAC_STRUCT m_master_nicout[MAX_NIC_NUM];//上级主机外网使用的网卡详情

    //下级相关字段
    int m_slavestatus[STATUS_INDEX_NUM];        //下级状态
    char m_slaveid[DEV_ID_LEN];                 //下级设备ID
    int m_slaverun;                             //下级是否在运行

    //其他字段
    bool m_b_tran_rule;                       //是备机时 是否向主机请求传输策略文件
    int m_tran_rule_cycle;                    //请求传输策略文件周期 单位分钟
    int m_hotbaklan;                          //热备口网卡号
    char m_inner_devtype[11];                 //内部设备类型
    int m_maxheartfail;                       //热备连续超时多少次切机
    HB_RESULT m_heartbeat_res[HB_RESULT_NUM]; //存放心跳回应结果用
    HB_CONF_FILE_INFO m_hbconf;               //存放写热备配置文件使用的信息

    int m_workflag;                           //工作模式

    CThread *m_report_th;
    CThread *m_server_th;
    CThread *m_client_th;
    CThread *m_rules_th;
    CThread *m_wrconf_th;
    CPACKET *m_cpack;

    sem_t m_heartbeat_sem; //服务端线程和客户端线程之间心跳回应通知用
    sem_t m_wrconf_sem;    //状态发送改变时 用于通知写配置文件的线程 重写配置文件
};

void *RecvReport(void *param);
void *ServerProcess(void *param);
void *ClientProcess(void *param);
void *RulesProcess(void *param);
void *WRConfProcess(void *param);

#endif
