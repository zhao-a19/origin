/*******************************************************************************************
*文件:    sip_tasks.cpp
*描述:    SIP服务任务
*
*作者:    张冬波
*日期:    2018-04-20
*修改:    创建文件                          ------>     2018-04-20
*         修改清除操作，调用外部脚本        ------>     2018-04-23
*         添加文件记录功能                  ------>     2018-04-24
*         修改程序，在网闸中使用            ------>     2018-07-19 王君雷
*         网闸开通道，把包含通道也打开      ------>     2018-07-24
*         添加函数sipdel                    ------>     2018-08-02
*         可以设置线程名称                   ------> 2021-02-23
*******************************************************************************************/
#include <pthread.h>
#include <errno.h>
using namespace std;
#include <vector>

#include "datatype.h"
#include "sip_tasks.h"
#include "debugout.h"
#include "syssocket.h"
//#include "platform.h"
#include "sip_record.h"
//#include "sysdir.h"
#include "FCPeerExecuteCMD.h"

typedef struct _sipnew {
    CSYSSOCKET *onetcp;
    psip_task task;

} sipnew, *psipnew;

/**
 * [sip_taskfunc 视频控制服务]
 * @param  arg [配置规则]
 * @return     [description]
 */
static void *_sipfunc_(void *arg);
static void *sip_taskfunc(void *arg)
{
    psip_task task = (psip_task)arg;

    //资源自动回收
    pthread_setself("gapsip_tasks");

    CSYSSOCKET onetcp(SOCKET_TCP, false);
    onetcp.setaddress(task->srvip, task->srvport);
    onetcp.setconnect(SOCKET_SRV);

    do {
        if (onetcp.getconnect()) {
            pthread_t tid;
            psipnew sip = (psipnew)malloc(sizeof(sipnew));
            sip->onetcp = new CSYSSOCKET(onetcp);
            sip->task = task;

            if (pthread_create(&tid, NULL, _sipfunc_, (void *)sip) != 0) {
                PRINT_ERR_HEAD;
                print_err("SIP Error addr = %s:%s", task->srvip, task->srvport);
                delete sip->onetcp;
                free(sip);
            }
        } else {
            break;
        }
    } while (1);

    PRINT_ERR_HEAD;
    print_err("SIP TASK addr = %s:%s", task->srvip, task->srvport);
    return NULL;
}

/**
 * [sip_createtask 视频控制服务]
 * @param  sip_arg [配置规则]
 * @return         [-1 失败]
 */
int32 sip_createtask(psip_task sip_arg)
{
    if (sip_arg == NULL) { return -1; }

    pthread_t tid;
    PRINT_DBG_HEAD;
    print_dbg("SIP TASK addr = %s:%s", sip_arg->srvip, sip_arg->srvport);
    return pthread_create(&tid, NULL, sip_taskfunc, (void *)sip_arg);
}

//注意：与网闸配置一致
enum {
    SIP_TST = 1,
    SIP_CLR,
    SIP_ADD,
    SIP_DEL,
};
#pragma pack(push, 1)
typedef struct  _sipdata {
    uint8 head[32];
    uint32 version;
    uint32 id;
    uint32 cmd;
    union {
        uint32 ack;
        uint32 length;
    };
} SIPDATA, *PSIPDATA;

typedef struct _sipdatax {
    char name[64];
    char recvip[16];    //光闸接收IP:PORT
    uint16 recvport;
    char sendip[16];    //光闸发送IP
    char srvip[16];     //视频服务IP:PORT
    uint16 srvport;
} SIPDATAX, *PSIPDATAX;

extern vector<SIPDATAX> sipvec;

#pragma pack(pop)

/**
 * [sipcheck 校验数据格式]
 * @param  data [数据内容]
 * @param  size [数据大小]
 * @return      [0：正确；-1：结构错误；-2：版本错误]
 */
static int32 sipcheck(PSIPDATA data, int32 size)
{
    if (data == NULL) { return -1; }

    PRINT_DBG_HEAD;
    print_dbg("SIP DATA %d = %d", sizeof(SIPDATA), size);

    if (size != sizeof(SIPDATA)) { return -1; }

    PRINT_DBG_HEAD;
    print_dbg("SIP DATA %s:%d, CMD = %d, LEN = %d", data->head, data->version, data->cmd, data->length);

    if (strcmp((pchar)(data->head), "SU_SIP") != 0) { return -1; }
    if (data->version != 1) { return -2; }

    return 0;
}

enum {
    CMD_ALL = 0,
    CMD_LOCAL,
    CMD_REMOTE,
};
static void _dosipcmd(const pchar cmd, int32 flag);
static void sipack(CSYSSOCKET *onetcp, PSIPDATA data, int32 ack);
static void sipadd_del(uint32 cmd, PSIPDATAX data);
extern bool brecordlog;

/**
 * [_sipfunc_ 控制连接]
 * @param  arg [配置规则]
 * @return     [description]
 */
void *_sipfunc_(void *arg)
{
    pthread_setself("gapsip_taskctl");

    psipnew sip = (psipnew)arg;
    CLOGMANAGE logmgr; //DB record

    uint32 ip;
    uint16 port;
    char ipport[100] = {0};

    sip->onetcp->settimeout(10 * 60);
    sip->onetcp->setdatamore(true);
    sip->onetcp->getaddress(&ip, &port, false, ipport);
    PRINT_DBG_HEAD;
    print_dbg("SIP ONE addr = %s", ipport);

    logmgr.Init(brecordlog);

    while (true) {
        SIPDATA predata;
        SIPDATAX data;
        int32 size, ack;
        if ((size = sip->onetcp->readsocket(&predata, sizeof(predata))) < 0) { break; }

        if ((ack = sipcheck(&predata, size)) != 0) {
            sipack(sip->onetcp, &predata, ack);
            PRINT_ERR_HEAD;
            print_err("SIP HEAD ERROR = %d", ack);
            continue;
        }

        //处理命令
        switch (predata.cmd) {
        case SIP_ADD:
        case SIP_DEL:
            if (predata.length != sizeof(data)) { sipack(sip->onetcp, &predata, -1); }
            else if (sip->onetcp->readsocket(&data, sizeof(data)) != sizeof(data)) {
                sipack(sip->onetcp, &predata, -1);
                PRINT_ERR_HEAD;
                print_err("SIP DATA ERROR = %d", predata.cmd);
            } else {
                //建立or删除视频通道
                sipadd_del(predata.cmd, &data);
                sipack(sip->onetcp, &predata, ack);
                if (predata.cmd == SIP_ADD) {
#if 0
                    sipaddone(&data);
#else
                    sipaddone2(&data);
#endif
                } else {
#if 0
                    sipdelone(&data);
#else
                    sipdelone2(&data);
#endif
                }
#if 0
                char log[1000];
                sprintf(log, "%s视频通道: %s:%d-->%s:%d,%s", (predata.cmd == SIP_ADD) ? "添加" : "删除",
                        data.recvip, data.recvport, data.srvip, data.srvport, data.sendip);
                logmgr.WriteCallLog("", "", sip->task->srvip, sip->task->srvport, "成功", log);
                sipsave();
#else

#endif
            }
            break;
        case SIP_CLR:
#if 0
            //清除视频通道
            char cmdtmp[200];
            sprintf(cmdtmp, "%ssipclr.sh", SysModules);
            _dosipcmd(cmdtmp, CMD_ALL);
            _dosipcmd("iptables -t nat -F POSTROUTING", CMD_REMOTE);        //兼容srvsocket的UDP处理
            _dosipcmd("iptables -t nat -A POSTROUTING -j MASQUERADE", CMD_REMOTE);
#else

            for (int i = 0; i < (int)sipvec.size(); i++) {
                sipadd_del(SIP_DEL, &sipvec[i]);
            }
#endif

            sipack(sip->onetcp, &predata, ack);
#if 0
            sipdelone(NULL, true);
            logmgr.WriteCallLog("", "", sip->task->srvip, sip->task->srvport, "成功", "清除视频通道");
            sipsave();
#else
            sipvec.clear();
#endif
            break;
        case SIP_TST:
            sipack(sip->onetcp, &predata, ack);
            break;
        default:
            PRINT_ERR_HEAD;
            print_err("SIP UNKNOWN add = %s, CMD = %d", ipport, predata.cmd);
            sipack(sip->onetcp, &predata, -1);
            break;
        }
    }

    delete sip->onetcp;
    free(sip);

    logmgr.DisConnect();

    PRINT_DBG_HEAD;
    print_dbg("SIP ONE EXIT addr = %s", ipport);
    return NULL;
}

/**
 * [_dosipcmd 视频命令控制]
 * @param cmd  [命令]
 * @param flag [类型]
 */
void _dosipcmd(const pchar cmd, int32 flag)
{
    //本地
    if ((flag == CMD_ALL) || (flag == CMD_LOCAL)) {
        system(cmd);
    }

    //接收端
    if ((flag == CMD_ALL) || (flag == CMD_REMOTE)) {
#if 0
        char tmp[400];
        sprintf(tmp, "%suferry %s", SysModules, cmd);
        system(tmp);
#endif
    }
}

/**
 * [sip_init 初始化视频通道]
 */
void sip_init(void)
{
#if 0
    _dosipcmd("iptables -t nat -N sipch", CMD_ALL);
    _dosipcmd("iptables -t nat -F sipch", CMD_ALL);

    for (int32 i = 0; i < sipload(); i++) {
        SIPDATAX data;
        sipgetone(i, &data);
        sipadd_del(SIP_ADD, &data);
    }
#endif
}

/**
 * [sipack description]
 * @param onetcp [description]
 * @param data   [description]
 * @param ack    [description]
 */
void sipack(CSYSSOCKET *onetcp, PSIPDATA data, int32 ack)
{
    PRINT_DBG_HEAD;
    print_dbg("SIP ONE ACK = %d", ack);

    data->ack = ack;
    onetcp->writesocket(data, sizeof(SIPDATA));
}

/**
 * [sipadd_del 添加&删除命令处理]
 * @param cmd  [命令类型]
 * @param data [命令参数]
 */
extern char g_natip[];
extern int g_cmdport;
void sipadd_del(uint32 cmd, PSIPDATAX data)
{
    if (data == NULL) { return; }

    char _cmd[200] = {0};

#if 0
    sprintf(_cmd, "iptables -t nat -%c PREROUTING -p udp -d %s --dport %d -j sipch",
            (cmd == SIP_ADD) ? 'A' : 'D', data->recvip, data->recvport);
    _dosipcmd(_cmd, CMD_LOCAL);
    usleep(10000);
    sprintf(_cmd, "iptables -t nat -%c sipch -p udp -d %s --dport %d -j DNAT --to %s:%d",
            (cmd == SIP_ADD) ? 'A' : 'D', data->recvip, data->recvport, SU_DEVINNER_IP, data->recvport);
    _dosipcmd(_cmd, CMD_LOCAL);


    sprintf(_cmd, "iptables -t nat -%c PREROUTING -p udp -d %s --dport %d -j sipch",
            (cmd == SIP_ADD) ? 'A' : 'D', SU_DEVINNER_IP, data->recvport);
    _dosipcmd(_cmd, CMD_REMOTE);
    usleep(10000);
    sprintf(_cmd, "iptables -t nat -%c sipch -p udp -d %s --dport %d -j DNAT --to %s:%d",
            (cmd == SIP_ADD) ? 'A' : 'D', SU_DEVINNER_IP, data->recvport, data->srvip, data->srvport);
    _dosipcmd(_cmd, CMD_REMOTE);


    sprintf(_cmd, "iptables -t nat -%c POSTROUTING -p udp -d %s --dport %d -j SNAT --to-source %s",
            (cmd == SIP_ADD) ? 'I' : 'D', data->srvip, data->srvport, data->sendip);
    _dosipcmd(_cmd, CMD_REMOTE);
#else

    sprintf(_cmd, "iptables -t nat -%c PREROUTING -p udp -d '%s' --dport %d -j DNAT --to '%s':%d",
            (cmd == SIP_ADD) ? 'I' : 'D', g_natip, data->recvport, data->srvip, data->srvport);
    PeerExecuteCMD2(_cmd, g_natip, g_cmdport);

    sprintf(_cmd, "iptables -t nat -%c PREROUTING -p udp -d '%s' --dport %d -j DNAT --to '%s':%d",
            (cmd == SIP_ADD) ? 'I' : 'D', g_natip, data->recvport + 1, data->srvip, data->srvport + 1);
    PeerExecuteCMD2(_cmd, g_natip, g_cmdport);

    sprintf(_cmd, "iptables -t nat -%c POSTROUTING -p udp -d '%s' -m multiport --dports %d,%d -j SNAT --to-source '%s'",
            (cmd == SIP_ADD) ? 'I' : 'D', data->srvip, data->srvport, data->srvport + 1, data->sendip);
    PeerExecuteCMD2(_cmd, g_natip, g_cmdport);

    sprintf(_cmd, "iptables -t nat -%c PREROUTING -p udp -d '%s' -m multiport --dports %d,%d -j DNAT --to '%s'",
            (cmd == SIP_ADD) ? 'I' : 'D', data->recvip, data->recvport, data->recvport + 1, g_natip);
    system(_cmd);

#endif
}

void sipdel(PSIPDATAX data)
{
    sipadd_del(SIP_DEL, data);
}
