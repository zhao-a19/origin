/*******************************************************************************************
*文件:  FCHotBakMain.cpp
*描述:  热备主程序类
*作者:  王君雷
*日期:  2016-03
*修改:
*       修改为linux编码风格,日志信息使用宏代替, 文件目录使用宏代替      ------> 2018-04-23
*       构造函数中初始化m_cpack为NULL，否则析构函数delete野指针会出错   ------> 2018-04-24
*       调用zlog初始化函数，准备使用zlog                                ------> 2018-07-19
*       函数变量命名统一风格;全部使用zlog;热备停止业务时把fileclient进程也杀掉;
*       无参函数加void;使用友元函数;使用基于内存的信号量代替有名信号量  ------> 2018-08-29
*       StartBS中sleep 5秒,防止把内部连接IP冲洗掉无法通信               ------> 2018-10-22
*       读取设备ID为空时，会去读取设备唯一码当做设备ID使用              ------> 2018-11-08
*       主备策略同步时，不覆盖"通信口检查"配置项                        ------> 2018-11-21
*       双机热备协议修改，WEB可以展示更多热备通信状态信息               ------> 2018-11-27
*       减少使用continue，策略同步协议使用结构，修改变量命名，封装SlaveSwitch
*       函数等                                                          ------> 2018-12-03
*       联调测试修改后台的双机热备协议，修改策略同步包超长等问题        ------> 2018-12-11
*       修改LoadData返回值判断有误BUG;热备接收数据包出错时做延迟        ------> 2018-12-14
*       修改181214引入的BUG，接收到非0801协议的数据包也做延迟，会有问题 ------> 2019-02-20
*       备机即使不运行也执行下内网的路由信息，解决备机管理不了的问题    ------> 2019-09-24
*       解决备机管理不了的问题                                          ------> 2019-11-19-dzj
*       读取LinkLanIPSeg、LinkLanPort失败，使用默认值，而不是直接退出   ------> 2020-02-14-wjl
*       兼容读取配置错误，设备角色默认为主机、热备策略同步默认不开启、
*       热备同步周期默认10分钟、LCDFlag可以为空、设备ID可以为空         ------> 2020-02-28 wjl
*       支持蜂鸣器时才包含sys/io.h文件                                 ------> 2020-05-15
*       支持飞腾平台                                                    ------> 2020-07-27
*       使用NOHUP_RUN宏，屏蔽飞腾平台调用程序时的差异                     ------> 2020-09-20
*       添加通过HA工具恢复用户配置功能                                   ------> 2020-09-28
*       恢复用户配置时用户证书也一起恢复                                 ------> 2020-09-29
*       恢复用户配置时外网后台账号一起恢复                               ------> 2020-10-21
*       可以设置线程名称                                               ------> 2021-02-23
*       hotbakmain跟据工作模式决定原始套接字是否接收全部协议包            ------> 2021-04-07
*       把对NEW_DBSYNC_TOOL的调用移动到hotbakmain中                     ------> 2021-04-11
*       调用dbsync_tool前先把可能正在运行的dbsync_tool进程杀掉           ------> 2021-04-12
*       主机向备机同步策略时，发包做延迟，解决M0设备乱序问题             ------> 2021-05-26
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/ipc.h>

#include "FCHotBakMain.h"
#include "FCMsgAck.h"
#include "FCMD5.h"
#include "FCLogManage.h"
#include "FCPeerExecuteCMD.h"
#include "simple.h"
#include "hardinfo.h"
#include "debugout.h"
#include "readcfg.h"
#include "hotbak_trans.h"
#include "common.h"

#ifdef SUPPORT_SPEACKER
#include <sys/io.h>
#endif

#define SRULES_TAR_PATH "/tmp/srule.tar"
#define RRULES_TAR_PATH "/tmp/rrule.tar"
#define HOTBAK_SHOW_PATH "/tmp/hotbak.cf"

int g_linklanipseg = 0;
int g_linklanport = 0;
#define IS_STR_EMPTY(str) (strcmp((str), "") == 0)

/**
 * [speaker 蜂鸣器响]
 * @param freq  [description]
 * @param delay [description]
 */
void speaker(unsigned int freq, unsigned int delay)
{
#ifdef SUPPORT_SPEACKER
    static int flag = 0, bit;
    if (flag == 0) {
        flag = 1;
        iopl(3);
    }
    outb(0xb6, 0x43);
    outb((freq & 0xff), 0x42);
    outb((freq >> 8), 0x42);
    bit = inb(0x61);
    outb(3 | bit, 0x61);
    usleep(10000 * delay);
    outb(0xfc | bit, 0x61);
#endif
}

/**
 * [Alarm 告警]
 */
void Alarm(void)
{
    unsigned int freq_alert[] = {2000, 2400, 0};
    unsigned int time_alert[] = {50, 60};
    int i;
    for (i = 0; freq_alert[i] != 0; i++) {
        speaker(freq_alert[i], time_alert[i]);
    }
#ifdef SUPPORT_SPEACKER
    iopl(3);
    outb(0xb6, 0x43);
#endif
}

HotBakManager::HotBakManager(void)
{
    //同步策略不准改变的字段
    m_ckweblogintx = 0;
    m_cklineswitch = 0;

    //本机相关字段
    BZERO(m_status);
    m_status[NIC_INDEX] = 1;
    BZERO(m_devid);
    m_b_master = true;
    m_run = 0;
    m_nicnum_in = m_nicnum_out = 0;
    BZERO(m_nicin);
    BZERO(m_nicout);
    m_lasthb_req = m_lasthb_res = 0;

    //上级相关字段
    BZERO(m_masterstatus);
    BZERO(m_masterid);
    m_masterrun = 0;
    m_master_nicnum_in = m_master_nicnum_out = 0;
    BZERO(m_master_nicin);
    BZERO(m_master_nicout);

    //下级相关字段
    BZERO(m_slavestatus);
    BZERO(m_slaveid);
    m_slaverun = 0;

    //其他字段
    m_b_tran_rule = false;
    m_tran_rule_cycle = 10;
    m_hotbaklan = -1;
    BZERO(m_inner_devtype);
    m_maxheartfail = 5;
    m_report_th = m_server_th = m_client_th = m_rules_th = m_wrconf_th = NULL;
    m_cpack = NULL;
    BZERO(m_hbconf);
    if (sem_init(&m_heartbeat_sem, 0, 0) == -1) {
        PRINT_ERR_HEAD
        print_err("init sem fail");
    }

    if (sem_init(&m_wrconf_sem, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init sem fail");
    }
}

HotBakManager::~HotBakManager(void)
{
    DELETE(m_report_th);
    DELETE(m_server_th);
    DELETE(m_client_th);
    DELETE(m_rules_th);
    DELETE(m_wrconf_th);
    if (m_cpack != NULL) {
        m_cpack->Close();
        delete m_cpack;
        m_cpack = NULL;
    }
    sem_destroy(&m_heartbeat_sem);
    sem_destroy(&m_wrconf_sem);
}

/**
 * [HotBakManager::Start 开始运行]
 * @return  [成功返回0 失败返回负值]
 */
int HotBakManager::Start(void)
{
    PRINT_DBG_HEAD
    print_dbg("start. hotbaklan is[%d] workflag[%d]", m_hotbaklan, m_workflag);

    m_cpack = new CPACKET(m_hotbaklan, m_workflag == WORK_MODE_TRANSPARENT);
    if (m_cpack == NULL) {
        PRINT_ERR_HEAD
        print_err("new CPACKET fail");
        return -1;
    }

    if (m_report_th == NULL) {
        m_report_th = new CThread;
        if (m_report_th != NULL) {
            m_report_th->ThCreate(RecvReport, (void *)this);
        } else {
            PRINT_ERR_HEAD
            print_err("report th null");
        }
    }

    if (m_client_th == NULL) {
        m_client_th = new CThread;
        if (m_client_th != NULL) {
            m_client_th->ThCreate(ClientProcess, (void *)this);
        } else {
            PRINT_ERR_HEAD
            print_err("client th null");
        }
    }

    if (m_server_th == NULL) {
        m_server_th = new CThread;
        if (m_server_th != NULL) {
            m_server_th->ThCreate(ServerProcess, (void *)this);
        } else {
            PRINT_ERR_HEAD
            print_err("server th null");
        }
    }

    if (m_rules_th == NULL) {
        if (!m_b_master) {
            m_rules_th = new CThread;
            if (m_rules_th != NULL) {
                //从设备开启线程，处理接收到的策略文件数据
                m_rules_th->ThCreate(RulesProcess, (void *)this);
            } else {
                PRINT_ERR_HEAD
                print_err("rules th null");
            }
        }
    }

    if (m_wrconf_th == NULL) {
        m_wrconf_th = new CThread;
        if (m_wrconf_th != NULL) {
            m_wrconf_th->ThCreate(WRConfProcess, (void *)this);
        } else {
            PRINT_ERR_HEAD
            print_err("wrconf th null");
        }
    }
    return 0;
}


/**
 * [RecvReport 接收汇报信息的线程]
 * @param  param [HotBakManager指针]
 * @return       [对象指针]
 */
void *RecvReport(void *param)
{
    pthread_setname("recvreport");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("recv report para null");
        return NULL;
    }

    PRINT_DBG_HEAD
    print_dbg("recv report begin");

    unlink(UNIX_REPORT_SRV_PATH);
    HotBakManager *p_this = (HotBakManager *)param;
    struct sockaddr_un unixaddr;
    int report_sock = 0;
    int ret = 0;
    char buf[64 * 1024] = {0};
    REPORT_HEAD reporthead;

    //准备好接收汇报的socket
    while ((report_sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket err[%s]", strerror(errno));
        sleep(1);
    }

    BZERO(unixaddr);
    unixaddr.sun_family = PF_UNIX;
    strcpy(unixaddr.sun_path, UNIX_REPORT_SRV_PATH);

    //绑定本地套接字
    while (bind(report_sock, (struct sockaddr *)&unixaddr, sizeof(unixaddr)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind err[%s:%s]", UNIX_REPORT_SRV_PATH, strerror(errno));
        sleep(1);
    }

    while (1) {
        BZERO(buf);
        ret = recvfrom(report_sock, buf, sizeof(buf), 0, NULL, NULL);
        if (ret < (int)sizeof(reporthead)) {
            PRINT_ERR_HEAD
            print_err("recvfrom ret[%d], which shuld be more than [%d]", ret, (int)sizeof(reporthead));
        } else {
            memcpy(&reporthead, buf, sizeof(reporthead));
            if (reporthead.len + (int)sizeof(reporthead) != ret) {
                PRINT_ERR_HEAD
                print_err("ret=%d,reporthead.len=%d", ret, reporthead.len);
            } else {
                switch (reporthead.type) {
                case REPORT_NIC_STATUS:
                    p_this->HandleNicReport(buf + sizeof(reporthead), reporthead.len);
                    break;
                //此处可以扩展 支持更多类型
                default:
                    break;
                }
            }
        }
    }

    close(report_sock);
    PRINT_ERR_HEAD
    print_err("recv report process will exit");
    return NULL;
}

/**
 * [ServerProcess 服务器线程函数]
 * @param  param [HotBakManager指针]
 * @return       [对象指针]
 */
void *ServerProcess(void *param)
{
    pthread_setname("svrproc");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("server process para null");
        return NULL;
    }

    PRINT_DBG_HEAD
    print_dbg("server process begin");

    HotBakManager *p_this = (HotBakManager *)param;
    unsigned char recvbuff[MAX_PKTSIZE] = {0};
    unsigned char kind = 0;
    int rlen = 0;
    struct sockaddr_un peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    BZERO(peer_addr);
    peer_addr.sun_family = PF_UNIX;
    strcpy(peer_addr.sun_path, UNIX_RULES_SRV_PATH);

    //当收到策略文件时 转发给m_rules_th去处理
    int rule_sock = 0;
    while ((rule_sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket err[%s],retry", strerror(errno));
        sleep(1);
    }

    //为了保证ClientProcess比ServerProcess早起来
    usleep(1000);

    PRINT_DBG_HEAD
    print_dbg("begin to read packet[%d]", rule_sock);

    while (1) {
        BZERO(recvbuff);
        rlen = sizeof(recvbuff);
        kind = 0;
        p_this->m_cpack->ReadPacket(recvbuff, &rlen, kind);
        if (rlen < 0) {
            //usleep(100000);//做延迟会有问题
        } else {
            PRINT_DBG_HEAD
            print_dbg("read kind[%d]", kind);
            switch (kind) {
            case C_SERCHDEV:
                p_this->HandleSearchDev();
                break;
            case C_INITDEV:
                p_this->HandleInitDev((const char *)recvbuff, rlen);
                break;
            case C_GETCTRL:
                p_this->HandleGetCtrl();
                break;
            case C_GETINFO:
                p_this->HandleGetInfo();
                break;
            case C_HEARTBEAT:
                p_this->HandleHB((const char *)recvbuff, rlen);
                break;
            case C_HEARTBEAT_RES:
                p_this->HandleHBResult((const char *)recvbuff, rlen);
                break;
            case C_GET_RULES:
                p_this->HandleGetRule((const char *)recvbuff, rlen);
                break;
            case C_RULES_FILE:
                //发送给 另一线程处理
                if (sendto(rule_sock, recvbuff, rlen, 0, (struct sockaddr *)&peer_addr, peer_addr_len) < 0) {
                    PRINT_ERR_HEAD
                    print_err("sendto err[%s]", strerror(errno));
                }
                break;
            case C_INIT_USERCONF:
                p_this->HandleInitUserConf((const char *)recvbuff, rlen);
                break;
            default:
                PRINT_ERR_HEAD
                print_err("unknown type[%d]", kind);
                break;
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("server process will exit");
    return NULL;
}

/**
 * [ClientProcess 客户端线程函数]
 * @param  param [HotBakManager指针]
 * @return       [对象指针]
 */
void *ClientProcess(void *param)
{
    pthread_setname("cliproc");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("client process para null");
        return NULL;
    }

    HotBakManager *p_this = (HotBakManager *)param;

    HB_RESULT hb_result = HB_OK;
    int seqid = 0;
    int timeout_cnt = 0; //心跳连续超时的次数

    if (p_this->m_b_master) { //主机
        p_this->m_run = 1;    //Client线程需要尽快设置该变量 否则Server线程可能会先起来、并在心跳回应中告诉备机 我故障了
        p_this->StartBS();
        sem_post(&(p_this->m_wrconf_sem));
    } else {
        p_this->SetInRoute();
        while (1) {
            sleep(1);
            if (p_this->m_b_tran_rule && (time(NULL) % (p_this->m_tran_rule_cycle * 60) == 0)) {
                p_this->SlaveRulesRequest();
            } else {
                seqid++;
                seqid %= HB_RESULT_NUM;
                if (p_this->SlaveHBRequest(seqid)
                    && p_this->SlaveWaitHBResult(hb_result, seqid)) {
                    p_this->SlaveHandleHBResult(hb_result, timeout_cnt);
                }
            }
        }

        PRINT_ERR_HEAD
        print_err("client process will exit");
    }
    return NULL;
}

/**
 * [RulesProcess 处理规则的线程函数]
 * @param  param [HotBakManager指针]
 * @return       [对象指针]
 */
void *RulesProcess(void *param)
{
    pthread_setname("ruleproc");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("rules process para null");
        return NULL;
    }
    unlink(UNIX_RULES_SRV_PATH);
    HotBakManager *p_this = (HotBakManager *)param;

    int ret = 0;
    int nextid = 0;
    FILE *fd = NULL;
    HB_RULES_TRANSFER ruledata;
    int rsock = 0;

    while ((rsock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket err[%s]", strerror(errno));
        sleep(1);
    }

    struct sockaddr_un addr;
    BZERO(addr);
    addr.sun_family = PF_UNIX;
    strcpy(addr.sun_path, UNIX_RULES_SRV_PATH);
    while (bind(rsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind err[%s:%s]", UNIX_RULES_SRV_PATH, strerror(errno));
        sleep(1);
    }

    while (1) {
        BZERO(ruledata);
        ret = recvfrom(rsock, (unsigned char *)&ruledata, sizeof(ruledata), 0, NULL, NULL);
        if (ret < (int)offsetof(HB_RULES_TRANSFER, buff)) {
            PRINT_ERR_HEAD
            print_err("recvfrom err[%d]", ret);
        } else {
            p_this->HandleRulesPacket(ruledata, &fd, nextid);
        }
    }

    FCLOSE(fd);
    close(rsock);
    PRINT_ERR_HEAD
    print_err("rules process will exit");
    return NULL;
}

/**
 * [HotBakManager::HandleRulesPacket 处理一个策略同步数据包]
 * @param  ruledata [策略同步数据]
 * @param  fd       [文件描述符]
 * @param  nextid   [期望的下一个ID号]
 * @return          [成功返回true]
 */
bool HotBakManager::HandleRulesPacket(HB_RULES_TRANSFER &ruledata, FILE **fd, int &nextid)
{
    bool bflag = true;

    if (ruledata.seqnumber == HB_FILE_END) { //文件结束
        if (ruledata.datalen != 32) {
            PRINT_ERR_HEAD
            print_err("md5 len error[%d]", ruledata.datalen);
            bflag = false;
        } else {
            FCLOSE(*fd);
            PRINT_INFO_HEAD
            print_info("recv rulefile end[%d]", nextid);
            if (CheckRulesFile(ruledata.buff)) {
                CoverRulesFile();
            }
        }
    } else {
        if (ruledata.seqnumber == HB_FILE_BEGIN) { //文件开始
            nextid = 1;
            FCLOSE(*fd);

            PRINT_INFO_HEAD
            print_info("recv rulefile begin[%d]", nextid);

            *fd = fopen(RRULES_TAR_PATH, "wb");
            if (*fd == NULL) {
                PRINT_ERR_HEAD
                print_err("fopen err[%s:%s]", RRULES_TAR_PATH, strerror(errno));
                bflag = false;
            }
        } else { //文件传输
            if (ruledata.seqnumber == nextid) {
                PRINT_INFO_HEAD
                print_info("recv rulefile. seqnumber[%d]", ruledata.seqnumber);
                nextid++;
            } else {
                PRINT_ERR_HEAD
                print_err("confused! ruledata.seqnumber[%d] nextid[%d]", ruledata.seqnumber, nextid);
                bflag = false;//可能传输错乱了
            }
        }

        if (bflag) {
            //写入文件
            if (*fd != NULL) {
                int wlen = fwrite(ruledata.buff, 1, ruledata.datalen, *fd);
                if (wlen != ruledata.datalen) {
                    PRINT_ERR_HEAD
                    print_err("fwrite err[wlen:%d ruledata.datalen:%d err:%s]", wlen,
                              ruledata.datalen, strerror(errno));
                    bflag = false;
                }
            } else {
                PRINT_ERR_HEAD
                print_err("fd is null");
                bflag = false;
            }
        }
    }

    return bflag;
}

/**
 * [HotBakManager::StartBS 开启业务]
 * @return  [成功返回0]
 */
int HotBakManager::StartBS(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    CCommon common;

    system(STOP_IN_BUSINESS_WITHOUT_HOTB);
    //关闭蜂鸣器
#ifdef SUPPORT_SPEACKER
    iopl(3);
    outb(0xb6, 0x43);
#endif
    PRINT_DBG_HEAD
    print_dbg("start sys6 now");
    sprintf(chcmd, "%s /initrd/abin/sys6 >/dev/null 2>&1&", NOHUP_RUN);
    system(chcmd);
    sprintf(chcmd, "%s /initrd/abin/autobak normal >/dev/null 2>&1&", NOHUP_RUN);
    system(chcmd);

    while (common.ProcessRuning("dbsync_tool")) {
        sprintf(chcmd, "killall -15 dbsync_tool >/dev/null 2>&1");
        system(chcmd);
        PRINT_INFO_HEAD
        print_info("stop dbsync_tool[%s]", chcmd);
        sleep(1);
    }
    sprintf(chcmd, "%s &", NEW_DBSYNC_TOOL);
    system(chcmd);

    sleep(5);
    return 0;
}

/**
 * [HotBakManager::StopBS 停止业务]
 * @return  [成功返回0]
 */
int HotBakManager::StopBS(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < m_nicnum_in; i++) {
        sprintf(chcmd, "ifconfig %s down", m_nicin[i].ethname);
        system(chcmd);
    }

    for (int i = 0; i < m_nicnum_out; i++) {
        sprintf(chcmd, "ifconfig %s down", m_nicout[i].ethname);
        PeerExecuteCMD(chcmd);
    }

    system(STOP_IN_BUSINESS_WITHOUT_HOTB);
    PeerExecuteCMD(STOP_OUT_BUSINESS);
#ifdef SUPPORT_SPEACKER
    //关闭蜂鸣器
    iopl(3);
    outb(0xb6, 0x43);
#endif
    return 0;
}

/**
 * [HotBakManager::SetMac 备机把自己的业务口MAC设置成与主机相同 为了业务能快速切换]
 * @param  pnic  [网卡信息结构指针]
 * @param  num   [数目]
 * @param  isout [是否为外网]
 * @return       [成功返回0]
 */
int HotBakManager::SetMac(const PNIC_MAC_STRUCT pnic, int num, bool isout)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < num; i++) {
        sprintf(chcmd, "ifconfig %s hw ether %s", pnic[i].ethname, pnic[i].mac);
        isout ? PeerExecuteCMD(chcmd) : system(chcmd);
    }
    return 0;
}

/**
 * [HotBakManager::LoadData 读取配置信息]
 * @return  [成功返回true]
 */
bool HotBakManager::LoadData(void)
{
    bool bflag = false;
    int tmpint = 0;
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SYSSET_CONF);
        return false;
    }

    //是否为主设备
    tmpint = 1;
    READ_INT(fileop, "SYSTEM", "MainDev", tmpint, false, _out);
    m_b_master = (tmpint == 1);
    if (!m_b_master) {
        READ_STRING(fileop, "SYSTEM", "MainDevice", m_masterid, true, _out);
        tmpint = 0;
        READ_INT(fileop, "SYSTEM", "CKHotbakRules", tmpint, false, _out);
        m_b_tran_rule = (tmpint == 1);
        READ_INT(fileop, "SYSTEM", "HotbakRulesCycle", m_tran_rule_cycle, false, _out);
        if (m_tran_rule_cycle <= 0) {
            m_tran_rule_cycle = 10;
        }
    }

    //读取管理口相关配置
    READ_STRING(fileop, "SYSTEM", "CSIP", m_csip, true, _out);
    READ_STRING(fileop, "SYSTEM", "CSPort", m_csport, true, _out);
    READ_STRING(fileop, "SYSTEM", "CSMask", m_csmask, true, _out);
    READ_STRING(fileop, "SYSTEM", "MGClientIP", m_mgcliip, true, _out);
    READ_INT(fileop, "SYSTEM", "CKWebLoginTX", m_ckweblogintx, false, _out);
    READ_INT(fileop, "SYSTEM", "CKLineSwitch", m_cklineswitch, false, _out);
    READ_INT(fileop, "SYSTEM", "WorkFlag", m_workflag, true, _out);
    fileop.CloseFile();

    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SYSINFO_CONF);
        return false;
    }
    READ_STRING(fileop, "SYSTEM", "DevIndex", m_devid, false, _out);
    if (strcmp(m_devid, "") == 0) {
        for (int i = 0; i < 5; ++i) {
            if (ReadSerial(m_devid, sizeof(m_devid))) {
                break;
            } else {
                sleep(1);
            }
        }
    }
    if (strcmp(m_devid, "") == 0) {
        goto _out;
    }
    READ_INT(fileop, "SYSTEM", "HotBakLan", m_hotbaklan, true, _out);
    READ_STRING(fileop, "SYSTEM", "InnerDevType", m_inner_devtype, true, _out);
    READ_INT(fileop, "SYSTEM", "MaxHeartFail", m_maxheartfail, false, _out);
    if (m_maxheartfail <= 0) {
        m_maxheartfail = 5;
    }
    READ_INT(fileop, "SYSTEM", "LinkLanIPSeg", g_linklanipseg, false, _out);
    if (g_linklanipseg < 1 || g_linklanipseg > 255) {
        g_linklanipseg = 1;
    }
    READ_INT(fileop, "SYSTEM", "LinkLanPort", g_linklanport, false, _out);
    if (g_linklanport < 1 || g_linklanport > 65535) {
        g_linklanport = DEFAULT_LINK_PORT;
    }

    bflag = true;
_out:
    fileop.CloseFile();
    return bflag;
}

/**
 * [HotBakManager::ReadSerial 读取唯一码 当做ID号使用]
 * @param  serial [唯一码 出参]
 * @param  len    [缓冲区长度]
 * @return        [读取成功返回true]
 */
bool HotBakManager::ReadSerial(char *serial, int len)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SERIAL_CFG, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SERIAL_CFG);
        return false;
    }

    if (fileop.ReadCfgFile("SYSTEM", "SERIAL", serial, len) != E_FILE_OK) {
        fileop.CloseFile();
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("serial[%s]", serial);
    fileop.CloseFile();
    return true;
}

/**
 * [HotBakManager::SendRules 主机向备机发送策略文件]
 * @return  [成功返回0  打开文件失败返回-1  发送文件失败返回-2]
 */
int HotBakManager::SendRules(void)
{
    PRINT_DBG_HEAD
    print_dbg("send rule begin");

    HB_RULES_TRANSFER ruledata;
    ruledata.datalen = 0;
    ruledata.seqnumber = HB_FILE_BEGIN;

    char chcmd[CMD_BUF_LEN] = {0};
    unlink(SRULES_TAR_PATH);
    sprintf(chcmd, "tar -czf %s %s", SRULES_TAR_PATH, RULES_DIR);
    system(chcmd);
    unsigned char md5_str[33] = {0};
    md5sum(SRULES_TAR_PATH, md5_str);

    //打开文件
    FILE *fd = fopen(SRULES_TAR_PATH, "rb");
    if (fd == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen[%s] err[%s]", SRULES_TAR_PATH, strerror(errno));
        return -1;
    }

    while (1) {
        BZERO(ruledata.buff);
        ruledata.datalen = fread(ruledata.buff, 1, sizeof(ruledata.buff), fd);
        if (ruledata.datalen <= 0) {
            ruledata.datalen = 32;
            memcpy(ruledata.buff, md5_str, 32);
            ruledata.seqnumber = HB_FILE_END;

            if (m_cpack->WritePacket((const unsigned char *)&ruledata, offsetof(HB_RULES_TRANSFER, buff)
                                     + ruledata.datalen, C_RULES_FILE) < 0) {
                PRINT_ERR_HEAD
                print_err("send end packet err.seqnumber[%d] datalen[%d]", ruledata.seqnumber,
                          ruledata.datalen);
                fclose(fd);
                return -2;
            }
            break;
        } else {
            PRINT_DBG_HEAD
            print_dbg("send rule seqnumber[%d] datalen[%d]", ruledata.seqnumber, ruledata.datalen);

            if (m_cpack->WritePacket((const unsigned char *)&ruledata, offsetof(HB_RULES_TRANSFER, buff)
                                     + ruledata.datalen, C_RULES_FILE) < 0) {
                PRINT_ERR_HEAD
                print_err("send file packet err.seqnumber[%d] datalen[%d]", ruledata.seqnumber,
                          ruledata.datalen);
                fclose(fd);
                return -2;
            }
            ruledata.seqnumber++;
			usleep(10000);
        }
    }

    fclose(fd);
    PRINT_DBG_HEAD
    print_dbg("send rule success");
    return 0;
}

loghandle glog_p = NULL;

int main(int argc, char **argv)
{
    _log_init_(glog_p, hotbakmain);

    HotBakManager manager;
    if (!manager.LoadData()) {
        PRINT_ERR_HEAD
        print_err("load data fail");
        return -1;
    }

    if (manager.Start() < 0) {
        PRINT_ERR_HEAD
        print_err("start fail");
        return -1;
    }

    while (1) {
        sleep(100);
    }
    return 0;
}

/**
 * [HotBakManager::MakeInfoString 制作设备信息字符串]
 * 组出的字符串如下：
 * [DevIndex=TR74415080101]-[DEVTYPE=TopRules 7000]-[InnerDevType=SU35440001]-[CSLan=3]-[HotBakLan=5]-
 * [LinkLan=4]-[LinkLanIPSeg=1]-[LinkLanPort=59876]-[ClientAuthPort=59876]-[LCDFlag=null]-[InterfaceNum=4]-
 * [OuterfaceNum=4]-[CSMAC=11:22:33:44:55:66]-[INLINKMAC=11:22:33:44:55:66]-[OUTLINKMAC=11:22:33:44:55:66]-
 * [SYS6VER=6.160608]-[VIRVER=10.1111.2222]
 * @param  chout [输出参数]
 * @param  len   [输出缓冲区长度]
 * @return       [成功返回true]
 */
bool HotBakManager::MakeInfoString(char *chout, int len)
{
    if ((chout == NULL) || (len <= 0)) {
        PRINT_ERR_HEAD
        print_err("para err[%s:%d]", chout, len);
        return false;
    }

    bool bflag = false;
    char devtype[100] = {0};
    int cslan;
    int linklan;
    int authport;
    char lcdflag[64] = {0};
    int interfacenum;
    int outerfacenum;
    char chcsmac[MAC_STR_LEN] = {0};
    char chinlinkmac[MAC_STR_LEN] = {0};
    char choutlinkmac[MAC_STR_LEN] = {0};
    char chsys6ver[100] = {0};
    char chvirver[100] = {0};

    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SYSINFO_CONF);
        return false;
    }

    READ_STRING(fileop, "SYSTEM", "DEVTYPE", devtype, true, _out);
    READ_INT(fileop, "SYSTEM", "CSLan", cslan, true, _out);
    READ_INT(fileop, "SYSTEM", "LinkLan", linklan, true, _out);
    READ_INT(fileop, "SYSTEM", "ClientAuthPort", authport, false, _out);
    READ_STRING(fileop, "SYSTEM", "LCDFlag", lcdflag, false, _out);
    READ_INT(fileop, "SYSTEM", "InterfaceNum", interfacenum, true, _out);
    READ_INT(fileop, "SYSTEM", "OuterfaceNum", outerfacenum, true, _out);

    if (get_mac(cslan, chcsmac)
        && get_mac(linklan, chinlinkmac)
        && get_out_mac(linklan, choutlinkmac)
        && ReadVersion(VERSION_FILE, chsys6ver, sizeof(chsys6ver))
        && ReadVersion(VIRUS_VERSION_FILE, chvirver, sizeof(chvirver))) {
        snprintf(chout, len,
                 "[DevIndex=%s]-[DEVTYPE=%s]-[InnerDevType=%s]-[CSLan=%d]-[HotBakLan=%d]-[LinkLan=%d]-[LinkLanIPSeg=%d]-"
                 "[LinkLanPort=%d]-[ClientAuthPort=%d]-[LCDFlag=%s]-[InterfaceNum=%d]-[OuterfaceNum=%d]-[CSMAC=%s]-"
                 "[INLINKMAC=%s]-[OUTLINKMAC=%s]-[SYS6VER=%s]-[VIRVER=%s]",
                 m_devid, devtype, m_inner_devtype, cslan, m_hotbaklan, linklan, g_linklanipseg, g_linklanport, authport,
                 lcdflag, interfacenum, outerfacenum, chcsmac, chinlinkmac, choutlinkmac, chsys6ver, chvirver);
        bflag = true;
    }
_out:
    fileop.CloseFile();
    return bflag;
}

/**
 * [HotBakManager::ReadVersion 从文件中读取版本信息]
 * @param  fname [文件名]
 * @param  ver   [版本号 出参]
 * @param  size  [版本号缓冲区大小]
 * @return       [成功返回true]
 */
bool HotBakManager::ReadVersion(const char *fname, char *ver, int size)
{
    if ((fname == NULL) || (ver == NULL) || (size <= 0)) {
        PRINT_ERR_HEAD
        print_err("para err，fname[%s],size[%d]", fname, size);
        return false;
    }

    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen[%s] err[%s]", fname, strerror(errno));
        return false;
    }

    int readlen = fread(ver, 1, size - 1, fp);
    if (readlen <= 0) {
        PRINT_ERR_HEAD
        print_err("fread[%s] err[%s]", fname, strerror(errno));
        fclose(fp);
        return false;
    }

    for (int i = 0; i < readlen; i++) {
        if ((ver[i] == '\r') || (ver[i] == '\n')) {
            ver[i] = '\0';
        }
    }
    fclose(fp);
    return true;
}

/**
 * [HotBakManager::HandleNicReport 处理接收到的网卡汇报信息]
 * @param  info [网卡汇报信息]
 * @param  len  [长度]
 * @return      [成果返回true]
 */
bool HotBakManager::HandleNicReport(const char *info, int len)
{
    NIC_REPORT_HEAD nichead;

    if (len < (int)sizeof(nichead)) {
        PRINT_ERR_HEAD
        print_err("info too short[%d],less than [%d]", len, (int)sizeof(nichead));
        return false;
    }

    memcpy(&nichead, info, sizeof(nichead));
    if ((nichead.nicnum_in < 0)
        || (nichead.nicnum_in > MAX_NIC_NUM)
        || (nichead.nicnum_out < 0)
        || (nichead.nicnum_out > MAX_NIC_NUM)
        || (len != (int)(sizeof(nichead) +
                         (nichead.nicnum_in + nichead.nicnum_out) * sizeof(NIC_MAC_STRUCT)))) {
        PRINT_ERR_HEAD
        print_err("nichead.nicnum_in[%d] nichead.nicnum_out[%d] len[%d]", nichead.nicnum_in,
                  nichead.nicnum_out, len);
        return false;
    }
    //把汇总数据存起来
    memcpy(&(m_nicin),  info + sizeof(nichead), sizeof(NIC_MAC_STRUCT) * nichead.nicnum_in);
    memcpy(&(m_nicout),  info + sizeof(nichead) + sizeof(NIC_MAC_STRUCT) * nichead.nicnum_in,
           sizeof(NIC_MAC_STRUCT) * nichead.nicnum_out);
    m_nicnum_in = nichead.nicnum_in;
    m_nicnum_out = nichead.nicnum_out;
#if 0
    for (int i = 0; i < m_nicnum_in; ++i) {
        PRINT_DBG_HEAD
        print_dbg("get report info.in :ethname[%s] mac[%s]", m_nicin[i].ethname, m_nicin[i].mac);
    }
    for (int i = 0; i < m_nicnum_out; ++i) {
        PRINT_DBG_HEAD
        print_dbg("get report info.out:ethname[%s] mac[%s]", m_nicout[i].ethname, m_nicout[i].mac);
    }
#endif
    if ((m_status[NIC_INDEX] == 1) && (nichead.status != NIC_STATUS_OK)) {
        m_status[NIC_INDEX] = 0;
        //状态发生变化了
        sem_post(&m_wrconf_sem);
    } else if ((m_status[NIC_INDEX] == 0) && (nichead.status == NIC_STATUS_OK)) {
        m_status[NIC_INDEX] = 1;
        //状态发生变化了
        sem_post(&m_wrconf_sem);
    }

    return true;
}

/**
 * [HotBakManager::CollectHBConf 收集写热备配置文件所需要的信息]
 * @param info [出参]
 */
void HotBakManager::CollectHBConf(HB_CONF_FILE_INFO &info)
{
    if (m_b_master) {
        //我是主机
        info.timeout = HB_TIMEOUT(time(NULL), m_lasthb_req) ? 1 : 0;
        strcpy(info.masterid, m_devid);
        info.masterrun = m_run;
        memcpy(&(info.masterstatus), &m_status, sizeof(m_status));
        strcpy(info.slaveid, m_slaveid);
        info.slaverun = m_slaverun;
        memcpy(&(info.slavestatus), &m_slavestatus, sizeof(m_slavestatus));
    } else {
        //我是备机
        info.timeout = HB_TIMEOUT(time(NULL), m_lasthb_res) ? 1 : 0;
        strcpy(info.masterid, m_masterid);
        info.masterrun = m_masterrun;
        memcpy(&(info.masterstatus), &m_masterstatus, sizeof(m_masterstatus));
        strcpy(info.slaveid, m_devid);
        info.slaverun = m_run;
        memcpy(&(info.slavestatus), &m_status, sizeof(m_status));
    }
}

/**
 * [WRConfProcess 写热备配置文件的线程函数]
 * @param  param [对象指针]
 * @return       [未使用]
 */
void *WRConfProcess(void *param)
{
    pthread_setname("wrconfproc");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("wrconf process para null");
        return NULL;
    }

    PRINT_DBG_HEAD
    print_dbg("wr conf process begin");

    int ret = 0;
    HB_CONF_FILE_INFO info;
    HotBakManager *p_this = (HotBakManager *)param;

    while (1) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        ret = sem_timedwait(&(p_this->m_wrconf_sem), &ts);
        if (ret == 0) {
        } else {
            //PRINT_DBG_HEAD
            //print_dbg("begin check hb conf info");
        }

        //超时xx 或者有其他线程通知我有变化 就从新处理一次
        BZERO(info);
        p_this->CollectHBConf(info);
        if (memcmp(&(p_this->m_hbconf), &info, sizeof(info)) != 0) {
            memcpy(&(p_this->m_hbconf), &info, sizeof(info));
            p_this->PrintHBConfInfo(p_this->m_hbconf);
            p_this->WriteConf();
        } else {
            //PRINT_DBG_HEAD
            //print_dbg("no change");
        }
    }

    PRINT_ERR_HEAD
    print_err("write conf process will exit");
    return NULL;
}

/**
 * [HotBakManager::HandleSearchDev 处理搜索设备的请求]
 * @return  [成功返回true]
 */
bool HotBakManager::HandleSearchDev(void)
{
    PRINT_DBG_HEAD
    print_dbg("serch dev type");

    int ret = m_cpack->WritePacket((const unsigned char *)m_devid, strlen(m_devid), C_DEVID);
    if (ret != (int)strlen(m_devid)) {
        PRINT_ERR_HEAD
        print_err("write packet ret error[%d].m_devid[%d:%s]", ret, (int)strlen(m_devid), m_devid);
        return false;
    }
    return true;
}

/**
 * [HotBakManager::HandleInitDev 处理设备初始化请求]
 * @param  buff [请求ID号]
 * @param  len  [ID号长度]
 * @return      [成功返回true]
 */
bool HotBakManager::HandleInitDev(const char *buff, int len)
{
    PRINT_INFO_HEAD
    print_info("init dev type[id:%s][len:%d]", buff, len);

    char devid[DEV_ID_LEN] = {0};
    if ((len <= 0) || (len >= (int)sizeof(devid))) {
        PRINT_ERR_HEAD
        print_err("len error[%d]", len);
    } else {
        memcpy(devid, buff, len);
        //是本设备ID 就初始化
        if (strcmp(m_devid, devid) == 0) {
            WriteSysLog(LOG_TYPE_INIT, D_SUCCESS, LOG_CONTENT_TOOL_INIT);
            system(INIT_SYS_SHELL);
            return true;
        } else {
            PRINT_INFO_HEAD
            print_info("m_devid[%s].required dev[%s]", m_devid, devid);
        }
    }
    return false;
}

/**
 * [HotBakManager::HandleInitUserConf 处理恢复用户配置]
 * @param  buff [请求ID编码后的信息]
 * @param  len  [长度]
 * @return      [成功返回true]
 */
bool HotBakManager::HandleInitUserConf(const char *buff, int len)
{
    PRINT_INFO_HEAD
    print_info("init userconf type");

    char devid[DEV_ID_LEN] = {0};
    char response[60] = {0};
    char chcmd[CMD_BUF_LEN] = {0};
    char key = 0x33;
    CCommon common;

    if ((len <= 1) || (len - 1 >= (int)sizeof(devid))) {
        PRINT_ERR_HEAD
        print_err("len error[%d]", len);
    } else {
        int dlen = buff[0];
        if ((dlen < 0) || (dlen >= sizeof(devid))) {
            PRINT_ERR_HEAD
            print_err("dlen err %d", dlen);
        } else {
            memcpy(devid, buff + 1, dlen);
            common.XOR(devid, dlen, key);
            if (strcmp(m_devid, devid) == 0) {
                PRINT_INFO_HEAD
                print_info("begin to init userconf[%s]", m_devid);

                //恢复配置
                sprintf(chcmd, "cp -f %s %s", USERCONF, LAST_RULE_DIR);
                system(chcmd);
                sprintf(chcmd, "cp -f %s*.cr %s", PRECFG_DIR, LAST_RULE_DIR);
                system(chcmd);
                sprintf(chcmd, "cp -f %s %s", PASSWD, LAST_RULE_DIR);
                system(chcmd);

                sprintf(chcmd, "cp -f %s %s", ORIGINAL_USERCONF, USERCONF);
                system(chcmd);
                sprintf(chcmd, "cp -f %s*.cr %s", ORIGINAL_PRECFG_DIR, PRECFG_DIR);
                system(chcmd);
                sprintf(chcmd, "cp -f %s %s", ORIGINAL_PASSWD, PASSWD);
                system(chcmd);
                sprintf(chcmd, "%s %s %s", PUT_FILE, ORIGINAL_PASSWD, PASSWD);
                system(chcmd);

                memset(response, 0x31, sizeof(response));//约定
                int ret = m_cpack->WritePacket((const unsigned char *)response,
                                               sizeof(response), C_INIT_USERCONF_RES);
                if (ret != (int)sizeof(response)) {
                    PRINT_ERR_HEAD
                    print_err("write packet ret error[%d]. %d", ret, (int)sizeof(response));
                    return false;
                }
                return true;
            } else {
                PRINT_INFO_HEAD
                print_info("m_devid[%s].required dev[%s]", m_devid, devid);
            }
        }
    }
    return false;
}

/**
 * [HotBakManager::HandleGetCtrl 处理获取管理信息请求]
 * @return  [成功返回true]
 */
bool HotBakManager::HandleGetCtrl(void)
{
    PRINT_INFO_HEAD
    print_info("get ctrl type");

    char sendbuff[MAX_PKTSIZE] = {0};
    sprintf(sendbuff, "%s:%s:%s:%s", m_csip, m_csport, m_csmask, m_mgcliip);
    int ret = m_cpack->WritePacket((const unsigned char *)sendbuff, strlen(sendbuff), C_CTRL_INFO);
    if (ret != (int)strlen(sendbuff)) {
        PRINT_ERR_HEAD
        print_err("write packet ret error[%d].expect [%d:%s]", ret, (int)strlen(sendbuff), sendbuff);
        return false;
    }

    PRINT_INFO_HEAD
    print_info("send ctrl ok");
    return true;
}

/**
 * [HotBakManager::HandleGetInfo 处理获取详细信息请求]
 * @return  [成功返回true]
 */
bool HotBakManager::HandleGetInfo(void)
{
    PRINT_INFO_HEAD
    print_info("get info type");
    char sendbuff[MAX_PKTSIZE] = {0};

    if (MakeInfoString(sendbuff, sizeof(sendbuff))) {
        int ret = m_cpack->WritePacket((const unsigned char *)sendbuff, strlen(sendbuff), C_INFO);
        if (ret != (int)strlen(sendbuff)) {
            PRINT_ERR_HEAD
            print_err("write packet ret error[%d].expect [%d]", ret, (int)strlen(sendbuff));
        } else {
            PRINT_INFO_HEAD
            print_info("send info ok");
            return true;
        }
    } else {
        PRINT_ERR_HEAD
        print_err("make info string fail");
    }
    return false;
}

/**
 * [HotBakManager::HandleGetRule 处理策略同步请求]
 *协议：
 *   devid       |selfId    |InnerDevType|
 *   目标主设备ID|自身设备ID|内部硬件型号|
 * @param  buff [请求信息]
 * @param  len  [请求信息长度]
 * @return      [成功返回true]
 */
bool HotBakManager::HandleGetRule(const char *buff, int len)
{
    PRINT_DBG_HEAD
    print_dbg("get rule type");

    const char *p1 = NULL, *p2 = NULL, *p3 = NULL;
    char slaveid[DEV_ID_LEN] = {0};
    char masterid[DEV_ID_LEN] = {0};
    char inner_type[11] = {0};

    if ((buff == NULL)
        || ((p1 = strchr(buff, '|')) == NULL)
        || ((p2 = strchr(p1 + 1, '|')) == NULL)
        || ((p3 = strchr(p2 + 1, '|')) == NULL)) {
        PRINT_ERR_HEAD
        print_err("format err[%s]", buff);
        return false;
    }

    if (((p1 - buff) >= (int)sizeof(masterid))
        || ((p2 - p1 - 1) >= (int)sizeof(slaveid))) {
        PRINT_ERR_HEAD
        print_err("ID too long[%s]", buff);
        return false;
    }

    memcpy(masterid, buff, p1 - buff);
    memcpy(slaveid, p1 + 1, p2 - p1 - 1);
    memcpy(inner_type, p2 + 1, 10);

    if (strcmp(masterid, m_devid) != 0) {
        PRINT_INFO_HEAD
        print_info("m_devid[%s].required dev[%s]", m_devid, masterid);
        return false;
    }

    if (strcmp(masterid, slaveid) == 0) {
        PRINT_ERR_HEAD
        print_err("master and slave can not be the same.[%s]", masterid);
        WriteSysLog(LOG_TYPE_HA_RULE, D_FAIL, LOG_CONTENT_MAINDEV_SELF);
        return false;
    }

    if (strcmp(inner_type, m_inner_devtype) != 0) {
        PRINT_ERR_HEAD
        print_err("innerdevtype err.[%s:%s]", m_inner_devtype, inner_type);
        WriteSysLog(LOG_TYPE_HA_RULE, D_FAIL, LOG_CONTENT_INNERDEVTYPE_ERR);
        return false;
    }

    if (SendRules() < 0) {
        PRINT_ERR_HEAD
        print_err("send rules fail. masterid[%s]", masterid);
        unlink(SRULES_TAR_PATH);
        return false;
    }

    unlink(SRULES_TAR_PATH);
    PRINT_DBG_HEAD
    print_dbg("send rule success");
    WriteSysLog(LOG_TYPE_HA_RULE, D_SUCCESS, LOG_CONTENT_HA_RULE_TOSLAVE_OK);
    return true;
}

/**
 * [HotBakManager::HandleHB 处理热备心跳请求]
 * @param  buff [请求信息]
 * @param  len  [请求长度]
 * @return      [成功返回true]
 */
bool HotBakManager::HandleHB(const char *buff, int len)
{
    unsigned char sendbuff[MAX_PKTSIZE] = {0};
    HEART_BEAT_REQ request;
    HEART_BEAT_RES_HEAD response_head;
    int ret = 0;
    int wlen = 0;

    PRINT_DBG_HEAD
    print_dbg("handle HB len[%d]", len);

    if (len != sizeof(HEART_BEAT_REQ)) {
        PRINT_ERR_HEAD
        print_err("hb request len error[%d].expect[%d]", len, (int)sizeof(HEART_BEAT_REQ));
        return false;
    }
    memcpy(&request, buff, len);
    if (strcmp(m_devid, request.masterid) != 0) {
        PRINT_INFO_HEAD
        print_info("mydevid[%s] masterid[%s]", m_devid, request.masterid);
        return false;
    }

    if (strcmp(request.masterid, request.slaveid) == 0) {
        PRINT_ERR_HEAD
        print_err("master and slave is the same.[%s]", request.masterid);
        WriteSysLog(LOG_TYPE_HEARTBEAT, D_FAIL, LOG_CONTENT_MAINDEV_SELF);
        return false;
    }

    //保存从设备的信息
    m_lasthb_req = time(NULL);
    memcpy(&m_slavestatus, &(request.slavestatus), sizeof(m_slavestatus));
    strcpy(m_slaveid, request.slaveid);
    m_slaverun = request.slaverun;
    sem_post(&m_wrconf_sem);

    //准备回应信息
    BZERO(response_head);
    if (m_run == 1) {
        response_head.hb_result = (m_status[NIC_INDEX] == 1) ? HB_OK : HB_FAIL;
    } else {
        response_head.hb_result = (m_b_master) ? HB_FAIL : HB_OK;
    }
    response_head.seqid = request.seqid;
    response_head.masterrun = m_run;
    memcpy(&(response_head.masterstatus), &m_status, sizeof(m_status));
    response_head.nicnum_in = m_nicnum_in;
    response_head.nicnum_out = m_nicnum_out;
    memcpy(sendbuff, &response_head, sizeof(response_head));
    wlen = sizeof(response_head);
    memcpy(sendbuff + wlen, &m_nicin, sizeof(m_nicin[0]) * m_nicnum_in);
    wlen += sizeof(m_nicin[0]) * m_nicnum_in;
    memcpy(sendbuff + wlen, &m_nicout, sizeof(m_nicout[0]) * m_nicnum_out);
    wlen += sizeof(m_nicout[0]) * m_nicnum_out;

    for (int i = 0; i < m_nicnum_in; ++i) {
        PRINT_DBG_HEAD
        print_dbg("hb response to slave.in  ethname[%s]mac[%s]", m_nicin[i].ethname, m_nicin[i].mac);
    }
    for (int i = 0; i < m_nicnum_out; ++i) {
        PRINT_DBG_HEAD
        print_dbg("hb response to slave.out ethname[%s]mac[%s]", m_nicout[i].ethname, m_nicout[i].mac);
    }

    ret = m_cpack->WritePacket(sendbuff, wlen, C_HEARTBEAT_RES);
    if (ret != wlen) {
        PRINT_ERR_HEAD
        print_err("write packet ret[%d]. expect [%d]", ret, wlen);
        return false;
    }
    PRINT_DBG_HEAD
    print_dbg("send heartbeat result over ret[%d]res[%d]seqid[%d]innicnum[%d]outnicnum[%d]",
              ret, response_head.hb_result, response_head.seqid, response_head.nicnum_in,
              response_head.nicnum_out);
    return true;
}

/**
 * [HotBakManager::HandleHBResult 处理热备心跳响应]
 * @param  buff [响应信息]
 * @param  len  [响应长度]
 * @return      [成功返回true]
 */
bool HotBakManager::HandleHBResult(const char *buff, int len)
{
    HEART_BEAT_RES_HEAD response_head;

    if (len < (int)sizeof(response_head)) {
        PRINT_ERR_HEAD
        print_err("len too short[%d]", len);
        return false;
    }
    memcpy(&response_head, buff, sizeof(response_head));

    PRINT_DBG_HEAD
    print_dbg("hb result len = %d", len);

    //校验
    if ((response_head.nicnum_in < 0)
        || (response_head.nicnum_in > MAX_NIC_NUM)
        || (response_head.nicnum_out < 0 )
        || (response_head.nicnum_out > MAX_NIC_NUM)
        || (response_head.seqid < 0)
        || (response_head.seqid >= HB_RESULT_NUM)) {

        PRINT_ERR_HEAD
        print_err("seqid[%d] in nicnum[%d] out nicnum[%d]", response_head.seqid,
                  response_head.nicnum_in, response_head.nicnum_out);
        return false;
    }

    //校验
    if ((len - sizeof(response_head)) <
        ((response_head.nicnum_in + response_head.nicnum_out) * sizeof(NIC_MAC_STRUCT))) {

        PRINT_ERR_HEAD
        print_err("seqid[%d] len[%d] too short. in nicnum[%d] out nicnum[%d]",
                  response_head.seqid, len, response_head.nicnum_in, response_head.nicnum_out);
        return false;
    }

    //保存结果信息
    m_masterrun = response_head.masterrun;
    memcpy(&m_masterstatus, &(response_head.masterstatus), sizeof(m_masterstatus));
    m_master_nicnum_in = response_head.nicnum_in;
    m_master_nicnum_out = response_head.nicnum_out;
    memcpy(&m_master_nicin, buff + sizeof(response_head), m_master_nicnum_in * sizeof(NIC_MAC_STRUCT));
    memcpy(&m_master_nicout, buff + sizeof(response_head) + m_master_nicnum_in * sizeof(NIC_MAC_STRUCT),
           m_master_nicnum_out * sizeof(NIC_MAC_STRUCT));
    m_heartbeat_res[response_head.seqid] = response_head.hb_result;
    m_lasthb_res = time(NULL);

    for (int i = 0; i < m_master_nicnum_in; ++i) {
        PRINT_DBG_HEAD
        print_dbg("seqid[%d] master in  ethname[%s] mac[%s]", response_head.seqid,
                  m_master_nicin[i].ethname, m_master_nicin[i].mac);
    }
    for (int i = 0; i < m_master_nicnum_out; ++i) {
        PRINT_DBG_HEAD
        print_dbg("seqid[%d] master out ethname[%s] mac[%s]", response_head.seqid,
                  m_master_nicout[i].ethname, m_master_nicout[i].mac);
    }

    //通知客户端线程处理
    sem_post(&m_heartbeat_sem);
    sem_post(&m_wrconf_sem);
    return true;
}

/**
 * [HotBakManager::SlaveRulesRequest 向主机发送策略同步请求]
 * @return  [成功返回true]
 */
bool HotBakManager::SlaveRulesRequest(void)
{
    unsigned char sendbuff[256] = {0};

    //请求策略文件
    BZERO(sendbuff);
    sprintf((char *)sendbuff, "%s|%s|%s|", m_masterid, m_devid, m_inner_devtype);
    int wlen = strlen((char *)sendbuff);

    //发送策略同步请求
    int ret = m_cpack->WritePacket(sendbuff, wlen, C_GET_RULES);
    if (ret != wlen) {
        PRINT_ERR_HEAD
        print_err("send get rule request ret[%d]. expect[%d]", ret, wlen);
        return false;
    }
    return true;
}

/**
 * [HotBakManager::SlaveHBRequest 向主机发送心跳探测请求]
 * @param  seqid     [顺序号 为了确定请求和响应的对应关系]
 * @return           [发送成功返回true]
 */
bool HotBakManager::SlaveHBRequest(int seqid)
{
    if ((seqid < 0) || (seqid >= HB_RESULT_NUM)) {
        PRINT_ERR_HEAD
        print_err("seqid error[%d]", seqid);
        return false;
    }
    HEART_BEAT_REQ request;
    BZERO(request);

    strcpy(request.masterid, m_masterid);
    strcpy(request.slaveid, m_devid);
    request.seqid = seqid;
    request.slaverun = m_run;
    memcpy(&(request.slavestatus), &m_status, sizeof(m_status));

    m_heartbeat_res[seqid] = HB_INVALID;
    int ret = m_cpack->WritePacket((const unsigned char *)&request, sizeof(request), C_HEARTBEAT);
    if (ret != (int)sizeof(request)) {
        PRINT_ERR_HEAD
        print_err("send heartbeat request ret[%d]. expect[%d]", ret, (int)sizeof(request));
        return false;
    }
    return true;
}

/**
 * [HotBakManager::SlaveWaitHBResult 备机等待心跳结果]
 * @param  result   [心跳结果]
 * @param  seqid    [顺序号]
 * @return          [获取结果成功返回true  超时也算成功]
 */
bool HotBakManager::SlaveWaitHBResult(HB_RESULT &result, int seqid)
{
    if ((seqid < 0) || (seqid >= HB_RESULT_NUM)) {
        PRINT_ERR_HEAD
        print_err("seqid error[%d]", seqid);
        return false;
    }

    while (1) {
        //超时时间1s
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;

        int ret = sem_timedwait(&(m_heartbeat_sem), &ts);
        if (ret == 0) {
            if (m_heartbeat_res[seqid] == HB_INVALID) {
                //等于 HB_INVALID 说明不是刚才发出的心跳的回应
                PRINT_INFO_HEAD
                print_info("not my response, wait again. seqid[%d]", seqid);
            } else {
                result = m_heartbeat_res[seqid];
                break;
            }
        } else { //超时
            result = HB_TMOUT;
            sem_post(&m_wrconf_sem);
            break;
        }
    }

    PRINT_DBG_HEAD
    print_dbg("result is %d. seqid[%d]", result, seqid);
    return true;
}

/**
 * [HotBakManager::SlaveHandleHBResult 备机处理心跳结果]
 * @param result      [心跳结果]
 * @param timeout_cnt [超时计数]
 */
void HotBakManager::SlaveHandleHBResult(HB_RESULT &result, int &timeout_cnt)
{
    switch (result) {
    case HB_OK:
        timeout_cnt = 0;
        if (m_run == 1) {
            //停掉备机 清空现场
            WriteSysLog(LOG_TYPE_HEARTBEAT, D_SUCCESS, LOG_CONTENT_PARENT_OK_I_STOP);
            PRINT_INFO_HEAD
            print_info("master is running, slave stop");
            SlaveSwitch(false);
        } else {
            //把外网网卡down掉
            for (int i = 0; i < m_master_nicnum_out; i++) {
                char chcmd[40] = {0};
                sprintf(chcmd, "ifconfig %s down", m_master_nicout[i].ethname);
                PeerExecuteCMD(chcmd);
                PRINT_INFO_HEAD
                print_info("master is running, slave down outnet card[%s]", m_master_nicout[i].ethname);
            }
        }
        break;
    case HB_FAIL:
        timeout_cnt = 0;
        if (m_run == 1) {
            Alarm();
        } else {
            WriteSysLog(LOG_TYPE_HEARTBEAT, D_SUCCESS, LOG_CONTENT_WANT_SWITCH);
            PRINT_INFO_HEAD
            print_info("master is something wrong, slave take place of master");
            SlaveSwitch(true);
        }
        break;
    case HB_TMOUT:
        if (m_run == 1) {
            Alarm();
        } else {
            timeout_cnt++;
            if (timeout_cnt > m_maxheartfail) {
                WriteSysLog(LOG_TYPE_HEARTBEAT, D_FAIL, LOG_CONTENT_HEARTBEAT_FAIL_I_RUN);
                PRINT_INFO_HEAD
                print_info("heartbeat timeout too many times[%d], slave begin to run", timeout_cnt);
                SlaveSwitch(true);
            }
        }
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown heartbeat result type[%d]", result);
        break;
    }
}

/**
 * [HotBakManager::SlaveSwitch 从机切机]
 * @param   brun [运行 or 停止]
 * @return  [成功返回true]
 */
bool HotBakManager::SlaveSwitch(bool brun)
{
    if (brun) {
        SetMac(m_master_nicin, m_master_nicnum_in, false);
        SetMac(m_master_nicout, m_master_nicnum_out, true);
        StartBS();
        system("killall -s SIGUSR1 recvmain"); //让recvmain重读IP等配置信息
        m_run = 1;
    } else {
        StopBS();
        m_run = 0;
    }
    sem_post(&m_wrconf_sem);
    return true;
}

/**
 * [HotBakManager::CheckRulesFile 对同步到备机的策略文件进行md5完整性校验]
 * @param  md5str32 [主机发送过来的 md5串]
 * @return          [校验通过返回true]
 */
bool HotBakManager::CheckRulesFile(const char *md5str32)
{
    unsigned char md5_str[33] = {0};
    if (md5sum(RRULES_TAR_PATH, md5_str) < 0) { //本地的
        PRINT_ERR_HEAD
        print_err("md5sum error[%s]", RRULES_TAR_PATH);
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("begin compare md5");

    if (memcmp(md5str32, md5_str, 32) == 0) {
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("md5 compare fail");
        WriteSysLog(LOG_TYPE_HA_RULE, D_FAIL, LOG_CONTENT_RULE_CHECK_FAIL);
        unlink(RRULES_TAR_PATH);
        return false;
    }
}

/**
 * [HotBakManager::CoverRulesFile 备机使用主机同步过来的策略覆盖现有策略]
 * @return  [成功返回true]
 */
bool HotBakManager::CoverRulesFile(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    system("rm -rf /tmp/var/");
    sprintf(chcmd, "tar -xzf %s -C /tmp/", RRULES_TAR_PATH);
    system(chcmd);
    unlink(RRULES_TAR_PATH);

    //修改不准改变的字段
    CFILEOP fileop;
    sprintf(chcmd, "/tmp%s", SYSSET_CONF);
    if (fileop.OpenFile(chcmd, "r+") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file[%s] fail", chcmd);
        system("rm -rf /tmp/var/");
        return false;
    }

    fileop.WriteCfgFile("SYSTEM", "CSIP", m_csip);
    fileop.WriteCfgFile("SYSTEM", "CSPort", m_csport);
    fileop.WriteCfgFile("SYSTEM", "CSMask", m_csmask);
    fileop.WriteCfgFile("SYSTEM", "MGClientIP", m_mgcliip);
    fileop.WriteCfgFileInt("SYSTEM", "MainDev", m_b_master ? 1 : 0);
    fileop.WriteCfgFile("SYSTEM", "MainDevice", m_masterid);
    fileop.WriteCfgFileInt("SYSTEM", "CKHotbakRules", m_b_tran_rule ? 1 : 0);
    fileop.WriteCfgFileInt("SYSTEM", "HotbakRulesCycle", m_tran_rule_cycle);
    fileop.WriteCfgFileInt("SYSTEM", "CKWebLoginTX", m_ckweblogintx);
    fileop.WriteCfgFileInt("SYSTEM", "CKLineSwitch", m_cklineswitch);
    fileop.CloseFile();

    system("cp -rf /tmp/var/*  /var/");
    system("rm -rf /tmp/var/");

    WriteSysLog(LOG_TYPE_HA_RULE, D_SUCCESS, LOG_CONTENT_HA_RULE_FROMMASTER_OK);
    PRINT_DBG_HEAD
    print_dbg("cover rule success");
    return true;
}

/**
 * [HotBakManager::WriteConf 写WEB展示热备相关信息的配置文件]
 *                           对于主机的运行状态 是按网卡状态来计算的
 * @return  [成功返回true]
 */
#define GREEN   1
#define RED     0
#define YELLOW -1
bool HotBakManager::WriteConf(void)
{
    CFILEOP fileop;
    if (fileop.OpenFile(HOTBAK_SHOW_PATH, "wb+") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", HOTBAK_SHOW_PATH);
        return false;
    }

    fileop.WriteCfgFileInt("SYSTEM", "ROLE", m_b_master ? 1 : 0);
    fileop.WriteCfgFileInt("SYSTEM", "TMOUTCOLOR", (m_hbconf.timeout != 1) ? GREEN : RED);
    fileop.WriteCfgFile("SYSTEM", "TMOUTDESC", (m_hbconf.timeout == 1) ? HOTBAK_TIMEOUT : HOTBAK_NOT_TIMEOUT);
    //ID
    fileop.WriteCfgFileInt("MASTER", "IDCOLOR", GREEN);
    fileop.WriteCfgFile("MASTER", "ID", m_hbconf.masterid);
    fileop.WriteCfgFileInt("SLAVE", "IDCOLOR", (strlen(m_hbconf.slaveid) != 0) ? GREEN : YELLOW);
    fileop.WriteCfgFile("SLAVE", "ID", (strlen(m_hbconf.slaveid) != 0) ? m_hbconf.slaveid : UNKNOWN_STRING);

    if (m_hbconf.timeout == 1) {
        if (m_b_master) {
            WriteMasterRunInfo(fileop);
            WriteMasterStatusInfo(fileop);
            fileop.WriteCfgFileInt("SLAVE", "RUNCOLOR", YELLOW);
            fileop.WriteCfgFile("SLAVE", "RUNDESC", UNKNOWN_STRING);
            fileop.WriteCfgFileInt("SLAVE", "STATUSCOLOR", YELLOW);
            fileop.WriteCfgFile("SLAVE", "STATUSDESC", UNKNOWN_STRING);
        } else {
            fileop.WriteCfgFileInt("MASTER", "RUNCOLOR", YELLOW);
            fileop.WriteCfgFile("MASTER", "RUNDESC", UNKNOWN_STRING);
            fileop.WriteCfgFileInt("MASTER", "STATUSCOLOR", YELLOW);
            fileop.WriteCfgFile("MASTER", "STATUSDESC", UNKNOWN_STRING);
            WriteSlaveRunInfo(fileop);
            WriteSlaveStatusInfo(fileop);
        }
    } else {
        WriteMasterRunInfo(fileop);
        WriteSlaveRunInfo(fileop);
        WriteMasterStatusInfo(fileop);
        WriteSlaveStatusInfo(fileop);
    }

    fileop.CloseFile();
    return true;
}

/**
 * [HotBakManager::WriteMasterRunInfo 把与“运行状态”相关MASTER信息写入配置文件]
 * @param fileop [文件操作对象]
 */
void HotBakManager::WriteMasterRunInfo(CFILEOP &fileop)
{
    if ((m_hbconf.masterrun == 1) && (m_hbconf.masterstatus[NIC_INDEX] == 1)) {
        fileop.WriteCfgFileInt("MASTER", "RUNCOLOR", GREEN);
        fileop.WriteCfgFile("MASTER", "RUNDESC", HOTBAK_RUN_OK);
    } else {
        fileop.WriteCfgFileInt("MASTER", "RUNCOLOR", RED);
        fileop.WriteCfgFile("MASTER", "RUNDESC", HOTBAK_RUN_STOP);
    }
}

/**
 * [HotBakManager::WriteSlaveRunInfo 把与“运行状态”相关SLAVE信息写入配置文件]
 * @param fileop [文件操作对象]
 */
void HotBakManager::WriteSlaveRunInfo(CFILEOP &fileop)
{
    if ((m_hbconf.slaverun == 1) && (m_hbconf.slavestatus[NIC_INDEX] == 1)) {
        fileop.WriteCfgFileInt("SLAVE", "RUNCOLOR", GREEN);
        fileop.WriteCfgFile("SLAVE", "RUNDESC", HOTBAK_RUN_OK);
    } else {
        fileop.WriteCfgFileInt("SLAVE", "RUNCOLOR", RED);
        fileop.WriteCfgFile("SLAVE", "RUNDESC", HOTBAK_RUN_STOP);
    }
}

/**
 * [HotBakManager::WriteMasterStatusInfo 把与“系统状态”相关MASTER信息写入配置文件]
 * @param fileop [文件操作对象]
 */
void HotBakManager::WriteMasterStatusInfo(CFILEOP &fileop)
{
    if (m_hbconf.masterstatus[NIC_INDEX] == 1) {
        fileop.WriteCfgFileInt("MASTER", "STATUSCOLOR", GREEN);
        fileop.WriteCfgFile("MASTER", "STATUSDESC", HOTBAK_STATUS_OK);
    } else {
        fileop.WriteCfgFileInt("MASTER", "STATUSCOLOR", RED);
        fileop.WriteCfgFile("MASTER", "STATUSDESC", HOTBAK_STATUS_NIC_BAD);
    }
}

/**
 * [HotBakManager::WriteSlaveStatusInfo 把与“系统状态”相关SLAVE信息写入配置文件]
 * @param fileop [文件操作对象]
 */
void HotBakManager::WriteSlaveStatusInfo(CFILEOP &fileop)
{
    if (m_hbconf.slavestatus[NIC_INDEX] == 1) {
        fileop.WriteCfgFileInt("SLAVE", "STATUSCOLOR", GREEN);
        fileop.WriteCfgFile("SLAVE", "STATUSDESC", HOTBAK_STATUS_OK);
    } else {
        fileop.WriteCfgFileInt("SLAVE", "STATUSCOLOR", RED);
        fileop.WriteCfgFile("SLAVE", "STATUSDESC", HOTBAK_STATUS_NIC_BAD);
    }
}

/**
 * [HotBakManager::PrintHBConfInfo 打印即将写入配置文件的信息]
 * @param info [结构体信息]
 */
void HotBakManager::PrintHBConfInfo(HB_CONF_FILE_INFO &info)
{
    PRINT_DBG_HEAD
    print_dbg("role[%d],timeout[%d]", m_b_master ? 1 : 0, info.timeout);
    PRINT_DBG_HEAD
    print_dbg("masterid[%s],masterrun[%d],masterstatus0[%d]",
              info.masterid, info.masterrun, info.masterstatus[NIC_INDEX]);
    PRINT_DBG_HEAD
    print_dbg("slaveid[%s],slaverun[%d],slavestatus0[%d]",
              info.slaveid, info.slaverun, info.slavestatus[NIC_INDEX]);
}

/**
 * [HotBakManager::WriteSysLog 写系统日志]
 * @param  logtype [日志类型]
 * @param  result  [日志结果 成功 、失败、等]
 * @param  remark  [备注]
 * @return         [成功返回0]
 */
int HotBakManager::WriteSysLog(const char *logtype, const char *result, const char *remark)
{
    CLOGMANAGE mlog;
    mlog.Init();
    mlog.WriteSysLog(logtype, result, remark);
    mlog.DisConnect();
    return 0;
}
/**
 * [HotBakManager::SetInRoute 设置内网侧管理口路由]
 */
void HotBakManager::SetInRoute(void)
{
    PRINT_DBG_HEAD
    print_dbg("begin to set route of man port");
    char csgw[IP_STR_LEN] = {0};
    char csipv6[IP_STR_LEN] = {0};
    char csgwipv6[IP_STR_LEN] = {0};
    char chcmd[CMD_BUF_LEN] = {0};
    CFILEOP fileop;

    if (fileop.OpenFile(SYSSET_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", DEV_CONF);
        return ;
    }

    READ_STRING(fileop, "SYSTEM", "CSGW", csgw, false, _out);
    if (!IS_STR_EMPTY(csgw)) {
        sprintf(chcmd, "route add default gw '%s' metric 200", csgw);
        system_safe(chcmd);
        PRINT_DBG_HEAD
        print_dbg("ipv4 defgw[%s]", chcmd);
    }

#if (SUPPORT_IPV6==1)
    READ_STRING(fileop, "SYSTEM", "CSIPv6", csipv6, false, _out);
    READ_STRING(fileop, "SYSTEM", "CSGWIPv6", csgwipv6, false, _out);
    if (!IS_STR_EMPTY(csipv6)) {
        if (!IS_STR_EMPTY(csgwipv6)) {
            sprintf(chcmd, "route -A inet6 add default gw '%s' metric 200", csgwipv6);
            system_safe(chcmd);
            PRINT_DBG_HEAD
            print_dbg("ipv6 defgw[%s]", chcmd);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("csipv6 error[%s]", csipv6);
    }
#endif

_out:
    fileop.CloseFile();
    PRINT_DBG_HEAD
    print_dbg("end of set in route");
    return ;
}
