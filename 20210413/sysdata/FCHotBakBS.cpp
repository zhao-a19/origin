/*******************************************************************************************
*文件:  FCHotBakBS.cpp
*描述:  负责轮询监视使用中的通信口网线连接状态 并汇报给hotbakmain进程
*作者:  王君雷
*日期:  2015
*修改:
*       通信口异常恢复后，killall dbsync，让dbsync重启，防止卡住        ------> 2018-04-26
*       完善注释信息,引入zlog                                           ------> 2018-11-21
*       汇报协议添加汇报头部,以后可以扩展,以便汇报更多类型的告警信息    ------> 2018-11-22
*       新增InNetMonitor、OutNetMonitor等函数，缩小ListenFunc函数体行数 ------> 2018-11-27
*       组汇报报文时使用NIC_REPORT_HEAD结构                             ------> 2018-12-03
*       负载均衡网卡，通信口检查时，不再每个周期都up、down一次          ------> 2019-01-04
*       通信口检查时，根据选项UpDownCard决定是否需要周期性up down网卡   ------> 2019-11-08
*       获取系统状态线程移动到recvmain，编译不过问题                    ------> 2019-11-19-dzj
*       当不支持蜂鸣器时不用包含sys/io.h头文件                          ------> 2020-05-15
*       外网侧添加网卡状态监测功能                                      ------> 2020-06-22
*       解决通过输入框、下拉框填写的路由列表，热备切换后外网侧丢失路由的问题 ------> 2020-08-31 wjl
*       可以设置线程名称                                                ------> 2021-02-23
*******************************************************************************************/
#include <sys/wait.h>
#include <time.h>
#include "FCHotBakBS.h"
#include "quote_global.h"
#include "struct_info.h"
#include "FCMsgAck.h"
#include "fileoperator.h"
#include "FCPeerExecuteCMD.h"
#include "hardinfo.h"
#include "debugout.h"
#include "outcheck.h"
#include "card_mg.h"

#define ALL_CARD_NORMAL -100

extern int g_linklanipseg;
extern int g_linklanport;

CHOTBAKBS::CHOTBAKBS(void)
{
    m_devbs = NULL;
    m_ywbs = NULL;
    BZERO(m_outdefgw);

    m_nicnum_in = 0;
    m_nicnum_out = 0;
    BZERO(m_nic_in);
    BZERO(m_nic_out);
    ReadOutDefGW();
}

CHOTBAKBS::~CHOTBAKBS(void)
{
}

/**
 * [CHOTBAKBS::ReadOutDefGW 读取外网侧默认网关]
 * @return  [对取成功返回0]
 */
int CHOTBAKBS::ReadOutDefGW(void)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(DEV_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", DEV_CONF);
        return -1;
    }

    m_fileop.ReadCfgFile("OUTNET", "DefGW", m_outdefgw, sizeof(m_outdefgw));
    m_fileop.CloseFile();
    return 0;
}

/**
 * [CHOTBAKBS::SetDevBS 设置对应的设备信息交互类]
 * @param p_devbs [对象指针]
 */
void CHOTBAKBS::SetDevBS(CDEVBS *p_devbs)
{
    m_devbs = p_devbs;
}

/**
 * [CHOTBAKBS::SetYWBS 设置对应的业务处理交互类]
 * @param p_devbs [对象指针]
 */
void CHOTBAKBS::SetYWBS(CYWBS *p_ywbs)
{
    m_ywbs = p_ywbs;
}

/**
 * [CHOTBAKBS::CollectMacInNet 汇总内网侧的使用中网卡的MAC信息]
 */
void CHOTBAKBS::CollectMacInNet(void)
{
    char mac[MAC_STR_LEN] = {0};
    m_nicnum_in = 0;

    for (int i = 0; i < (int)g_ethin.size(); i++) {

        if (m_nicnum_in >= MAX_NIC_NUM) {
            PRINT_INFO_HEAD
            print_info("card full[%d:%d]", m_nicnum_in, (int)g_ethin.size());
            break;
        }

        BZERO(mac);
        while (!get_mac(g_ethin[i], mac)) {
            PRINT_ERR_HEAD
            print_err("get mac fail retry[%d]", g_ethin[i]);
            sleep(1);
        }

        if (ANMIT_BOND_NO == g_ethin[i]) {
            sprintf(m_nic_in[m_nicnum_in].ethname, "bond0");
            sprintf(m_nic_in[m_nicnum_in].mac, "%s", mac);
            m_nicnum_in++;

            for (int j = 0; j < m_ywbs->m_sysrulesbs->m_inbonding->devnum; j++) {
                if (m_nicnum_in >= MAX_NIC_NUM) {
                    PRINT_INFO_HEAD
                    print_info("card full[%d:%d]", m_nicnum_in,
                               m_ywbs->m_sysrulesbs->m_inbonding->devnum);
                    break;
                }

                int tmpno = m_ywbs->m_sysrulesbs->m_inbonding->dev[j];
                BZERO(mac);
                while (!get_mac(tmpno, mac)) {
                    PRINT_ERR_HEAD
                    print_err("bond get mac fail retry[%d]", tmpno);
                    sleep(1);
                }

                sprintf(m_nic_in[m_nicnum_in].ethname, "eth%d", tmpno);
                sprintf(m_nic_in[m_nicnum_in].mac, "%s", mac);
                m_nicnum_in++;
            }
        } else {
            sprintf(m_nic_in[m_nicnum_in].ethname, "eth%d", g_ethin[i]);
            sprintf(m_nic_in[m_nicnum_in].mac, "%s", mac);
            m_nicnum_in++;
        }
    }
}

/**
 * [CHOTBAKBS::CollectMacOutNet 汇总外网侧的使用中网卡的MAC信息]
 */
void CHOTBAKBS::CollectMacOutNet(void)
{
    char mac[MAC_STR_LEN] = {0};
    m_nicnum_out = 0;

    for (int i = 0; i < (int)g_ethout.size(); i++) {
        if (m_nicnum_out >= MAX_NIC_NUM) {
            PRINT_INFO_HEAD
            print_info("card full[%d:%d]", m_nicnum_out, (int)g_ethout.size());
            break;
        }

        BZERO(mac);
        while (!get_out_mac(g_ethout[i], mac)) {
            PRINT_ERR_HEAD
            print_err("get mac fail retry[%d]", g_ethout[i]);
            sleep(1);
        }

        if (ANMIT_BOND_NO == g_ethout[i]) {
            sprintf(m_nic_out[m_nicnum_out].ethname, "bond0");
            sprintf(m_nic_out[m_nicnum_out].mac, "%s", mac);
            m_nicnum_out++;

            for (int j = 0; j < m_ywbs->m_sysrulesbs->m_outbonding->devnum; j++) {
                if (m_nicnum_out >= MAX_NIC_NUM) {
                    PRINT_INFO_HEAD
                    print_info("card full[%d:%d]", m_nicnum_out,
                               m_ywbs->m_sysrulesbs->m_outbonding->devnum);
                    break;
                }

                int tmpno = m_ywbs->m_sysrulesbs->m_outbonding->dev[j];
                BZERO(mac);
                while (!get_out_mac(tmpno, mac)) {
                    PRINT_ERR_HEAD
                    print_err("bond get mac fail retry[%d]", tmpno);
                    sleep(1);
                }

                sprintf(m_nic_out[m_nicnum_out].ethname, "eth%d", tmpno);
                sprintf(m_nic_out[m_nicnum_out].mac, "%s", mac);
                m_nicnum_out++;
            }
        } else {
            sprintf(m_nic_out[m_nicnum_out].ethname, "eth%d", g_ethout[i]);
            sprintf(m_nic_out[m_nicnum_out].mac, "%s", mac);
            m_nicnum_out++;
        }
    }
}

/**
 * [CHOTBAKBS::CollectMac 汇总使用中的网卡的MAC信息,向hotbakmain汇报时会使用]
 */
void CHOTBAKBS::CollectMac(void)
{
    CollectMacInNet();
    CollectMacOutNet();
}

/**
 * [ListenFunc 负责汇总MAC信息，需要时检查网卡连通情况，并定期向hotbakmain汇报]
 * @param  param [对象指针]
 * @return       [未使用]
 */
void *ListenFunc(void *param)
{
    pthread_setname("listenfunc");
    if (param == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    CHOTBAKBS *p_this = (CHOTBAKBS *)param;
    int rptfd = 0;
    while ((rptfd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail[%s],retry", strerror(errno));
        sleep(1);
    }

    struct sockaddr_un peer_addr;
    BZERO(peer_addr);
    peer_addr.sun_family = PF_UNIX;
    strcpy(peer_addr.sun_path, UNIX_REPORT_SRV_PATH);

    int nicstatus = NIC_STATUS_OK;  //当前网卡状态
    int badarea = 0;                //网卡被拔掉的位置 内网0 外网1
    char badethname[32] = {0};      //被拔掉的网口名
    int badethno = ALL_CARD_NORMAL; //ALL_CARD_NORMAL 表示正常 没有bad网卡
    char report[64 * 1024] = {0};
    int sendlen = 0;
    bool firsttime = true;
    PNIC_REPORT_HEAD pnichead = (PNIC_REPORT_HEAD)(report + sizeof(REPORT_HEAD));

    while (1) {
        if (g_cardchange) {
            if (firsttime) {
                firsttime = false;
            } else {
                p_this->UpInNet();
                p_this->UpOutNet();
                sleep(4);
            }
            PRINT_INFO_HEAD
            print_info("loading card info");
            nicstatus = NIC_STATUS_OK;
            badethno = ALL_CARD_NORMAL;
            BZERO(badethname);
            p_this->CollectMac();
            sendlen = p_this->MakeReportInfo(report, sizeof(report), nicstatus);
            g_cardchange = false;
        }

        if (p_this->m_devbs->m_cklineswitch == 1) {
            if (badethno == ALL_CARD_NORMAL) {
                if (p_this->InNetMonitor(badethno, badethname, badarea)
                    && p_this->OutNetMonitor(badethno, badethname, badarea)) {
                    nicstatus = NIC_STATUS_OK;
                } else {
                    nicstatus = NIC_STATUS_ERR;
                    if (badarea == 0) {
                        p_this->DownInNet(badethno);
                        p_this->DownOutNet();
                    } else {
                        p_this->DownInNet();
                        p_this->DownOutNet(badethno);
                    }
                }
            } else { //上次循环有被拔掉的网口
                if (p_this->GetBadCardStatus(badethno, badethname, badarea) == 1) {
                    BZERO(badethname);
                    badethno = ALL_CARD_NORMAL;
                    p_this->UpInNet();
                    p_this->UpOutNet();
                    p_this->m_ywbs->SetRouteList(1);
                    p_this->m_ywbs->SetDefGW();
                    p_this->SetOutRoute();
                    system("killall dbsync");
                    sleep(4);
                } else {
                    if (badarea == 0) {
                        p_this->UpDownInNet(badethno);
                        p_this->UpDownOutNet();
                    } else {
                        p_this->UpDownInNet();
                        p_this->UpDownOutNet(badethno);
                    }
                }
            }
        }

        pnichead->status = nicstatus;
        if (sendto(rptfd, report, sendlen, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
            PRINT_ERR_HEAD
            print_err("sendto hotbakmain fail[%s]", strerror(errno));
        } else {
            //report ok
        }
        sleep(1);
    }

    PRINT_ERR_HEAD
    print_err("nic report thread will exit");
    return NULL;
}

/**
 * [CHOTBAKBS::Start 运行]
 * @return  [成功返回true]
 */
bool CHOTBAKBS::Start(void)
{
    if (!m_ywbs->Start()) {
        PRINT_ERR_HEAD
        print_err("ywbs start fail");
    }

    if (DEVFLAG[0] == 'I') {
        m_hotbakth.ThCreate(ListenFunc, (void *)this);
    } else {
        if (m_devbs->m_cklineswitch == 1) {
            StartOutCheck(&(m_devbs->m_linklan));
        }
    }
    m_ctrlth.ThCreate(CtrlFunc, (void *)this);
    return true;
}

/**
 * [CHOTBAKBS::DownInNet DOWN内网卡,把除了except_eth之外的内网卡DOWN掉]
 * @param  except_eth [例外网卡]
 * @return            [成功返回0]
 */
int CHOTBAKBS::DownInNet(int except_eth)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < (int)g_ethin.size(); i++) {
        if (g_ethin[i] != except_eth) {
            if (ANMIT_BOND_NO == g_ethin[i]) {
                sprintf(chcmd, "ifconfig bond0 down");
            } else {
                sprintf(chcmd, "ifconfig eth%d down", g_ethin[i]);
            }
            system(chcmd);
        }
    }
    return 0;
}

/**
 * [CHOTBAKBS::UpDownInNet UP、DOWN内网卡]
 * @param  except_eth [例外网卡]
 * @return            [成功返回0]
 */
int CHOTBAKBS::UpDownInNet(int except_eth)
{
    char chcmd1[CMD_BUF_LEN] = {0};
    char chcmd2[CMD_BUF_LEN] = {0};
    if (m_devbs->m_updowncard == 1) {
        for (int i = 0; i < (int)g_ethin.size(); i++) {
            if (g_ethin[i] != except_eth) {
                if (ANMIT_BOND_NO == g_ethin[i]) {
#if 0
                    sprintf(chcmd1, "ifconfig bond0 up");
                    sprintf(chcmd2, "ifconfig bond0 down");
                    system(chcmd1);
                    system(chcmd2);
#endif
                } else {
                    sprintf(chcmd1, "ifconfig eth%d up", g_ethin[i]);
                    sprintf(chcmd2, "ifconfig eth%d down", g_ethin[i]);
                    system(chcmd1);
                    system(chcmd2);
                }
            }
        }
    }
    return 0;
}

/**
 * [CHOTBAKBS::DownOutNet DOWN外网网卡]
 * @param  except_eth [例外网卡]
 * @return            [成功返回0]
 */
int CHOTBAKBS::DownOutNet(int except_eth)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < (int)g_ethout.size(); i++) {
        if (g_ethout[i] != except_eth) {
            if (ANMIT_BOND_NO == g_ethout[i]) {
                sprintf(chcmd, "ifconfig bond0 down");
            } else {
                sprintf(chcmd, "ifconfig eth%d down", g_ethout[i]);
            }
            while (PeerExecuteCMD(chcmd) < 0) {
                PRINT_ERR_HEAD
                print_err("peer execute fail,retry[%s]", chcmd);
            }
        }
    }

    return 0;
}

/**
 * [CHOTBAKBS::UpDownOutNet UP、DOWN外网网卡]
 * @param  except_eth [例外网卡]
 * @return            [成功返回0]
 */
int CHOTBAKBS::UpDownOutNet(int except_eth)
{
    char chcmd1[CMD_BUF_LEN] = {0};
    char chcmd2[CMD_BUF_LEN] = {0};

    if (m_devbs->m_updowncard == 1) {
        for (int i = 0; i < (int)g_ethout.size(); i++) {
            if (g_ethout[i] != except_eth) {
                if (ANMIT_BOND_NO == g_ethout[i]) {
#if 0
                    sprintf(chcmd1, "ifconfig bond0 up");
                    sprintf(chcmd2, "ifconfig bond0 down");
#endif
                } else {
                    sprintf(chcmd1, "ifconfig eth%d up", g_ethout[i]);
                    sprintf(chcmd2, "ifconfig eth%d down", g_ethout[i]);

                    while (PeerExecuteCMD(chcmd1) < 0) {
                        PRINT_ERR_HEAD
                        print_err("peer execute fail,retry[%s]", chcmd1);
                    }

                    while (PeerExecuteCMD(chcmd2) < 0) {
                        PRINT_ERR_HEAD
                        print_err("peer execute fail,retry[%s]", chcmd2);
                    }
                }
            }
        }
    }

    return 0;
}

/**
 * [CHOTBAKBS::GetOutCardStatus 获取对端一张网卡的状态]
 * @param  ethname [网卡名]
 * @return         [1为正常 0为异常 -1传输出错或超时]
 */
int CHOTBAKBS::GetOutCardStatus(char *ethname)
{
    if ((ethname == NULL) || (strlen(ethname) == 0)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    if (DEVFLAG[0] != 'I') {
        PRINT_ERR_HEAD
        print_err("this is outnet");
        return -1;
    }

    HEADER header;
    memset(&header, 0, sizeof(header));
    header.appnum = GET_CARD_STATUS_TYPE;
    char send_buf[MAX_BUF_LEN] = {0};
    unsigned int length = sizeof(length) + strlen(ethname);

    //按协议组消息
    memcpy(send_buf, &header, sizeof(header));
    memcpy(send_buf + sizeof(header), &length, sizeof(length));
    memcpy(send_buf + sizeof(header) + sizeof(length), ethname, strlen(ethname));

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.253", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton error[%s:%s]", ip, strerror(errno));
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    char recvbuf[512] = {0};
    socklen_t addrlen = sizeof(addr);

    for (int i = 0; i < 5; i++) {
        //发送给对端
        ret = sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("sendto error[%s]", strerror(errno));
            close(fd);
            return -1;
        }

        //接收状态
        ret = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&addr, &addrlen);
        if (ret < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                PRINT_INFO_HEAD
                print_info("recvfrom timeout");
            } else {
                PRINT_ERR_HEAD
                print_err("recvfrom error[%s]", strerror(errno));
            }
            continue;
        } else {
            //校验一下
            if (ret < (int)(strlen(ethname) + sizeof(int))) {
                PRINT_ERR_HEAD
                print_err("recvfrom size error[%d]", ret);
                continue;
            }
            if (memcmp(ethname, recvbuf, strlen(ethname)) != 0) {
                PRINT_ERR_HEAD
                print_err("not dest card[%s]", ethname);
                continue;
            }
            int cardstat = 0;
            memcpy(&cardstat, recvbuf + strlen(ethname), sizeof(int));
            close(fd);
            return cardstat;
        }
    }

    PRINT_ERR_HEAD
    print_err("will exit[%s]", ethname);
    close(fd);
    return -1;
}

/**
 * [CHOTBAKBS::UpInNet UP内网所有使用中的业务网卡]
 * @return  [成功返回0]
 */
int CHOTBAKBS::UpInNet(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < (int)g_ethin.size(); i++) {
        if (ANMIT_BOND_NO == g_ethin[i]) {
            sprintf(chcmd, "ifconfig bond0 up");
        } else {
            sprintf(chcmd, "ifconfig eth%d up", g_ethin[i]);
        }
        system(chcmd);
    }
    return 0;
}

/**
 * [CHOTBAKBS::UpOutNet UP外网所有使用中的业务网卡]
 * @return  [成功返回0]
 */
int CHOTBAKBS::UpOutNet(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < (int)g_ethout.size(); i++) {
        if (ANMIT_BOND_NO == g_ethout[i]) {
            sprintf(chcmd, "ifconfig bond0 up");
        } else {
            sprintf(chcmd, "ifconfig eth%d up", g_ethout[i]);
        }
        while (PeerExecuteCMD(chcmd) < 0) {
            PRINT_ERR_HEAD
            print_err("peer execute fail[%s]", chcmd);
        }
    }
    return 0;
}

/**
 * [CHOTBAKBS::SetOutRoute 设置外网的路由信息]
 * @return  [成功返回0]
 */
int CHOTBAKBS::SetOutRoute(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    //设置外网路由
    for (int i = 0; i < m_devbs->m_outnet.rtnum; i++) {
        if (memcmp(m_devbs->m_outnet.rtlist[i], "route", 5) == 0) {
            while (PeerExecuteCMD(m_devbs->m_outnet.rtlist[i]) < 0) {
                PRINT_ERR_HEAD
                print_err("peer execute fail[%s]", m_devbs->m_outnet.rtlist[i]);
            }
        }
    }

    //设置外网默认路由
    if (strcmp(m_outdefgw, "") != 0) {
        sprintf(chcmd, "route add default gw %s", m_outdefgw);
        while (PeerExecuteCMD(chcmd) < 0) {
            PRINT_ERR_HEAD
            print_err("peer execute fail[%s]", chcmd);
        }
    }

    //设置外网路由
    for (int i = 0; i < m_devbs->m_outnet.srtnum; ++i) {
        BZERO(chcmd);
        m_devbs->m_outnet.srtlist[i].combineRoute(chcmd);
        PeerExecuteCMD(chcmd);
    }
    return 0;
}

/**
 * [CHOTBAKBS::InNetMonitor 轮询查看内网通信卡连接状态]
 * @param badethno   [连接有问题的网卡的编号 出参 如:0]
 * @param badethname [连接有问题的网卡的名称 出参 如：eth0]
 * @param badarea    [连接有问题的网卡的区域 出参]
 * @return           [所有都OK则返回true]
 */
bool CHOTBAKBS::InNetMonitor(int &badethno, char *badethname, int &badarea)
{
    char chname[32] = {0};

    for (int i = 0; i < (int)g_ethin.size(); i++) {
        INT_TO_CARDNAME(g_ethin[i], chname);
        int ret = get_netcard_status(chname);
        if (ret != 1) {
            strcpy(badethname, chname);
            badethno = g_ethin[i];
            badarea = 0;

            PRINT_ERR_HEAD
            print_err("innet card bad[%s]", badethname);

            char chsyslog[SYSLOG_BUF_LEN] = {0};
            sprintf(chsyslog, "%s%s[%s]", INNET_SIDE, LOG_TYPE_LINE_CK_FAIL,
                    (ANMIT_BOND_NO == badethno) ? BOND_CARD : m_devbs->interface[badethno]);
            CLOGMANAGE mlog;
            mlog.Init();
            mlog.WriteSysLog(LOG_TYPE_NET_LINE_CK, D_FAIL, chsyslog);
            mlog.DisConnect();
            return false;
        }
    }

    return true;
}

/**
 * [CHOTBAKBS::OutNetMonitor 轮询查看外网通信卡连接状态]
 * @param badethno   [连接有问题的网卡的编号 出参 如:0]
 * @param badethname [连接有问题的网卡的名称 出参 如：eth0]
 * @param badarea    [连接有问题的网卡的区域 出参]
 * @return           [所有都OK则返回true]
 */
bool CHOTBAKBS::OutNetMonitor(int &badethno, char *badethname, int &badarea)
{
    char chname[32] = {0};

    for (int i = 0; i < (int)g_ethout.size(); i++) {
        INT_TO_CARDNAME(g_ethout[i], chname);
        int ret = GetOutCardStatus(chname);
        if (ret != 1) {
            strcpy(badethname, chname);
            badethno = g_ethout[i];
            badarea = 1;

            PRINT_ERR_HEAD
            print_err("outnet card bad[%s]", badethname);

            char chsyslog[SYSLOG_BUF_LEN] = {0};
            sprintf(chsyslog, "%s%s[%s]", OUTNET_SIDE, LOG_TYPE_LINE_CK_FAIL,
                    (ANMIT_BOND_NO == badethno) ? BOND_CARD : m_devbs->outerface[badethno]);
            CLOGMANAGE mlog;
            mlog.Init();
            mlog.WriteSysLog(LOG_TYPE_NET_LINE_CK, D_FAIL, chsyslog);
            mlog.DisConnect();
            return false;
        }
    }

    return true;
}

/**
 * [CHOTBAKBS::GetBadCardStatus 获取上次循环时连接异常的网卡  有没有连接上]
 * @param  badethno   [连接有问题的网卡的编号]
 * @param  badethname [连接有问题的网卡的名称]
 * @param  badarea    [连接有问题的网卡的区域]
 * @return            [成功返回1]
 */
int CHOTBAKBS::GetBadCardStatus(int badethno, char *badethname, int badarea)
{
    int ret = 0;

    if (badarea == 0) {
        ret = get_netcard_status(badethname);
        if (ret == 1) {
            //被拔掉的网线接上了
            PRINT_INFO_HEAD
            print_info("innet card recover[%s]", badethname);

            char chsyslog[SYSLOG_BUF_LEN] = {0};
            sprintf(chsyslog, "%s%s[%s]", INNET_SIDE, LOG_TYPE_LINE_CK_OK,
                    (ANMIT_BOND_NO == badethno) ? BOND_CARD : m_devbs->interface[badethno]);
            CLOGMANAGE mlog;
            mlog.Init();
            mlog.WriteSysLog(LOG_TYPE_NET_LINE_CK, D_SUCCESS, chsyslog);
            mlog.DisConnect();
        }
    } else {
        ret = GetOutCardStatus(badethname);
        if (ret == 1) {
            //被拔掉的网线接上了
            PRINT_INFO_HEAD
            print_info("outnet card recover[%s]", badethname);

            char chsyslog[SYSLOG_BUF_LEN] = {0};
            sprintf(chsyslog, "%s%s[%s]", OUTNET_SIDE, LOG_TYPE_LINE_CK_OK,
                    (ANMIT_BOND_NO == badethno) ? BOND_CARD : m_devbs->outerface[badethno]);
            CLOGMANAGE mlog;
            mlog.Init();
            mlog.WriteSysLog(LOG_TYPE_NET_LINE_CK, D_SUCCESS, chsyslog);
            mlog.DisConnect();
        }
    }

    return ret;
}

/**
 * [CHOTBAKBS::MakeReportInfo 按协议组装用于汇报的信息]
 * @param  report    [汇报信息缓冲区 出参]
 * @param  rlen      [缓冲区长度]
 * @param  nicstatus [总体网卡连接状态]
 * @return           [返回组装后的长度 失败返回负值]
 */
int CHOTBAKBS::MakeReportInfo(char *report, int rlen, int nicstatus)
{
    if ((report == NULL) || (rlen <= 0)) {
        PRINT_ERR_HEAD
        print_err("para error[%d]", rlen);
        return -1;
    }

    NIC_REPORT_HEAD nichead;
    nichead.status = nicstatus;
    nichead.nicnum_in = m_nicnum_in;
    nichead.nicnum_out = m_nicnum_out;

    REPORT_HEAD reporthead;
    reporthead.type = REPORT_NIC_STATUS;
    reporthead.len = sizeof(nichead) + (nichead.nicnum_in + nichead.nicnum_out) * sizeof(NIC_MAC_STRUCT);

    if (rlen < reporthead.len + (int)sizeof(reporthead)) {
        PRINT_ERR_HEAD
        print_err("buff len[%d] less than required[%d] ", rlen, reporthead.len + (int)sizeof(reporthead));
        return -1;
    }

    memcpy(report, &reporthead, sizeof(reporthead));
    int len = sizeof(reporthead);
    memcpy(report + len, &nichead, sizeof(nichead));
    len += sizeof(nichead);
    memcpy(report + len, m_nic_in, nichead.nicnum_in * sizeof(NIC_MAC_STRUCT));
    len += nichead.nicnum_in * sizeof(NIC_MAC_STRUCT);
    memcpy(report + len, m_nic_out, nichead.nicnum_out * sizeof(NIC_MAC_STRUCT));
    len += nichead.nicnum_out * sizeof(NIC_MAC_STRUCT);
    return len;
}
