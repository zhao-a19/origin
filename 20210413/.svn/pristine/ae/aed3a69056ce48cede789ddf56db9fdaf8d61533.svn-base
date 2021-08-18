/*******************************************************************************************
*文件:  control.cpp
*描述:  模块调度控制
*作者:  王君雷
*日期:  2020-10-21
*修改:
*      可以设置线程名称                                                ------> 2021-02-23
*******************************************************************************************/
#include "control.h"
#include "common.h"
#include "FCHotBakBS.h"
#include "keyword_mg.h"
#include "sysconn_mg.h"
#include "filetype_mg.h"
#include "debugout.h"
#include "quote_global.h"
#include "diffcfg.h"
#include "readcfg.h"
#include "FCNetTimeSync.h"
#include "card_mg.h"

extern CardMG g_cardmg;

/**
 * [checkCardChange 检查网卡统计信息有无变化]
 */
void checkCardChange(void)
{
    g_cardmg.analysis();
    if ((g_cardmg.getInVec() == g_ethin) && (g_cardmg.getOutVec() == g_ethout)) {
        PRINT_INFO_HEAD
        print_info("card no change");
    } else {
        g_ethin = g_cardmg.getInVec();
        g_ethout = g_cardmg.getOutVec();
        g_cardchange = true;
        PRINT_INFO_HEAD
        print_info("card changed");
    }
}

/**
 * [reloadKeyword 重新加载关键字过滤相关设置]
 */
void reloadKeyword(void)
{
    PRINT_INFO_HEAD
    print_info("reload keyword begin");

    KeywordMG keymg;
    keymg.readConf();
    if (DEVFLAG[0] == 'I') {
        keymg.setRule();
    } else {
    }
    PRINT_INFO_HEAD
    print_info("reload keyword over[%d]", keymg.size());
}

/**
 * [reloadFsync 重新加载文件交换策略]
 * @param bs [CHOTBAKBS指针]
 */
void reloadFsync(CHOTBAKBS *bs)
{
    if (bs->m_devbs->m_workflag == WORK_MODE_TRANSPARENT) {
        PRINT_INFO_HEAD
        print_info("transparent mode ignore");
        return;
    }

    FILESYNC_MG &mg = bs->m_ywbs->m_sysrulesbs->m_filesync_mg;
    mg.clear();
    mg.loadConf();
    mg.makeNatIP();
    mg.setNatIP();
    if (DEVFLAG[0] == 'I') {
        mg.writeConf();
        g_fsync_num = mg.taskNum();
        g_fsync_change = true;
        bs->m_ywbs->AddlCardFileSync();
        checkCardChange();
    } else {
        if (mg.outFtpPortNum() > 0) {
            bs->m_ywbs->SetFtpNat();
        }
        mg.configNatIP();
        mg.clearOutIptables();
        mg.setOutIptables();
    }
    PRINT_INFO_HEAD
    print_info("reload fsync over");
}

/**
 * [reloadPrivFsync 重新加载私有文件交换策略]
 * @param bs [CHOTBAKBS指针]
 */
void reloadPrivFsync(CHOTBAKBS *bs)
{
    if (bs->m_devbs->m_workflag == WORK_MODE_TRANSPARENT) {
        PRINT_INFO_HEAD
        print_info("transparent mode ignore");
        return;
    }

    PVT_FILESYNC_MG &mg = bs->m_ywbs->m_sysrulesbs->m_pvt_filesync_mg;
    mg.clear();
    mg.loadConf();
    mg.setNatIP();
    if (DEVFLAG[0] == 'I') {
        mg.writeConf();
        g_pvtf_num = mg.taskNum();
        g_pvtf_change = true;
        checkCardChange();
    } else {
        mg.clearOutIptables();
        mg.setOutIptables();
    }
    PRINT_INFO_HEAD
    print_info("reload priv fsync over");
}

/**
 * [reloadNewDbsync 重新加载新的数据库同步策略]
 */
void reloadNewDbsync(void)
{
    PRINT_INFO_HEAD
    print_info("reload new dbsync");
    char chcmd[CMD_BUF_LEN] = {0};

    if (DEVFLAG[0] == 'I') {
        sprintf(chcmd, "%s &", NEW_DBSYNC_TOOL);
        system(chcmd);
    }
}

/**
 * [reloadWebProxy 重新加载web代理策略]
 * @param bs [CHOTBAKBS指针]
 */
void reloadWebProxy(CHOTBAKBS *bs)
{
    PRINT_INFO_HEAD
    print_info("reload webproxy begin");

    if (bs->m_devbs->m_workflag != WORK_MODE_PROXY) {
        PRINT_INFO_HEAD
        print_info("only run in proxy mode[%d]. ignore mode[%d]",
                   WORK_MODE_PROXY, bs->m_devbs->m_workflag);
        return;
    }

    CCommon common;
    WebProxyMG &mg = bs->m_ywbs->m_sysrulesbs->m_webproxy_mg;
    mg.clear();
    mg.loadConf();
    mg.run();
    if (common.ProcessRuning("nginx")) {
        if (g_nginx.rule_num() > 0) {
            PRINT_INFO_HEAD
            print_info("rule num[%d] nginx already running and will reload config", g_nginx.rule_num());
            g_nginx.generate_file();
            g_nginx.reload();
        } else {
            PRINT_INFO_HEAD
            print_info("rule num[%d] nginx will stop", g_nginx.rule_num());
            g_nginx.stop();
        }
    } else {
        if (g_nginx.rule_num() > 0) {
            PRINT_INFO_HEAD
            print_info("rule num[%d] nginx not running start it", g_nginx.rule_num());
            StartNginxProcess(&g_nginx);
        }
    }
    if (DEVFLAG[0] == 'I') {
        bs->m_ywbs->AddlCardWebProxy();
        checkCardChange();
    }
    PRINT_INFO_HEAD
    print_info("reload webproxy over");
}

/**
 * [reloadMulticast 重新加载组播策略]
 * @param bs [CHOTBAKBS指针]
 */
void reloadMulticast(CHOTBAKBS *bs)
{
    PRINT_INFO_HEAD
    print_info("reload multicast begin");
    MulticastMG &mg = bs->m_ywbs->m_sysrulesbs->m_multicast_mg;
    mg.clear();
    mg.loadConf();
    if (bs->m_devbs->m_workflag == WORK_MODE_TRANSPARENT) {
        mg.clearTransparentIptables();
        mg.setTransparentIptables();
    } else {
        mg.run();
    }
    if (DEVFLAG[0] == 'I') {
        checkCardChange();
    }
    PRINT_INFO_HEAD
    print_info("reload multicast over");
}

/**
 * [reloadDiskAlert 重新加载磁盘告警阈值]
 */
void reloadDiskAlert(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (DEVFLAG[0] == 'I') {
        sprintf(chcmd, "killall -s SIGUSR1 recvmain");
    } else {
        sprintf(chcmd, "killall -s SIGUSR1 recvmain_w");
    }
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("reload disk alert value[%s]", chcmd);
}

/**
 * [reloadFileType 重新加载文件类型过滤]
 */
void reloadFileType(void)
{
    FileTypeMG &s1 = FileTypeMG::GetInstance();
    s1.ReadConf();
    PRINT_INFO_HEAD
    print_info("reload filetype over[%d]", s1.Size());
}

/**
 * [reloadVirus 重新加载防病毒相关配置]
 */
void reloadVirus(void)
{
    //sys6的各功能模块暂未使用防病毒相关 先留空
    PRINT_INFO_HEAD
    print_info("reload virus check");
}

/**
 * [reloadAutobak 重新加载自动备份]
 */
void reloadAutobak(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_INFO_HEAD
    print_info("reload auto bak");
    if (DEVFLAG[0] == 'I') {
        system("killall autobak >/dev/null 2>&1");
        usleep(10000);
        sprintf(chcmd, "%s /initrd/abin/autobak normal >/dev/null 2>&1&", NOHUP_RUN);
        system(chcmd);
    }
}

/**
 * [reloadNetTime 重启网络时间同步]
 */
void reloadNetTime(void)
{
    g_TimeChange = true;
    PRINT_INFO_HEAD
    print_info("reload net time sync over");
}

/**
 * [reloadMaxConn 重新加载系统并发数设置]
 */
void reloadMaxConn(void)
{
    PRINT_INFO_HEAD
    print_info("reload max conn");
    SetSysMaxConn();
}

/**
 * [DoNotice 处理一次通知]
 * @param buff     [接收到的通知信息]
 * @param buffsize [信息长度]
 * @param bs [CHOTBAKBS指针]
 */
void DoNotice(const char *buff, int buffsize, CHOTBAKBS *bs)
{
    MODULE tmpmod;
    int num = buffsize / sizeof(tmpmod);
    PRINT_INFO_HEAD
    print_info("buffsize[%d] change mod num[%d]", buffsize, num);

    for (int i = 0; i < num; ++i) {
        memcpy(&tmpmod, buff + i * sizeof(tmpmod), sizeof(tmpmod));
        PRINT_INFO_HEAD
        print_info("change modname[%s] ischange[%d]", tmpmod.modname, tmpmod.is_change);

        if (strcmp(tmpmod.modname, M_KEYWORD) == 0) {
            reloadKeyword();
        } else if (strcmp(tmpmod.modname, M_FSYNC) == 0) {
            reloadFsync(bs);
        } else if (strcmp(tmpmod.modname, M_PRIVFSYNC) == 0) {
            reloadPrivFsync(bs);
        } else if (strcmp(tmpmod.modname, M_NEWDBSYNC) == 0) {
            reloadNewDbsync();
        } else if (strcmp(tmpmod.modname, M_WEBPROXY) == 0) {
            reloadWebProxy(bs);
        } else if (strcmp(tmpmod.modname, M_MULTICAST) == 0) {
            reloadMulticast(bs);
        } else if (strcmp(tmpmod.modname, M_DISKALERT) == 0) {
            reloadDiskAlert();
        } else if (strcmp(tmpmod.modname, M_FILETYPE) == 0) {
            reloadFileType();
        } else if (strcmp(tmpmod.modname, M_CKVIRUS) == 0) {
            reloadVirus();
        } else if (strcmp(tmpmod.modname, M_AUTOBAK) == 0) {
            reloadAutobak();
        } else if (strcmp(tmpmod.modname, M_NETTIME) == 0) {
            reloadNetTime();
        } else if (strcmp(tmpmod.modname, M_MAXCONN) == 0) {
            reloadMaxConn();
        } else {
            PRINT_ERR_HEAD
            print_err("unknown modename[%s][%d]", tmpmod.modname, tmpmod.is_change);
        }
    }
}

/**
 * [CtrlFunc 控制线程 负责接收模块变化通知 并执行模块重启操作]
 * @param  para [CHOTBAKBS指针]
 * @return      [未使用]
 */
void *CtrlFunc(void *para)
{
    pthread_setname("ctrlfunc");
    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    CHOTBAKBS *p_this = (CHOTBAKBS *)para;
    char ip[IP_STR_LEN] = {0};
    char buff[65535];
    CBSTcpSockServer server;
    sprintf(ip, "%d.0.0.%d", g_linklanipseg, (DEVFLAG[0] == 'I') ? 254 : 253);
    int sock = 0, newsock = 0;
    int rlen = 0;
    while ((sock = server.Open(ip, g_noticeport)) < 0) {
        PRINT_ERR_HEAD
        print_err("Open[%s][%d] fail %d,retry", ip, g_noticeport, sock);
        sleep(1);
    }

    while (1) {
        newsock = server.StartServer();
        if (newsock > 0) {
            rlen = server.Recv(newsock, (unsigned char *)buff, sizeof(buff));
            if (rlen > 0) {
                DoNotice(buff, rlen, p_this);
            }
            close(newsock);
        } else {
            PRINT_ERR_HEAD
            print_err("accept error[%s] retry", strerror(errno));
        }
    }

    server.Close();
    PRINT_ERR_HEAD
    print_err("control thread exit now");
    return NULL;
}
