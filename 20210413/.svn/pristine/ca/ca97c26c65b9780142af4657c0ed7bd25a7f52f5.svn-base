/*******************************************************************************************
*文件:  FCLinkService.cpp
*描述:  视频联动调度服务启动
*作者:  王君雷
*日期:  2018-07-11
*修改:
*       gapsip命令行参数变为：listenip listernport natip cmdport isout iflog
*                                                                       ------> 2018-07-19
*       gapsip输出定位到 ">/dev/null", ">"前缺少空格                    ------> 2018-07-23
*******************************************************************************************/
#include "FCLinkService.h"
#include "debugout.h"
#include "critical.h"
#include "define.h"
#include "fileoperator.h"

#define LINK_SERVER_CONF LINK_SIP_CONF

char g_link_nat_ip[IP_STR_LEN] = {0};
bool g_inside = false;
extern int g_linklanport;
extern bool g_iflog;

/**
 * [loadLinkInfo 读取视频联动服务配置信息]
 * @param  ipbuff  [存放读取到的监听IP]
 * @param  iplen   [IP缓冲区长度]
 * @param  portbuff[存放读取到的监听端口]
 * @param  portlen [端口缓冲区长度]
 * @return         [读取成功返回true 读取失败或不需要开启服务 返回false]
 */
bool loadLinkInfo(char *ipbuff, int iplen, char *portbuff, int portlen)
{
    bool bflag = false;
    int tmpint = 0;
    CFILEOP m_fileop;

    if (m_fileop.OpenFile(LINK_SERVER_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", LINK_SERVER_CONF);
        goto _out;
    }

    m_fileop.ReadCfgFileInt("SIP", "CKSrv", &tmpint);

    if (tmpint == 1) {
        if (m_fileop.ReadCfgFile("SIP", g_inside ? "InSrvIP" : "OutSrvIP",
                                 ipbuff, iplen) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read[%s][%s]fail", "SIP", g_inside ? "InSrvIP" : "OutSrvIP");
            goto _out;
        }
        if (m_fileop.ReadCfgFile("SIP", g_inside ? "InSrvPort" : "OutSrvPort",
                                 portbuff, portlen) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read[%s][%s]fail", "SIP", g_inside ? "InSrvPort" : "OutSrvPort");
            goto _out;
        }
        bflag = true;
    }
_out:
    m_fileop.CloseFile();
    return bflag;
}

/**
 * [linkDeamon 视频联动线程函数]
 * @param arg [未使用],
 */
void *linkDeamon(void *arg)
{
    pthread_setself("linkdeamon");

    char ip[IP_STR_LEN] = {0};
    char port[PORT_STR_LEN] = {0};
    char chcmd[CMD_BUF_LEN] = {0};

    //
    //./gapsip listenip listernport natip cmdport isout iflog
    //
    if (loadLinkInfo(ip, sizeof(ip), port, sizeof(port))) {
        sprintf(chcmd, "%s '%s' '%s' %s %d %d %d >/dev/null 2>&1 ",
                LINK_SERVER, ip, port, g_link_nat_ip, g_linklanport, (g_inside ? 0 : 1),
                (g_iflog ? 1 : 0));

        PRINT_DBG_HEAD
        print_dbg("link service start...[%s]", chcmd);

        while (1) {
            system_safe(chcmd);
            PRINT_ERR_HEAD
            print_err("link service restart[%s]", chcmd);
            sleep(5);
        }
    }

    return NULL;
}

/**
 * [RunLinkService 开启视频联动服务]
 * @param  inside [本端是内网侧吗？ 要根据该项去读取对应的配置文件]
 * @param  tmpip  [内部DNAT使用的IP]
 * @return        [成功返回0 失败返回负值]
 */
int RunLinkService(bool inside, const char *tmpip)
{
    g_inside = inside;

    if ((tmpip != NULL) && (strlen(tmpip) < sizeof(g_link_nat_ip))) {
        strcpy(g_link_nat_ip, tmpip);
    } else {
        PRINT_ERR_HEAD
        print_err("input tmpip[%s] invalid", tmpip);
        return -1;
    }

    pthread_t pid;
    if (pthread_create(&pid, NULL, linkDeamon, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread create error[%s]", tmpip);
        return -1;
    }

    return 0;
}
