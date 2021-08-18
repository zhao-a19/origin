/*******************************************************************************************
*文件:    diffcfg.cpp
*描述:    后台配置文件扫描
*
*作者:    赵子昂
*日期:    2020-10-19
*修改:    创建文件                                             ------>     2020-10-19
*        调整代码结构，暂不处理数据库同步模块                    ------>     2020-12-12
*        修改bug，私有文件交换增加回写配置项                     ------>     2020-12-16
*        可以设置线程名称                                      ------>     2021-02-23
*        调用dbsync_tool前先把可能正在运行的dbsync_tool进程杀掉  ------>    2021-04-12 wjl
*******************************************************************************************/
#include "datatype.h"
#include "debugout.h"
#include "gap_config.h"
#include "fileoperator.h"
#include "syscfg.h"
#include "FCBSTX.h"
#include "diffcfg.h"
#include "sendfiletcp.h"
#include "netinfo.h"
#include "stringex.h"
#include "md5.h"
#include "define.h"
#include "common.h"

typedef struct cfg {
    pchar key;
    pchar value;
} CFG;
static CFG sysset[] = {
    {"SYSTEM", "BUFFALERT"},        //存储空间管理
    {"SYSTEM", "FilterFlag"},       //是否开启关键字过滤
    {"SYSTEM", "FilterKeyNum"},     //关键字过滤规则数
    {"SYSTEM", "CKFileType"},       //是否检查文件类型
    {"SYSTEM", "FilterFileType"},   //允许/禁止的文件类型
    {"SYSTEM", "CKVirus"},          //是否开启防病毒检测
    {"SYSTEM", "AUTOBAK"},          //是否启动规则备份
    {"SYSTEM", "AUTOBAK_TO"},       //自动规则备份
    {"SYSTEM", "AUTOBAK_PORT"},     //自动规则备份端口
    {"SYSTEM", "AUTOBAK_USER"},     //自动备份用户名
    {"SYSTEM", "AUTOBAK_PASS"},     //自动备份用户密码
    {"SYSTEM", "AUTOBAK_TIME"},     //自动备份时间间隔
    {"SYSTEM", "CKNetTime"},        //是否开启远程校时
    {"SYSTEM", "NetTimeServer"},    //远程时间服务器地址
    {"SYSTEM", "NetTimeCycle"},     //校时周期
    {"SYSTEM", "SYSMaxConn"},       //系统并发数设置
};
static CFG f_sync[] = {
    {"TASK", "OutMapPath"},         //sys6回写配置
    {"TASK", "OutBakMapPath"},
};
static CFG pf_sync[] = {
    {"DIR", "PORT2"},
    {"DIR", "TOIP2"},
    {"DIR", "TOIP"},
    {"DIR", "PORT"},
};

typedef struct msg {
    pchar cfg;
    char result[56];
    CSYSCFG fop;
} MSG;
static MSG MSG1[] = {               //SYSSET_CONF KEY_CONF MULTICAST_CONF FILESYNC_CONF PRIV_FILESYNC_CONF WEBPROXY_CONF 特殊处理
    {SYSSET_CONF},
    {RULE_CONF},
    {KEY_CONF},
    {KEYUTF8_CONF},
    {DEV_CONF},
    {BONDING_CONF},
    {MULTICAST_CONF},
    {SIP_CONF},
    {SIP_INTER_CNT_CONF},
    {PDT_CONF},
    {LINK_SIP_CONF},
    {FILESYNC_CONF},
    {PRIV_FILESYNC_CONF},
    {WEBPROXY_CONF},
    //{NEW_DBSYNC_CONF},            //数据库同步由dbsync_tool处理 zza
    {NULL},
};
static MSG MSG2[] = {
    {SYSSET_CONF},
    {RULE_CONF},                    //该配置文件下次改动特殊处理，有独立模块生效时，除了该文件其余全发
    {KEY_CONF},
    {KEYUTF8_CONF},
    {DEV_CONF},
    {BONDING_CONF},
    {MULTICAST_CONF},
    {SIP_CONF},
    {SIP_INTER_CNT_CONF},
    {PDT_CONF},
    {LINK_SIP_CONF},
    {FILESYNC_CONF},
    {PRIV_FILESYNC_CONF},
    {WEBPROXY_CONF},
    //{NEW_DBSYNC_CONF},
    {NULL},
};

static struct mod {                 //各项配置文件改变对应的操作：startall或者发送的模块名
    pchar mod;
} G_MOD[] = {
    {SPECIAL},
    {STARTALL},
    {M_KEYWORD},
    {M_KEYWORD},
    {STARTALL},
    {STARTALL},
    {M_MULTICAST},
    {STARTALL},
    {STARTALL},
    {STARTALL},
    {STARTALL},
    {M_FSYNC},
    {M_PRIVFSYNC},
    {M_WEBPROXY},
    // {M_NEWDBSYNC},
};

static struct SPEC_MOD {            //只通知内网而不需通知外网的模块名
    pchar spec_mod;
} SPEC_MOD[] = {
    {M_AUTOBAK},
    // {M_NEWDBSYNC},
};

static struct SEND_CFG {            //需要向外网发送的配置文件
    pchar cfg;
} SEND_CFG[] = {
    {SYSSET_CONF},
    {FILESYNC_CONF},
    {PRIV_FILESYNC_CONF},
    {WEBPROXY_CONF},
    {MULTICAST_CONF},
    {KEY_CONF},
    {KEYUTF8_CONF},
    {NULL},
};

int g_linklanipseg = 0;
int g_linktcpfileport = 0;
int g_scanlinkport = 0;
int g_modnum = 0;
bool g_startall = false;
bool g_fsync = false;
bool g_pfsync = false;
char g_modulename[MAX_MODNUM][50];
char g_chmsg[2048];
char g_md5_last[128];
char g_md5_now[128];

/**
 * [readsysinfo 读取sysinfo]
 * @return [description]
 */
static int readsysinfo(void)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        return -1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", &g_linklanipseg);
    if (g_linklanipseg < 1 || g_linklanipseg > 255) {
        g_linklanipseg = 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkTCPFilePort", &g_linktcpfileport);
    if ((g_linktcpfileport < 1) || (g_linktcpfileport > 65535)) {
        g_linktcpfileport = DEFAULT_LINK_TCP_FILE_PORT;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "RuleNoticePort", &g_scanlinkport);
    if ((g_scanlinkport < 1) || (g_scanlinkport > 65535)) {
        g_scanlinkport = DEFAULT_NOTICE_PORT;
    }

    m_fileop.CloseFile();
    PRINT_DBG_HEAD;
    print_dbg("LinkLanIPSeg:%d  RuleNoticePort:%d", g_linklanipseg, g_scanlinkport);

    return 0;
}

/**
 * [read_cslan 读取管理口号]
 * @param  cslan [网卡号 出参]
 * @return       [读取成功返回true]
 */
static bool read_cslan(int &cslan)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("OpenFile error[%s]", SYSINFO_CONF);
        return false;
    }

    if (fileop.ReadCfgFileInt("SYSTEM", "CSLan", &cslan) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("start read sclan fail.");
        fileop.CloseFile();
        return false;
    }

    fileop.CloseFile();
    return true;
}

/**
 * [read_task_num 获取配置文件中策略个数]
 * @param  cfg  [配置文件]
 * @param  item [检索项]
 * @return      [个数]
 */
static int read_task_num(pchar cfg, pchar item)
{
    char cmd[256] = {0};
    sprintf(cmd, "grep %s %s |wc -l", item, cfg);
    char result[20] = {0};

    if (sysinfo(cmd, result, sizeof(result)) ==  NULL) {
        PRINT_ERR_HEAD
        print_err("sysinfo : %s fail! ", cmd);
        return 0;
    }
    return atoi(result);
}

/**
 * [makemap 将配置文件中需要详细比较的key值写进map中]
 * @param  cfg  [配置文件编号]
 * @param  mp [map入出参]
 */
static void makemap(int cfg, map<string, bool> &mp)
{
    CSYSCFG fp;
    string newkey;
    int task_num;
    char key[128] = {0};
    CFILEOP sipconf;
    switch (cfg) {
    case SYSSET:
        for (int i = 0; i < (int)(sizeof(sysset) / sizeof(sysset[0])); i++) {
            fp.makekey(sysset[i].key, sysset[i].value, newkey);
            mp.insert(pair<string, bool>(newkey, false));
        }
        break;
    case FILESYNC:
        task_num = read_task_num(FILESYNC_CONF, "TaskName");
        if (task_num == 0) {        //防止策略停止后，检查任务为0，map创建错误 zza
            mp.insert(pair<string, bool>("", false));
            break;
        }
        for (int i = 0; i < task_num; ++i) {
            sprintf(key, "%s%d", f_sync[0].key, i);
            for (int j = 0; j < (int)(sizeof(f_sync) / sizeof(f_sync[0])); j++) {
                fp.makekey(key, f_sync[j].value, newkey);
                mp.insert(pair<string, bool>(newkey, false));
            }
        }
        break;
    case PRIV_FILESYNC:
        task_num = read_task_num(PRIV_FILESYNC_CONF, "TaskName");
        if (task_num == 0) {
            mp.insert(pair<string, bool>("", false));
            break;
        }
        for (int i = 0; i < task_num; ++i) {
            sprintf(key, "%s%d", pf_sync[0].key, i);
            for (int j = 0; j < (int)(sizeof(pf_sync) / sizeof(pf_sync[0])); j++) {
                fp.makekey(key, pf_sync[j].value, newkey);
                mp.insert(pair<string, bool>(newkey, false));
            }
        }
        break;
    case SIP_INTER_CNT:
        int tasknum, tasksipnum;
        if (sipconf.OpenFile(SIP_INTER_CNT_CONF, "r") == E_FILE_FALSE) {
            PRINT_ERR_HEAD
            print_err("openfile[%s] error", SIP_INTER_CNT_CONF);
            break;
        }
        sipconf.ReadCfgFileInt("SYS", "TaskNum", &tasknum);
        sipconf.ReadCfgFileInt("SYS", "TaskNumSIP", &tasksipnum);
        sipconf.CloseFile();
        if (tasknum == 0 && tasksipnum == 0) {
            mp.insert(pair<string, bool>("", false));
            break;
        }
        if (tasknum != 0) {
            for (int i = 0; i < tasknum; ++i) {
                sprintf(key, "Task%d", i);
                fp.makekey(key, "Name", newkey);
                mp.insert(pair<string, bool>(newkey, false));
            }
        }
        if (tasksipnum != 0) {
            for (int i = 0; i < tasksipnum; ++i) {
                sprintf(key, "TaskSIP%d", i);
                fp.makekey(key, "Name", newkey);
                mp.insert(pair<string, bool>(newkey, false));
            }
        }
        break;
    case EMPTY:
        mp.insert(pair<string, bool>("", false));
        break;
    default:
        break;
    }

#if 0
    map<string, bool>::iterator a;
    int32 b;
    PRINT_DBG_HEAD;
    print_dbg("makemap num :%d", mp.size());
    for (a = mp.begin(), b = 1; a != mp.end(); a++, b++) {
        PRINT_DBG_HEAD;
        print_dbg("makemap num :%d string %s", b, ((string)(a->first)).c_str());
    }
#endif
}

/**
 * [get_file_md5 获取文件MD5]
 * @param  filename [文件绝对路径]
 * @param  md5_info [出入参MD5信息]
 * @return          [description]
 */
static int get_file_md5(pchar filename, pchar md5_info)
{
    int ret = 0;
    if (filename == NULL) {
        return -1;
    }
    uint8 MD5[16] = {0};
    memset(md5_info, 0, sizeof(md5_info));
    if (md5sum(filename, MD5) != 0) {
        PRINT_ERR_HEAD
        print_err("md5sum : %s fail! ", filename);
        return -1;
    }
    for (int i = 0; i < sizeof(MD5); i++) {
        ret += snprintf(md5_info + ret, sizeof(md5_info), "%x", MD5[i]);
    }
    PRINT_INFO_HEAD
    print_info("info : g_md5 %s : %s", filename, md5_info);
    return 0;
}

/**
 * [diff_keycfg_md5 比较两次获取的MD5值]
 * @return [description]
 */
static int diff_keycfg_md5(int sig)
{
    if (strcmp(g_md5_last, g_md5_now) != 0) {
        PRINT_INFO_HEAD
        print_info("key.cfg changed! md5_old:%s md5_new:%s", g_md5_last, g_md5_now);
        if (strstr(g_chmsg, FILTERFG) == NULL && strstr(g_chmsg, FILTERKN) == NULL) {
            if (sig == 1) strcpy(MSG2[KEY].result, G_MOD[KEY].mod);
            else strcpy(MSG1[KEY].result, G_MOD[KEY].mod);
            strcpy(g_modulename[g_modnum], M_KEYWORD);
            g_modnum++;
            strcpy(g_modulename[g_modnum], M_FSYNC);
            g_modnum++;
            strcpy(g_modulename[g_modnum], M_PRIVFSYNC);
            g_modnum++;
            g_pfsync = true;
            g_fsync = true;
        }
    }
    return 0;
}

/**
 * [diff_check_msg 比较配置文件中具体模块信息]
 * @param  cfg   [配置文件对应值]
 * @return       [description]
 */
static int diff_check_msg(int cfg)
{
    switch (cfg) {
    case SYSSET:
        if (strstr(g_chmsg, AUTOBAK) != NULL) {
            strcpy(g_modulename[g_modnum], M_AUTOBAK);
            g_modnum++;
        }
        if (strstr(g_chmsg, BUFFALERT) != NULL) {
            strcpy(g_modulename[g_modnum], M_DISKALERT);
            g_modnum++;
        }
        if (strstr(g_chmsg, FILTERFG) != NULL || strstr(g_chmsg, FILTERKN) != NULL) {
            strcpy(g_modulename[g_modnum], M_KEYWORD);
            g_modnum++;
            strcpy(g_modulename[g_modnum], M_FSYNC);
            g_modnum++;
            strcpy(g_modulename[g_modnum], M_PRIVFSYNC);
            g_modnum++;
            g_pfsync = true;
            g_fsync = true;
        }
        if (strstr(g_chmsg, FILETYPE) != NULL) {
            strcpy(g_modulename[g_modnum], M_FILETYPE);
            g_modnum++;
        }
        if (strstr(g_chmsg, CKVIRUS) != NULL) {
            strcpy(g_modulename[g_modnum], M_CKVIRUS);
            g_modnum++;
            if (!g_fsync) {
                strcpy(g_modulename[g_modnum], M_FSYNC);
                g_modnum++;
                g_fsync = true;
            }
        }
        if (strstr(g_chmsg, NETTIME) != NULL) {
            strcpy(g_modulename[g_modnum], M_NETTIME);
            g_modnum++;
        }
        if (strstr(g_chmsg, SYSMAXCONN) != NULL) {
            strcpy(g_modulename[g_modnum], M_MAXCONN);
            g_modnum++;
        }
        break;
    default:
        break;
    }
    return 0;
}

/**
 * [sendinfo 向内外网发送模块变动通知]
 * @param  ip   [内外网ip]
 * @param  port [端口]
 * @param  info [发送的模块信息]
 * @return      [0成功 -1失败]
 */
static int sendinfo(pchar ip, int port, MODULE *info, int size)
{
    CBSTcpSockClient client;
    int sock = client.Open(ip, port, false);
    if (sock < 0) {
        PRINT_ERR_HEAD;
        print_err("connect %s:%d： server failed!", ip, port);
        g_startall = true;
        return -1;
    }
    int len = client.Send(sock, (unsigned char *)info, size);
    if (len != size) {
        PRINT_ERR_HEAD;
        print_err("Send INFO failed!");
        g_startall = true;
        close(sock);
        return -1;
    }
    close(sock);

    PRINT_DBG_HEAD;
    print_dbg("exit sendinfo to sys6.");
    return 0;
}

/**
 * [diff_mod_to_sys6 组装结构体信息与内外网sys6通信]
 * @return [description]
 */
static int diff_mod_to_sys6(void)
{
    if (g_modnum == 0) return 0;

    char ip_int[128] = {0};
    char ip_out[128] = {0};
    int n_outmd = 0;
    bool find = false;
    sprintf(ip_int, "%d.0.0.254", g_linklanipseg);
    sprintf(ip_out, "%d.0.0.253", g_linklanipseg);

    MODULE INFO_INT[g_modnum];
    memset(&INFO_INT, 0, sizeof(INFO_INT));
    for (int i = 0; i < g_modnum; ++i) {
        for (int j = 0; j < (int)(sizeof(SPEC_MOD) / sizeof(SPEC_MOD[0])); ++j) {
            if (strcmp(SPEC_MOD[j].spec_mod, g_modulename[i]) == 0) {
                strcpy(INFO_INT[i].modname, g_modulename[i]);
                INFO_INT[i].is_change = 1;
                n_outmd++;
                find = true;
                break;
            }
        }
        if (find) {
            find = false;
            continue;
        } else {
            strcpy(INFO_INT[i].modname, g_modulename[i]);
            INFO_INT[i].is_change = 1;
        }
    }
    int out_modnum = g_modnum - n_outmd;
    MODULE INFO_OUT[out_modnum];
    memset(&INFO_OUT, 0, sizeof(INFO_OUT));
    for (int j = 0, k = 0; j < out_modnum; ++j, ++k) {
        for (int i = 0; i < (int)(sizeof(SPEC_MOD) / sizeof(SPEC_MOD[0])); ++i) {
            if (strcmp(SPEC_MOD[i].spec_mod, g_modulename[k]) == 0) {
                k++;
                break;
            }
        }
        strcpy(INFO_OUT[j].modname, g_modulename[k]);
        INFO_OUT[j].is_change = 1;
    }

    PRINT_DBG_HEAD;
    print_dbg("in_net mod %d, out_net mod %d", g_modnum, out_modnum);

#if 0
    printf("g_modnum = %d\n", g_modnum);
    for (int j = 0; j < g_modnum; ++j) {
        printf("%s %d\n", INFO_INT[j].modname, INFO_INT[j].is_change);
    }
    printf("sizeof(INFO_INT)= %d\n", sizeof(INFO_INT));

    printf("out_modnum = %d\n", out_modnum);
    for (int j = 0; j < out_modnum; ++j) {
        printf("%s %d\n", INFO_OUT[j].modname, INFO_OUT[j].is_change);
    }
    printf("sizeof(INFO_OUT)= %d\n", sizeof(INFO_OUT));

#endif

    if (sendinfo(ip_int, g_scanlinkport, INFO_INT, sizeof(INFO_INT)) == -1) return 0;
    if (out_modnum == 0) return 0;
    if (sendinfo(ip_out, g_scanlinkport, INFO_OUT, sizeof(INFO_OUT)) == -1) return 0;

    PRINT_DBG_HEAD;
    print_dbg("mod info send to in/out sys6 end");
    return 0;
}

/**
 * [diff_deal 处理结构中的信息]
 * @param msg [结构]
 */
static void diff_deal(MSG *msg)
{
    int i = 0;
    while (msg[i].cfg != NULL) {
        if (strcmp(msg[i].result, STARTALL) == 0) {
            g_startall = true;
            PRINT_DBG_HEAD;
            print_dbg("result find STARTALL!");
            return;
        } else if (strcmp(msg[i].result, SPECIAL) == 0) {
            //处理sysset
            diff_check_msg(i);
        } else if (strlen(msg[i].result) == 0) {
            i++;
            continue;
        } else {
            if ((g_fsync && (i == FILESYNC)) || (g_pfsync && (i == PRIV_FILESYNC))) {
                // i++;
                // continue;
            } else {
                strcpy(g_modulename[g_modnum], msg[i].result);
                g_modnum++;
            }
        }
        i++;
    }
}

/**
 * [diff_info_process 信息处理]
 * @return [description]
 */
static int diff_info_process(void)
{
    int i = 0;
    if (g_modnum != 0) {
        while (SEND_CFG[i].cfg != NULL) {
            if (send_file_tcp(SEND_CFG[i].cfg, SEND_CFG[i].cfg, 0, 1) != 0) {
                g_startall = true;
                return -1;
            } else {
                PRINT_INFO_HEAD
                print_info("info : diffcfg sendcfg : %s ", SEND_CFG[i].cfg);
            }
            i++;
        }
    } else {
        PRINT_INFO_HEAD
        print_info("info : diffcfg not find mod changed!");
        return 0;
    }
    return 0;
}

/**
 * [diff_check_value 校验配置文件键值]
 * @param  id     [配置文件编号]
 * @param  sig    [循环扫描标志位]
 * @param  precfg [配置文件]
 * @return        [description]
 */
static int diff_check_value(int id, int sig, char *precfg, MSG *msg_now, MSG *msg_last)
{
    if (g_startall) return 0;

    bool other = true;
    map <string, bool> mp;
    map<string, bool>::iterator i;
    switch (id) {
    case SYSSET:
        makemap(id, mp);
        if (sig == 1) msg_now[id].fop.finddiff(msg_last[id].fop, mp, other, false);
        else msg_last[id].fop.finddiff(msg_now[id].fop, mp, other, false);

        if (!other) {
            PRINT_INFO_HEAD
            print_info("info : %s other options changed  action : startall!", precfg);
            if (sig == 1) strcpy(msg_now[id].result, STARTALL);
            else strcpy(msg_last[id].result, STARTALL);
        }

        for (i = mp.begin(); i != mp.end(); i++) {
            if (!i->second) {
                PRINT_INFO_HEAD
                print_info("info : %s %s changed!", precfg, ((string)(i->first)).c_str());
                strcat(g_chmsg, ((string)(i->first)).c_str());
                if (sig == 1) strcpy(msg_now[id].result, G_MOD[id].mod);
                else strcpy(msg_last[id].result, G_MOD[id].mod);
            } else {
                PRINT_INFO_HEAD
                print_info("info : %s %s not changed", precfg, ((string)(i->first)).c_str());
            }
        }
        break;
    case FILESYNC:
        makemap(id, mp);
        if (sig == 1) msg_now[id].fop.finddiff(msg_last[id].fop, mp, other, false);
        else msg_last[id].fop.finddiff(msg_now[id].fop, mp, other, false);

        for (i = mp.begin(); i != mp.end(); i++) {
            if (!i->second) {
                PRINT_INFO_HEAD
                print_info("info : %s %s changed!", precfg, ((string)(i->first)).c_str());
            } else {
                PRINT_INFO_HEAD
                print_info("info : %s %s not changed", precfg, ((string)(i->first)).c_str());
            }
        }
        if (!other) {
            PRINT_INFO_HEAD
            print_info("info : %s other options changed!", precfg);
            if (sig == 1) strcpy(msg_now[id].result, G_MOD[id].mod);
            else strcpy(msg_last[id].result, G_MOD[id].mod);
        }
        break;
    case PRIV_FILESYNC:
        makemap(id, mp);
        if (sig == 1) msg_now[id].fop.finddiff(msg_last[id].fop, mp, other, false);
        else msg_last[id].fop.finddiff(msg_now[id].fop, mp, other, false);

        if (!other) {
            PRINT_INFO_HEAD
            print_info("info : %s other options changed!", precfg);
            if (sig == 1) strcpy(msg_now[id].result, G_MOD[id].mod);
            else strcpy(msg_last[id].result, G_MOD[id].mod);
        }
        break;
    case SIP_INTER_CNT:
        makemap(id, mp);
        if (sig == 1) msg_now[id].fop.finddiff(msg_last[id].fop, mp, other, false);
        else msg_last[id].fop.finddiff(msg_now[id].fop, mp, other, false);

        if (!other) {
            PRINT_INFO_HEAD
            print_info("info : %s other options changed!", precfg);
            if (sig == 1) strcpy(msg_now[id].result, G_MOD[id].mod);
            else strcpy(msg_last[id].result, G_MOD[id].mod);
        }
        break;
    default:
        makemap(EMPTY, mp);
        if (sig == 1) msg_now[id].fop.finddiff(msg_last[id].fop, mp, other, false);
        else msg_last[id].fop.finddiff(msg_now[id].fop, mp, other, false);
        if (!other) {
            PRINT_INFO_HEAD
            print_info("info : %s options changed", precfg);
            if (sig == 1) strcpy(msg_now[id].result, G_MOD[id].mod);
            else strcpy(msg_last[id].result, G_MOD[id].mod);
        }
        break;
    }

    return 0;
}

/**
 * [diff_task 任务逻辑处理]
 * @param  sig      [标志位]
 * @param  recvmsg  [触发接收信息]
 * @param  msg_now  [当前信息结构]
 * @param  msg_last [上次信息结构]
 * @return          [description]
 */
static int diff_task(int *sig, pchar recvmsg, MSG *msg_now, MSG *msg_last)
{
    int cslan = -1;
    char chcmd[1024] = {0};
    CCommon common;

    if (strcmp(recvmsg, START) == 0) {

        if (*sig == 1) get_file_md5(KEY_CONF, g_md5_now);
        else get_file_md5(KEY_CONF, g_md5_last);

        int i = 0;
        while (msg_now[i].cfg != NULL) {
            PRINT_DBG_HEAD
            print_dbg("diffcfg : %s", msg_now[i].cfg);
            if (!msg_now[i].fop.open(msg_now[i].cfg, true, true)) {
                PRINT_ERR_HEAD
                print_err("diffcfg read config open[%s] fail", msg_now[i].cfg);
                g_startall = true;
            }
#if 0
            map<string, string> test = msg_now[i].fop.getmap();
            map<string, string>::iterator a;
            int32 b;
            printf("!!!!config counts = %d\n", test.size());
            for (a = test.begin(), b = 1; a != test.end(); a++, b++) {
                printf("!!!CONFIG_%03d %s = %s\n", b, ((string)(a->first)).c_str(), ((string)(a->second)).c_str());
            }
#endif
            diff_check_value(i, *sig, msg_now[i].cfg, msg_now, msg_last);
            i++;
        }

        if (*sig == 1) diff_deal(msg_now);
        else diff_deal(msg_last);

        diff_keycfg_md5(*sig);
        diff_info_process();

        if (g_startall) {
            PRINT_INFO_HEAD
            print_info("info : diffcfg start %s", SYSTEM_STARTALL);
            system(SYSTEM_STARTALL);
        } else {
            sleep(1);               //加延时保证发送到外网的配置文件写入磁盘
            while (common.ProcessRuning("dbsync_tool")) {
                sprintf(chcmd, "killall -15 dbsync_tool >/dev/null 2>&1");
                system(chcmd);
                PRINT_INFO_HEAD
                print_info("stop dbsync_tool[%s]", chcmd);
                sleep(1);
            }
            sprintf(chcmd, "%s &", NEW_DBSYNC_TOOL);
            system(chcmd);//dbsync_tool来管理数据库同步模块
            PRINT_INFO_HEAD
            print_info("info : diffcfg start %s", chcmd);
            if (read_cslan(cslan)) {//授权模块重新启动
                system("killall ausvr");
                sprintf(chcmd, "%s /initrd/abin/ausvr eth%d >/dev/null &", NOHUP_RUN, cslan);
                system(chcmd);
                PRINT_INFO_HEAD
                print_info("info : diffcfg start %s", chcmd);
            }
            diff_mod_to_sys6();
            if (g_startall) system(SYSTEM_STARTALL);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("error recvmsg : %s  diffcfg result : STARTALL", recvmsg);
        system(SYSTEM_STARTALL);    //获取信息错误执行startall
    }

    if (*sig == 1) *sig = 0;
    else *sig = 1;

    int j = 0;
    while (msg_last[j].cfg != NULL) {
        msg_last[j].fop.close();    //清空map数据
        memset(msg_last[j].result, 0, sizeof(msg_last[j].result));
        memset(msg_now[j].result, 0, sizeof(msg_now[j].result));
        j++;
    }

    g_modnum = 0;
    g_startall = false;
    g_fsync = false;
    g_pfsync = false;
    memset(g_chmsg, 0, sizeof(g_chmsg));
    memset(g_modulename, 0, sizeof(g_modulename));

    PRINT_DBG_HEAD;
    print_dbg("info : diff_task end.");
    return 0;
}

/**
 * [Diffcfg_process 配置文件扫描线程]
 * @param  arg [暂不使用]
 * @return     [description]
 */
static void *Diffcfg_process(void *arg)
{
    pthread_setself("diffcfg");
    readsysinfo();                  //读取sysinfo
    int sig = 0;
    int i = 0;
    char recvmsg[1024] = {0};

    get_file_md5(KEY_CONF, g_md5_last);
    while (MSG1[i].cfg != NULL) {
        PRINT_DBG_HEAD
        print_dbg("diffcfg : %s", MSG1[i].cfg);
        if (!MSG1[i].fop.open(MSG1[i].cfg, true, true)) {
            PRINT_ERR_HEAD
            print_err("diffcfg read config open[%s] fail", MSG1[i].cfg);
            return NULL;
        }
        i++;
    }

    sig++;
    while (scan_server(recvmsg, sizeof(recvmsg)) == 0) {
        if (sig == 1) diff_task(&sig, recvmsg, MSG2, MSG1);
        else diff_task(&sig, recvmsg, MSG1, MSG2);
    }
    return NULL;
}

/**
 * [Diffcfg 创建扫描线程]
 * @return  [description]
 */
int Diffcfg(void)
{
    pthread_t thd;
    if (pthread_create(&thd, NULL, Diffcfg_process, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create Diffcfg_process fail !!");
        return -1;
    }
    return 0;
}
