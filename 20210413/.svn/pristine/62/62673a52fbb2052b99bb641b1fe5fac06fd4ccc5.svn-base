/*******************************************************************************************
*文件: update.cpp
*描述: 升级操作后台支持程序
*作者: 王君雷
*日期: 2018-10-15
*修改：
*      添加处理模块授权功能                                             ------> 2018-10-16
*      添加内核升级功能                                                 ------> 2019-08-30
*      如果存在永久授权则不替换授权文件，否则替换为90天临时授权（宋宇） ------> 2019-09-29
*      添加both目录，可以同时升级内外网文件，去除fork逻辑               ------> 2020-02-20 wjl
*      先尝试使用TCP方式传输文件、失败再用UDP方式传输，解决升级过程末尾
*      gap_outupdate.sh没有被正确删除掉的BUG，不严重                    ------> 2020-02-25
*      升级支持ARM平台                                                  ------> 2020-03-28-dzj
*      支持飞腾平台                                                     ------> 2020-07-27
*      升级外网OS升级脚本前休眠5秒(宋宇)                                ------> 2020-08-08
*      等待外网执行gap_outupdate.sh超时时间由1s改为120s                 ------> 2020-09-04
*      修正飞腾平台获取当前平台类型时的错误                              ------> 2020-09-29
*      支持tar包首部 2KB异或混淆，解包兼容旧版upk包                      ------> 2021-02-19 zza
*      添加旧版数据库同步升级到2021年03月时策略判断与阻止功能             ------> 2021-03-19 wjl
*      可以兼容旧数据库同步策略                                         ------> 2021-03-23 wjl
*      当旧数据库同步策略中启用了更新转插入功能时阻止导入                 ------> 2021-03-26 wjl
*      修改判断更新转插入的错误问题                                     ------> 2021-04-08 wjl
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "define.h"
#include "update_parser.h"
#include "fileoperator.h"
#include "FCPeerExecuteCMD.h"
#include "FCSendFileUdp.h"
#include "sendfiletcp.h"
#include "FCLicenseMod.h"
#include "FCMD5.h"
#include "debugout.h"
#include "common.h"
#include "au_logtrans.h"

#define CREATETIME          "2021-04-08"
#define UPDATE_VERSION      (0x21) //update自身的版本 只支持大于等于该值的升级包的导入
#define OS_UPDATE_SH_PATH     "/tmp/os/osupdate.sh"
#define OS_UPDATE_PACK_PATH   "/tmp/os/osimg.tgz"
#define POWER_SHOW_FILE_PATH  "/etc/init.d/sysver.cf"
#define AUTH_FILE_PATH1       "/etc/httpd/client.cf"
#define AUTH_FILE_PATH2       "/var/lib/tmcvd"

int g_linklanipseg = 0;
int g_linklanport = 0;
int g_linktcpfileport = 0;
loghandle glog_p = NULL;

int g_infcnt = 0, g_outfcnt = 0, g_osfcnt = 0, g_bothfcnt = 0;
bool g_osupdated = false;//OS是否升级过了
bool g_isforever = false;//是否为永久授权的设备

/**
 * [usage 使用说明]
 * @param name [程序名]
 */
void usage(const char *name)
{
    printf("Usage(%s):\n\t%s updatepack\n\t%s xxx.modcer cer\n\t%s -c updatepack\n", CREATETIME, name, name, name);
}

/**
 * [readlinkinfo 读取内部连接信息]
 * @param  plinkseg  [内连网段]
 * @param  plinkport [内连端口]
 * @return           [成功返回0 失败返回负值]
 */
int readlinkinfo(int *plinkseg, int *plinkport)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        printf("openfile %s error\n", SYSINFO_CONF);
        return -1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", plinkseg);
    if (*plinkseg < 1 || *plinkseg > 255) {
        PRINT_ERR_HEAD
        print_err("LinkLanIPSeg[%d] error, use defult 1", *plinkseg);
        *plinkseg = 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanPort", plinkport);
    if (*plinkport < 1 || *plinkport > 65535) {
        PRINT_ERR_HEAD
        print_err("LinkLanPort[%d] error, use defult %d", *plinkport, DEFAULT_LINK_PORT);
        *plinkport = DEFAULT_LINK_PORT;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkTCPFilePort", &g_linktcpfileport);
    if ((g_linktcpfileport < 1) || (g_linktcpfileport > 65535)) {
        g_linktcpfileport = DEFAULT_LINK_TCP_FILE_PORT;
    }

    m_fileop.CloseFile();
    return 0;
}

/**
 * [get_currplat 获取运行当前程序的平台]
 * @return  [平台号 获取失败返回-1]
 */
int get_currplat(void)
{
    int ret = PLAT_UNKNOWN;
    char buff[64] = {0};
    CCommon common;

#if (SUOS_V==2000)
    ret = PLAT_FT;
    PRINT_INFO_HEAD
    print_info("ft os,use default %d", ret);
    return ret;
#endif

    if (common.Sysinfo("uname -m", buff, sizeof(buff)) != NULL) {
        if (strncasecmp("i686", buff, strlen("i686")) == 0) {
            ret = PLAT_I686;
        } else if (strncasecmp("SW_64", buff, strlen("SW_64")) == 0) {
            ret = PLAT_SW_64;
        } else if (strncasecmp("X86_64", buff, strlen("X86_64")) == 0) {
            ret = PLAT_X86_64;
        } else if (strncasecmp("aarch64", buff, strlen("aarch64")) == 0) {
            ret = PLAT_ARM_64;
        } else {
            PRINT_ERR_HEAD
            print_err("unknown plat[%s]", buff);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("uname -m exec fail");
    }

    return ret;
}

/**
 * [check_totalhead_strict 严格检查升级包头部]
 * @param  totalhead [升级包头部]
 * @return           [检查通过返回true]
 */
bool check_totalhead_strict(TOTAL_HEAD &totalhead)
{
    unsigned char md5buff16[16] = {0};
    int platver = 0;

    //CHECK KEY
    if ((strcmp(totalhead.checkkey, TOTAL_CHECK_KEY) != 0) && (strcmp(totalhead.checkkey, TOTAL_OS_KEY) != 0)) {
        PRINT_ERR_HEAD
        print_err("upk key = %s", totalhead.checkkey);
        printf("check key fail\n");
        return false;
    }

    //UPVER
    if (totalhead.upver < UPDATE_VERSION) {
        PRINT_ERR_HEAD
        print_err("check upver fail[%d:%d]", totalhead.upver, UPDATE_VERSION);
        printf("check upver fail[%d:%d]\n", totalhead.upver, UPDATE_VERSION);
        return false;
    }

    //PLATVER
    platver = get_currplat();
    if ((totalhead.platver == PLAT_UNKNOWN) || (platver != totalhead.platver)) {
        PRINT_ERR_HEAD
        print_err("check plat fail[%d][%d]", totalhead.platver, platver);
        printf("check plat fail[%d]\n", totalhead.platver);
        return false;
    }

    //MD5
    if (md5sum(UPDATE_PASR_TMPTAR, md5buff16) < 0) {
        PRINT_ERR_HEAD
        print_err("md5sum fail[%s]", UPDATE_PASR_TMPTAR);
        printf("md5sum fail[%s]\n", UPDATE_PASR_TMPTAR);
        return false;
    }
    if (memcmp(md5buff16, totalhead.md5buff16, 16) != 0) {
        PRINT_ERR_HEAD
        print_err("md5sum check fail[%s]", UPDATE_PASR_TMPTAR);
        printf("md5sum check fail[%s]\n", UPDATE_PASR_TMPTAR);
        return false;
    }
    return true;
}

/**
 * [check_ndbsync 数据库同步升级检查]
 * @param  totalhead [升级包头部]
 * @return           [检查通过返回true]
 */
bool check_ndbsync(TOTAL_HEAD &totalhead)
{
    char buff_line[64] = {0};
    char buff_db2[64] = {0};
    char buff_kingbase[64] = {0};
    char buff_postgresql[64] = {0};
    char buff_ckupsert[64] = {0};

    int linenum = 0;
    int db2num = 0;
    int kingbasenum = 0;
    int postgresqlnum = 0;
    int ckupsertnum = 0;
    char ver202103[20] = {"8.1.202103"};
    char ver202103_2[20] = {"8.1_2.202103"};
    char ver202104[20] = {"8.1.202104"};
    char ver202104_2[20] = {"8.1_2.202104"};
    char chcmd[1024] = {0};
    CCommon common;

    //
    //是X86_64平台
    //并且升级前是旧版的数据库同步版本
    //并且即将升级的升级包是2021年03 04月的特殊包
    //
    if ((totalhead.platver == PLAT_X86_64)
        && (!common.FileExist(NEW_DBSYNC_INIT_SH))
        && ((memcmp(totalhead.reserved, ver202103, strlen(ver202103)) == 0)
            || (memcmp(totalhead.reserved, ver202103_2, strlen(ver202103_2)) == 0)
            || (memcmp(totalhead.reserved, ver202104, strlen(ver202104)) == 0)
            || (memcmp(totalhead.reserved, ver202104_2, strlen(ver202104_2)) == 0)
           )) {

        //查找当前策略中有无配置 DB2 Kingbase Postgresql 三种数据库
        if ((common.Sysinfo("cat /var/self/rules/precfg/PREDBSYNC|wc -l",
                            buff_line, sizeof(buff_line)) == NULL)
            || (common.Sysinfo("cat /var/self/rules/precfg/PREDBSYNC |grep DBMS|grep DB2|wc -l",
                               buff_db2, sizeof(buff_db2)) == NULL)
            || (common.Sysinfo("cat /var/self/rules/precfg/PREDBSYNC |grep DBMS|grep Kingbase|wc -l",
                               buff_kingbase, sizeof(buff_kingbase)) == NULL)
            || (common.Sysinfo("cat /var/self/rules/precfg/PREDBSYNC |grep DBMS|grep Postgresql|wc -l",
                               buff_postgresql, sizeof(buff_postgresql)) == NULL)
            || (common.Sysinfo("cat /var/self/rules/precfg/PREDBSYNC |grep CKUpsert|grep \\'1\\'|wc -l",
                               buff_ckupsert, sizeof(buff_ckupsert)) == NULL)) {
            PRINT_ERR_HEAD
            print_err("check /var/self/rules/precfg/PREDBSYNC fail");
            printf("check /var/self/rules/precfg/PREDBSYNC fail\n");
            sprintf(chcmd, "echo \"数据库同步策略文件没找到 升级失败\">%s", UPDATE_PASR_STAT);
            system(chcmd);
            sleep(5); //让web多展示几秒
            return false;
        }

        linenum = atoi(buff_line);
        db2num = atoi(buff_db2);
        kingbasenum = atoi(buff_kingbase);
        postgresqlnum = atoi(buff_postgresql);
        ckupsertnum = atoi(buff_ckupsert);
        PRINT_INFO_HEAD
        print_info("linenum %d,db2num %d, kingbasenum %d, postgresqlnum %d,ckupsertnum %d",
                   linenum, db2num, kingbasenum, postgresqlnum, ckupsertnum);

        //文件中行数少于10行认为是无策略
        if (linenum < 10) {
            PRINT_INFO_HEAD
            print_info("no find dbsync rules, allow upgrade");
        } else {
            if ((db2num == 0) && (kingbasenum == 0) && (postgresqlnum == 0)) {
#if 0
                sprintf(chcmd, "echo \"警告:发现您配置了DB同步策略 本次升级不可兼容旧配置 " \
                        "1.请通过拍照等方式牢记DB同步策略 " \
                        "2.删除DB同步策略 " \
                        "3.重新导入升级 " \
                        "4.升级后重新配置策略\">%s", UPDATE_PASR_STAT);
#else
                if (ckupsertnum > 0) {
                    sprintf(chcmd,
                            "echo \"警告:发现您配置了DB同步策略 且启用了 更新转插入 功能" \
                            "本次升级后不支持此功能 建议您不要升级 本次升级退出\">%s", UPDATE_PASR_STAT);
                } else {
                    PRINT_INFO_HEAD
                    print_info("not find db2 or kingbase or postgresql rules");
                    goto _out;
                }
#endif
            } else {
                sprintf(chcmd,
                        "echo \"警告:发现您配置了[DB2]或[Kingbase]或[Postgresql]类型的DB同步策略 " \
                        "本次升级后不支持这些类型 建议您不要升级 本次升级退出\">%s", UPDATE_PASR_STAT);
            }
            system(chcmd);
            PRINT_ERR_HEAD
            print_err("dbsync rule check fail");
            sleep(10);//让web多展示几秒
            return false;
        }
    }

_out:
    PRINT_INFO_HEAD
    print_info("dbsync rules check ok");
    return true;
}

/**
 * [check_special 检查一些额外的其他信息]
 * @param  totalhead [升级包头部]
 * @return           [检查通过返回true]
 */
bool check_special(TOTAL_HEAD &totalhead)
{
    bool ret = check_ndbsync(totalhead);
    //....以后可以在此添加更多检查项
    return ret;
}

/**
 * [update_os 升级内核]
 * @param  isint     [true内网]
 * @return           [成功返回true]
 */
bool update_os(bool isint)
{
    bool bret = false;
    char chcmd[2 * FILE_PATH_MAX_LEN] = {0};
    if (isint) {
        sprintf(chcmd, "echo \"内网内核升级中\">%s", UPDATE_PASR_STAT);
        system(chcmd);
        sprintf(chcmd, "%s %s", OS_UPDATE_SH_PATH, OS_UPDATE_PACK_PATH);
    } else {
        sprintf(chcmd, "echo \"外网内核升级中\">%s", UPDATE_PASR_STAT);
        system(chcmd);
        sleep(5);     //防止外网OS脚本还未成功加权限就被执行
        sprintf(chcmd, "%s %s %s", CMDPROXY, OS_UPDATE_SH_PATH, OS_UPDATE_PACK_PATH);
    }

    FILE *fp = popen(chcmd, "r");
    if (NULL == fp) {
        PRINT_ERR_HEAD
        print_err("%s popen[%s]failed[%s]", isint ? "innet" : "outnet", chcmd, strerror(errno));
        printf("%s popen[%s]failed[%s]\n", isint ? "innet" : "outnet", chcmd, strerror(errno));
        return false;
    }
    while (fgets(chcmd, sizeof(chcmd), fp) != NULL) {
        PRINT_DBG_HEAD
        print_dbg("return info:%s", chcmd);
        if (strstr(chcmd, "success") != NULL) {
            PRINT_DBG_HEAD
            print_dbg("os update success");
            bret = true;
            break;
        }
    }
    pclose(fp);
    if (!bret) {
        PRINT_ERR_HEAD
        print_err("update %s os fail", isint ? "innet" : "outnet");
        printf("update %s os fail\n", isint ? "innet" : "outnet");
    }
    return bret;
}

/**
 * [update_os 升级内外网的OS]
 * @return  [成功返回true]
 */
bool update_os(void)
{
    system("killall ausvr");
    if (update_os(false) && update_os(true)) {
        g_osupdated = true;//需要置为true
        return true;
    }
    return false;
}

/**
 * [check_power 权限检查]
 * @return           [永久返回true]
 */
bool check_power(void)
{
    char buf[1024] = {0};
    bool bret = false;
    FILE *fp = fopen(POWER_SHOW_FILE_PATH, "r");
    if (NULL == fp) {
        PRINT_ERR_HEAD
        print_err("fopen %s failed:%s", POWER_SHOW_FILE_PATH, strerror(errno));
        return false;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        PRINT_DBG_HEAD
        print_dbg("power info = %s", buf);
        if (strstr(buf, AUTH_FOREVER_VERSION) != NULL) {
            PRINT_DBG_HEAD
            print_dbg("power is foerver");
            bret = true;
            break;
        }
    }
    pclose(fp);
    return bret;
}

/**
 * [get_modname 获取模块名]
 * @param  fname [文件路径名]
 * @return       [成功返回true]
 */
bool get_modname(const char *fname)
{
    char *p1 = NULL;
    char *p2 = NULL;
    char *p3 = NULL;
    static char prevmod[FILE_PATH_MAX_LEN] = {0};
    char modname[FILE_PATH_MAX_LEN] = {0};
    char cmd[FILE_PATH_MAX_LEN] = {0};
    p1 = strchr((char *)fname, '-');
    if (p1 != NULL) {
        p2 = strchr(++p1, '-');
    } else {
        return false;
    }
    if (p2 != NULL) {
        p3 = strchr(++p2, '-');
    } else {
        return false;
    }
    if (p3 != NULL) {
        strncpy(modname, p2, p3 - p2);
    } else {
        return false;
    }
    PRINT_DBG_HEAD
    print_dbg("get fname = %s ,modname = %s ", fname, modname);
    if (strcmp(prevmod, modname) != 0) {
        strcpy(prevmod, modname);
        sprintf(cmd, "echo \"%s\">%s", prevmod, UPDATE_PASR_STAT);
        system(cmd);
        sleep(2);
    }
    return true;
}

/**
 * [update_file_os 升级OS文件]
 * @param  orgpath  [已经还原为完整升级内容的文件]
 * @param  filehead [文件头]
 * @return          [成功返回true]
 */
bool update_file_os(const char *orgpath, FILE_HEAD &filehead)
{
    char chcmd[FILE_PATH_MAX_LEN] = {0};
    bool bret = false;
    char newpath[FILE_PATH_MAX_LEN] = {0};
    sprintf(newpath, "/tmp/%s", filehead.path);
    //升级外网
    if (send_file_tcp(orgpath, newpath, filehead.permission) == 0) {
        PRINT_DBG_HEAD
        print_dbg("tcp send osfile[%s]to outnet[%s]success", orgpath, newpath);
    } else if (send_file_udp(orgpath, newpath, 10) == 0) {
        PRINT_DBG_HEAD
        print_dbg("send osfile[%s]to outnet[%s]success", orgpath, newpath);
        if (filehead.permission == PERM_EXEC) {
            sprintf(chcmd, "chmod +x '%s'", newpath);
            PeerExecuteCMD(chcmd);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("send osfile[%s] to outnet failed", orgpath);
        printf("send osfile[%s] to outnet failed\n", orgpath);
        return bret;
    }

    //升级内网
    if (update_mkdir(newpath)) {
        if (filehead.permission == PERM_EXEC) {
            snprintf(chcmd, sizeof(chcmd), "chmod +x '%s'", orgpath);
            system(chcmd);
        }
        snprintf(chcmd, sizeof(chcmd), "mv -f '%s' '%s'", orgpath, newpath);
        system(chcmd);
        bret = true;
    }
    return bret;
}

/**
 * [update_file_outnet 升级外网文件]
 * @param  orgpath  [已经还原为完整升级内容的文件]
 * @param  filehead [文件头]
 * @return          [成功返回true]
 */
bool update_file_outnet(const char *orgpath, FILE_HEAD &filehead)
{
    char chcmd[FILE_PATH_MAX_LEN] = {0};
    get_modname(orgpath);
    if (send_file_tcp(orgpath, filehead.path, filehead.permission) == 0) {
        PRINT_INFO_HEAD
        print_info("tcp OUTNET[PERM:%d][LEN:%d][ORGPATH:%s][PATH:%s]", filehead.permission, filehead.len, orgpath, filehead.path);
        return true;
    } else if (send_file_udp(orgpath, filehead.path, 10) == 0) {
        if (filehead.permission == PERM_EXEC) {
            sprintf(chcmd, "chmod +x '%s'", filehead.path);
            PeerExecuteCMD(chcmd);
        }
        PRINT_INFO_HEAD
        print_info("OUTNET[PERM:%d][LEN:%d][ORGPATH:%s][PATH:%s]", filehead.permission, filehead.len, orgpath, filehead.path);
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("OUTNET[PERM:%d][LEN:%d][ORGPATH:%s][PATH:%s]", filehead.permission, filehead.len, orgpath, filehead.path);
        printf("send file to outnet fail.[PERM:%d][LEN:%d][ORGPATH:%s][PATH:%s]\n",
               filehead.permission, filehead.len, orgpath, filehead.path);
        return false;
    }
}

/**
 * [update_file_innet 升级内网文件]
 * @param  orgpath  [已经还原为完整升级内容的文件]
 * @param  filehead [文件头]
 * @return          [成功返回true]
 */
bool update_file_innet(const char *orgpath, FILE_HEAD &filehead)
{
    char chcmd[2 * FILE_PATH_MAX_LEN] = {0};

    if (g_isforever
        && ((strcmp(AUTH_FILE_PATH1, filehead.path) == 0) || (strcmp(AUTH_FILE_PATH2, filehead.path) == 0))) {
        PRINT_INFO_HEAD
        print_info("find power file[%s],current license forever,ignore it", filehead.path);
        unlink(orgpath);
        return true;
    }
    get_modname(orgpath);
    if (update_mkdir(filehead.path)) {
        if (filehead.permission == PERM_EXEC) {
            snprintf(chcmd, sizeof(chcmd), "chmod +x '%s'", orgpath);
            system(chcmd);
        }
        snprintf(chcmd, sizeof(chcmd), "mv -f '%s' '%s'", orgpath, filehead.path);
        system(chcmd);
        PRINT_INFO_HEAD
        print_info("INNET[PERM:%d][LEN:%d][ORGPATH:%s][PATH:%s]", filehead.permission, filehead.len, orgpath, filehead.path);
        return true;
    }
    return false;
}

/**
 * [update_file 升级文件]
 * @param  orgpath  [已经还原为完整升级内容的文件]
 * @param  filehead [文件头]
 * @return          [成功返回true]
 */
bool update_file(const char *orgpath, FILE_HEAD &filehead)
{
    bool bret = false;

    if ((filehead.area != FILE_AREA_OS) && (g_osfcnt >= 2) && (!g_osupdated)) {
        if (update_os()) {
        } else {
            PRINT_ERR_HEAD
            print_err("update os fail\n");
            return bret;
        }
    }

    switch (filehead.area) {
    case FILE_AREA_INNET:
        bret = update_file_innet(orgpath, filehead);
        if (bret) {g_infcnt++;}
        break;
    case FILE_AREA_OUTNET:
        bret = update_file_outnet(orgpath, filehead);
        if (bret) {g_outfcnt++;}
        break;
    case FILE_AREA_OS:
        bret = update_file_os(orgpath, filehead);
        if (bret) {g_osfcnt++;}
        break;
    case FILE_AREA_BOTH:
        bret = update_file_outnet(orgpath, filehead)
               && update_file_innet(orgpath, filehead);
        if (bret) {g_bothfcnt++;}
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown area[%d]orgpath[%s]", filehead.area, orgpath);
        printf("unknown area[%d]orgpath[%s]\n", filehead.area, orgpath);
        break;
    }
    return bret;
}

/**
 * [do_update 处理升级包]
 * @param  filename [升级包路径名称]
 * @return          [成功返回true]
 */
bool do_update(const char *filename)
{
    bool bret = false;
    char chcmd[1024] = {0};
    TOTAL_HEAD totalhead;
    memset(&totalhead, 0, sizeof(totalhead));

    PRINT_INFO_HEAD
    print_info("begin to update");

    g_isforever = check_power();

    if ((readlinkinfo(&g_linklanipseg, &g_linklanport) == 0)
        && check_updatepack_suffix(filename)
        && check_updatepack_size(filename, false)
        && uppack_updatepack(filename, totalhead, NULL)
        && check_totalhead_strict(totalhead)
        && check_special(totalhead)
        && unpack_tmptar()
        && scandir_file(update_file)) {

        if (strcmp(totalhead.checkkey, TOTAL_OS_KEY) == 0) {
            if ((g_osfcnt >= 2) && (!g_osupdated) && (!update_os())) {
                //只有当更新包里面只有os相关的文件，才会执行到这里的update os
                PRINT_ERR_HEAD
                print_err("update os fail");
                return false;
            }
            sprintf(chcmd, "sed -i s/0003/0004/ /var/self/sysinfo.cf");
            system(chcmd);
            PeerExecuteCMD(chcmd);
            sprintf(chcmd, "echo \"更新成功 即将重启\">%s", UPDATE_PASR_STAT);
            system(chcmd);

            PRINT_DBG_HEAD
            print_dbg("update success ,have os");
        }

        system(GAP_IN_SHELL);
        unlink(GAP_IN_SHELL);

        PeerExecuteCMD(GAP_OUT_SHELL, 120);
        sprintf(chcmd, "rm -f %s", GAP_OUT_SHELL);
        PeerExecuteCMD(chcmd);

        PRINT_INFO_HEAD
        print_info("update success.infilecnt[%d] outfilecnt[%d] osfilecnt[%d] bothfilecnt[%d]",
                   g_infcnt, g_outfcnt, g_osfcnt, g_bothfcnt);
        bret = true;
    } else {
        PRINT_ERR_HEAD
        print_err("update fail");
        bret = false;
    }
    return bret;
}

/**
 * [update_check 检查升级包]
 * @param  filename [升级包路径名称]
 * @return          [成功返回true]
 */
bool update_check(const char *filename)
{
    bool bret = false;
    TOTAL_HEAD totalhead;
    memset(&totalhead, 0, sizeof(totalhead));

    bret = (readlinkinfo(&g_linklanipseg, &g_linklanport) == 0)
           && check_updatepack_suffix(filename)
           && check_updatepack_size(filename, false)
           && uppack_updatepack(filename, totalhead, NULL)
           && check_totalhead_strict(totalhead);

    if (bret) {
        PRINT_DBG_HEAD
        print_dbg("check upk success, ver[%s]", totalhead.reserved);
        printf("ver:%s", totalhead.reserved);//前台要接收该输出信息，不可以注释或删除
    } else {
        PRINT_ERR_HEAD
        print_err("check upk failed");
        printf("check upk failed\n");
    }
    return bret;

}

/**
 * [read_cslan 读取管理口号]
 * @param  ethno [管理口号 出参]
 * @return       [成功返回true]
 */
bool read_cslan(int &ethno)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        printf("openfile[%s] error\n", SYSINFO_CONF);
        return false;
    }

    if (fileop.ReadCfgFileInt("SYSTEM", "CSLan", &ethno) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("read CSLan error");
        printf("read CSLan error\n");
        fileop.CloseFile();
        return false;
    }

    fileop.CloseFile();
    return true;
}

/**
 * [do_modcer 处理模块授权]
 * @param  filename [模块授权文件]
 * @return          [成功返回true]
 */
bool do_modcer(const char *filename)
{
    char chcmd[1024] = {0};
    int ethno = 0;

    if (!read_cslan(ethno)) {
        return false;
    }

    CLicenseMod lmod(ethno);
    if (lmod.readfile(filename)) {
        sprintf(chcmd, "cp -f '%s' '%s'", filename, MOD_LICENSE_FILE);
        system(chcmd);
        system("sync");
    } else {
        //读取失败 则可能是校验失败
        return false;
    }

    return true;
}


int IS_XOR = 0;
int main(int argc, char **argv)
{
    _log_init_(glog_p, update);

    PRINT_INFO_HEAD
    print_info("enter update");

    if (argc == 2) {
        if (do_update(argv[1])) {
        } else {
            return -1;
        }
    } else if ((argc == 3) && (strcmp(argv[1], "-c") == 0)) {
        if (update_check(argv[2])) {
            return 0;
        } else {
            printf("check upk failed\n");
            return -1;
        }
    } else if ((argc == 3) && (strcmp(argv[2], "cer") == 0)) {
        if (do_modcer(argv[1])) {
        } else {
            return -1;
        }
    } else {
        usage(argv[0]);
        return -1;
    }

    system("sync");
    system("/etc/init.d/start >/dev/null");
    printf("success\n");//WEB判断升级成功的依据
    return 0;
}
