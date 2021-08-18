/*******************************************************************************************
*文件:  init_out.c
*描述:  外网系统启动程序，设置相关系统环境和启动各业务程序
*作者:  王君雷
*日期:  2015
*
*修改:
*        /proc/sys/vm/panic_on_oom写入1，系统异常可以自动重启   ------> 2018-01-23
*        改为UTF8编码,改用linux缩进格式                         ------> 2018-01-23
*        配置文件使用宏表示                                     ------> 2018-04-23
*        引入zlog                                               ------> 2018-09-10
*        启动后创建ipv6版本的CHAIN1链                           ------> 2019-01-30
*        开机打开ipv6的forwarding                               ------> 2019-02-26
*        内联卡设置ethtool -K ethx rxvlan/txvlan off等          ------> 2019-07-31
*        设置运行sys6时链接wireshark的环境变量                  ------> 2019-10-08-dzj
*        执行hwclock -s 解决使用CST时区差8小时的问题            ------> 2019-12-24
*        开机拉起USB程序                                        ------> 2020-07-16
*        只有V8.1的系统开机拉起USB程序                           ------> 2020-08-03
*        拉起重构后的数据库同步程序                              ------> 2020-08-17
*        拉起重构后的数据库同步程序之前判断脚本是否存在            ------> 2020-09-02
*        外网侧开机启动时创建NAT_PRIV_FILE链用于私有文件交换跳转   ------> 2020-11-05
*        开机创建组播使用的iptables链                            ------> 2020-11-12
*        限制多播源地址过滤数量由默认的10改为20                   ------> 2020-11-13
*        开机创建WEB代理使用的iptables链                         ------> 2020-11-18
*        开机创建FILTER_MAC链,用于IPMAC绑定                      ------> 2020-11-25
*        拉起重构后的数据库同步程序使用check_run.sh               ------> 2020-12-04
*        开机拉起mac自检程序                                     ------> 2021-01-29
*        开机创建防DDOS使用的链                                  ------> 2021-03-04
*        添加启用看门狗功能宏                                    ------> 2021-03-10
*        开机启动时调用调整php.ini相关配置,为深信服二维码功能做准备 ------> 2021-03-22
*        开机启动时调用syslog_set.sh修改logger.sh脚本            ------> 2021-04-09
*******************************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "fileoperator.h"
#include "common.h"
#include "define.h"
#include "FCKey.h"
#include "hardinfo.h"
#include "debugout.h"

loghandle glog_p = NULL;

/**
 * [readlinklan 读取内联卡信息]
 * @param  plinklan    [出参]
 * @param  plinklanseg [出参]
 * @return             [description]
 */
int readlinklan(int *plinklan, int *plinklanseg)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open[%s]fail", SYSINFO_CONF);
        return -1;
    }

    char tmp[100] = {0};
    if (fileop.ReadCfgFile("SYSTEM", "LinkLan", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read LinkLan fail");
        fileop.CloseFile();
        return -1;
    }
    *plinklan = atoi(tmp);

    fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", plinklanseg);
    fileop.CloseFile();
    return 0;
}

/**
 * [upcard UP所有网卡 按最多20个处理的]
 */
void upcard(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < MAX_NIC_NUM; i++ ) {
        sprintf(chcmd, "ifconfig eth%d up >/dev/null 2>&1 ", i);
        system(chcmd);
    }
}

/**
 * [bulid_key 创建硬件绑定KEY]
 * @param lan [内联卡号]
 */
void bulid_key(int lan)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char chout[33] = {0};

    KEY mykey(KEY_FILE, lan);
    if (mykey.file_exist(CLI_TOOL_FILE)) {
        if (mykey.file_exist(KEY_FILE)) {
            //因为已经存在key文件了 直接把clitool删除掉
            sprintf(chcmd, "rm -f %s", CLI_TOOL_FILE);
            system(chcmd);
            system("sync");
        } else {
            //创建key文件
            if (mykey.md5(time(NULL), chout)) {
                sprintf(chcmd, "%s %s", CLI_TOOL_FILE, chout);
                system(chcmd);
                if (mykey.file_exist(KEY_FILE)) {
                    //创建成功后把clitool删除
                    sprintf(chcmd, "rm -f %s", CLI_TOOL_FILE);
                    system(chcmd);
                    system("sync");
                } else {
                }
            }
        }
    }
}

/**
 * [check_key 检查硬件绑定KEY]
 * @param  lan [内联卡号]
 * @return     [成功返回true]
 */
bool check_key(int lan)
{
    char readmd5[33] = {0};//文件中读取到的
    char calcmd5[33] = {0};//当前环境计算得到的

    KEY mykey(KEY_FILE, lan);
    if (mykey.file_exist(KEY_FILE)) {
        if (mykey.read_key(readmd5)) {
            if (mykey.calc_md5(calcmd5)) {
                if (strcmp(readmd5, calcmd5) == 0) {
                    return true;
                } else {
                    PRINT_ERR_HEAD
                    print_err("readinfo[%s] calcinfo[%s]", readmd5, calcmd5);
                }
            }
        }
    }

    return false;
}

/**
 * [readusb 读取是否启用USB程序]
 * @param  pusb [出参]
 * @return      [成功返回0]
 */
int readusb(int *pusb)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open[%s]fail", SYSINFO_CONF);
        return -1;
    }

    char tmp[100] = {0};
    if (fileop.ReadCfgFile("SYSTEM", "CKUSB", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read CKUSB fail");
        fileop.CloseFile();
        return -1;
    }
    *pusb = atoi(tmp);
    fileop.CloseFile();
    return 0;
}

/**
 * [usb_run 运行usb程序]
 */
void usb_run(void)
{
#if (SUOS_V==81)
    int tmpint = 1;
    readusb(&tmpint);
    PRINT_INFO_HEAD
    print_info("ck usb is %d", tmpint);

    if (tmpint == 1) {
        system(USB_TOOL_SH);
    }
#endif
}

/**
 * [run_new_dbsync 拉起重构后的数据库同步程序]
 */
void run_new_dbsync(void)
{
    CCommon common;
    if (!common.FileExist(NEW_DBSYNC_INIT_SH)) {
        PRINT_INFO_HEAD
        print_info("[%s] not exist.return", NEW_DBSYNC_INIT_SH);
        return;
    }
    char chcmd[CMD_BUF_LEN] = {0};
    chmod(NEW_DBSYNC_INIT_SH, 0755);
    chmod(NEW_DBSYNC_RUN_SH, 0755);
    chmod(NEW_DBSYNC_CK_RUN_SH, 0755);
    system(NEW_DBSYNC_INIT_SH);
    sprintf(chcmd, "%s &", NEW_DBSYNC_CK_RUN_SH);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("run new dbsync[%s]", chcmd);
}

/**
 * [checkmac_run 运行mac自检程序]
 * @param flag [true表示接收 false表示发送]
 */
void checkmac_run(bool flag)
{
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "%s %c &", CHECK_MAC_FILE, flag ? 'r' : 's');
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("checmac run:%s", chcmd);
}

/**
 * [call_watchdog 调用看门狗程序]
 */
void call_watchdog(void)
{
#ifdef SUPPORT_WATCHDOG
    CCommon common;
    if (!common.FileExist(CALL_WARTCH_DOG)) {
        PRINT_INFO_HEAD
        print_info("[%s] not exist.return", CALL_WARTCH_DOG);
        return;
    }

    char chcmd[CMD_BUF_LEN] = {0};
    chmod(CALL_WARTCH_DOG, 0755);
    sprintf(chcmd, "%s >/dev/null 2>&1& ", CALL_WARTCH_DOG);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("run call watchdog[%s]", chcmd);
#endif
}

/**
 * [mod_phpini 调整php.ini配置文件]
 */
void mod_phpini(void)
{
#define MOD_PHPINI_FILE "/initrd/abin/modphpini.sh"
    CCommon common;
    if (!common.FileExist(MOD_PHPINI_FILE)) {
        PRINT_INFO_HEAD
        print_info("[%s] not exist.return", MOD_PHPINI_FILE);
        return;
    }
    chmod(MOD_PHPINI_FILE, 0755);
    system(MOD_PHPINI_FILE);
    unlink(MOD_PHPINI_FILE);
}

/**
 * [mod_logger 修改填充logger.sh中的信息]
 */
void mod_logger(void)
{
#define SYSLOG_SET_SH "/initrd/abin/syslog_set.sh"
    CCommon common;
    if (!common.FileExist(SYSLOG_SET_SH)) {
        PRINT_INFO_HEAD
        print_info("[%s] not exist.return", SYSLOG_SET_SH);
        return;
    }
    chmod(SYSLOG_SET_SH, 0755);
    system(SYSLOG_SET_SH);
    unlink(SYSLOG_SET_SH);
    PRINT_INFO_HEAD
    print_info("mod logger.sh over");
}

int main(int argc, char **argv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    _log_init_(glog_p, init_out);

    upcard();
    system("ulimit -n 65536");
    //system(HOW_TO_RUN_MYSQL);
    system("rm -rf /usr/local/apache2/logs/*");
    system("iptables -N FILTER_KEYWORD");
    system("iptables -N FILTER_MULTICAST");
    system("iptables -N FILTER_WEBPROXY");
    system("iptables -N FILTER_MAC");
    system("iptables -N FILTER_DDOS");
    system("iptables -t nat -N CHAIN1");
    system("iptables -t nat -N NAT_PRIV_FILE");
    system("iptables -t nat -N NAT_FILE");
    system("iptables -t nat -N NAT_MULTICAST");
    system("iptables -t nat -N NAT_WEBPROXY");
#if (SUPPORT_IPV6==1)
    system("ip6tables -N FILTER_KEYWORD");
    system("ip6tables -N FILTER_MULTICAST");
    system("ip6tables -N FILTER_WEBPROXY");
    system("ip6tables -N FILTER_MAC");
    system("ip6tables -t nat -N CHAIN1");
    system("ip6tables -t nat -N NAT_PRIV_FILE");
    system("ip6tables -t nat -N NAT_FILE");
    system("ip6tables -t nat -N NAT_MULTICAST");
    system("ip6tables -t nat -N NAT_WEBPROXY");
    system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");
#endif
    system("echo 1 >/proc/sys/net/ipv4/conf/all/arp_ignore");
    system("echo 2 >/proc/sys/net/ipv4/conf/all/arp_announce");
    system("echo 1 >/proc/sys/net/ipv4/ip_forward");
    system("echo 1 > /proc/sys/vm/panic_on_oom");
    system("echo 1 >/proc/sys/kernel/panic_on_oops");
    system("echo 3 >/proc/sys/kernel/panic");
    system("echo 500000 > /proc/sys/net/nf_conntrack_max");
    sprintf(chcmd, "echo %d > /proc/sys/net/ipv4/igmp_max_msf", MULTICAST_MAX_SRC_NUM);//限制多播源地址过滤数量
    system(chcmd);
    system("export OPENSSL_NO_DEFAULT_ZLIB=1");
    setenv("LD_LIBRARY_PATH", "/lib64:/usr/lib64:/lib:/usr/lib", 0);
    system("hwclock -s");
    system("/etc/init.d/startvir &");
    usb_run();
    checkmac_run(false);
    call_watchdog();
    mod_phpini();
    mod_logger();

    int linklan = 0;
    int linklanseg = 1;

    if (readlinklan(&linklan, &linklanseg) == 0) {
        sprintf(chcmd, "ifconfig eth%d mtu 9000", linklan);
        system(chcmd);
    } else {
        printf("readlinklan error");
        PRINT_ERR_HEAD
        print_err("read link lan fail");
        return 0;
    }

    bulid_key(linklan);

    //检查key
    if (!check_key(linklan)) {
        printf("check_key error\n");
        PRINT_ERR_HEAD
        print_err("check key error");
        return -1;
    }

    snprintf(chcmd, sizeof(chcmd), "ifconfig eth%d %d.0.0.253 netmask %s up", linklan, linklanseg, DEFAULT_LINK_MASK);
    system(chcmd);
    snprintf(chcmd, sizeof(chcmd), "ethtool -K eth%d txvlan off", linklan);
    system(chcmd);
    snprintf(chcmd, sizeof(chcmd), "ethtool -K eth%d rxvlan off", linklan);
    system(chcmd);
    system(HOW_TO_RUN_MYSQL);
    run_new_dbsync();
    sleep(5);
    system("cp -f /etc/httpd/extra/normal-httpd-ssl.conf /etc/httpd/extra/httpd-ssl.conf");
    system("/usr/local/apache2/bin/apachectl restart");
    system("/usr/local/php5/bin/php /var/ctauth/AuthDaemon.php &");
    system("/initrd/abin/recvmain_w &");
    PRINT_INFO_HEAD
    print_info("init over");
    return 0;
}
