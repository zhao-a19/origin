/*******************************************************************************************
*文件: gap_config.h
*描述: 路径配置宏定义
*
*作者: 王君雷
*日期: 2018-01-23
*修改: 创建文件                                                   ------> 2018-01-23
*      把程序中使用到目录的地方，都改用宏。V8系统进行了目录规划，
*      通过宏控制，实现读取不同的目录                             ------> 2018-04-23
*      mac.info文件，v6和v8，读取不同的目录                       ------> 2018-04-24
*      添加宏SUPPORT_DPDK，V8支持DPDK，V6不支持                   ------> 2018-05-16
*      添加PDT_CONF配置项                                         ------> 2018-07-31
*      把病毒库查杀服务的本地套接字路径放到本文件中               ------> 2018-08-07
*      添加私有协议文件同步配置文件                               ------> 2018-08-28
*      添加短信告警文件路径到本文件                               ------> 2019-03-06
*      nginx文件路径调整，改放到/usr/local/nginx/目录             ------> 2019-07-05
*      添加IPV6删除路由脚本路径ROUTE6_DEL_SH                      ------> 2019-07-08
*      添加平台互联互斥锁使用的路径和相关配置文件                 ------> 2019-07-31 -dzj
*      除了V6版本，其他版本不指定iptables的绝对路径               ------> 2019-09-04
*      修改设置iptables规则为iptables-restore方式                 ------> 2019-12-01-dzj
*      添加TCP发送和接收文件程序                                  ------> 2020-02-25 wjl
*      TCP文件传输使用文件transfer                                ------> 2020-03-10
*      添加LCD_TTY_DEV等arm64合并过程中涉及到的文件;除了v6
*      都使用系统自带的awk工具                                    ------> 2020-05-15
*      添加USB启动脚本路径                                        ------> 2020-07-16
*      支持飞腾平台，重新约定SUOS_V号,arm64对应1000，飞腾对应2000 ------> 2020-07-27
*      添加重构后的dbsync配置文件                                ------> 2020-08-17
*      添加通过HA工具恢复用户配置功能                             ------> 2020-09-28
*      添加scancfg宏                                            ------> 2020-10-28
*      修改scancfg为diffcfg                                     ------> 2020-11-09
*      注释DPDK相关内容                                          ------> 2020-12-03
*      添加宏NEW_DBSYNC_CK_RUN_SH                               ------> 2020-12-04
*      添加看门狗程序相关路径                                     ------> 2021-03-10
*      添加新数据库同步配置文件bak路径                             ------> 2021-03-30
*******************************************************************************************/
#ifndef _GAP_CONFIG_H_
#define _GAP_CONFIG_H_

#define UNIX_REPORT_SRV_PATH   "/tmp/report_svr_sock"
#define UNIX_RULES_SRV_PATH    "/tmp/rules_svr_sock"
#define UNIX_SERV_PATH         "/tmp/stf"
#define UNIX_VIRUS_PATH        "/tmp/virus"
#define WEBPROXY_RUN_CONF      "/tmp/webproxy"       //web代理启动配置文件路径
#define START_PID_PATH         "/tmp/startpid"       //文件锁路径  为了避免多个进程同时调用start
#define SYS_CMD_PATH           "/syscmd"             //执行系统命令，消息队列路径
#define MAIL_STORE_PATH        "/initrd/mail_temp/"
#define START_CF               "/etc/init.d/start.cf"
#define CMD_PROXY_PATH         "/initrd/abin/"
#define PORT_LIST_MUTEX_PATH   "/portlistmutex"      //互斥访问portlist使用的路径
#define TCP_STATE_MUTEX_PATH   "/tcpthstatemutex"    //互斥访问tcpthstate使用的路径
#define SIP_TCP_STATE_MUTEX_PATH   "/siptcpthstatemutex"    //互斥访问siptcpthstate使用的路径
#define IPTABLES_MUTEX_PATH    "/iptlock"            //互斥访问iptables的锁的路径 多线程同时操作ipitable可能会失败
#define RUN_LOG_PATH           "/initrd/abin/run.log"
#define VERSION_FILE           "/initrd/abin/version"
#define VIRUS_VERSION_FILE     "/initrd/viruslib/version"
#define DPDK_NIC_BIND_PY       "/initrd/abin/dpdk_nic_bind.py"
#define CREATEDB_FILE          "/initrd/abin/createdb"
#define LINK_SERVER            "/initrd/abin/gapsip"
#define MYSQL_SUDB_PATH        "/var/lib/mysql/sudb/"
#define INIT_SYS_SHELL         "/etc/init.d/initsys"
#define LAST_RULE_DIR                   "/initrd/last/"
#define ORIGINAL_DIR                    "/initrd/original/"
#define ORIGINAL_TEST_DIR               "/initrd/original_ts/"
#define HTTPD_SSL_CONF                  "/etc/httpd/extra/httpd-ssl.conf"
#define ORIGINAL_NORMAL_HTTPD_SSL_CONF  "/initrd/original/normal-httpd-ssl.conf"
#define ORIGINAL_TEST_HTTPD_SSL_CONF    "/initrd/original_ts/test-httpd-ssl.conf"
#define NORMAL_HTTPD_SSL_CONF           "/etc/httpd/extra/normal-httpd-ssl.conf"
#define TEST_HTTPD_SSL_CONF             "/etc/httpd/extra/test-httpd-ssl.conf"
#define IRQ_SH_PATH                     "/initrd/abin/irq.sh"
#define SUL2FWD_FILE           "/initrd/abin/sul2fwd"
#define CLEAN_TRACK_FILE       "/initrd/abin/clean_track"
#define NTPCLIENT              "/initrd/abin/ntpclient"
#define PRIVFSYNC              "/initrd/abin/fileclient"
#define MSYNC_FILE             "/initrd/abin/msync"
#define WEB_PROXY              "/initrd/abin/webproxy"
#define SERIAL_CFG             "/tmp/serial.cf"
#define IP6TABLES              "ip6tables"
#define SMSCLINET              "/initrd/abin/smsc"
#define NGINX                  "/usr/local/nginx/nginx"
#define NGINX_HTTP_CONF        "/usr/local/nginx/conf/httpproxy.conf"
#define ROUTE6_DEL_SH          "/initrd/abin/ipv6routedel.sh"
#define RESTART                "/etc/init.d/restart"
#define ETC_START              "/etc/init.d/start"
#define ETC_STARTALL           "/etc/init.d/startall"
#define CMDPROXY               "/initrd/abin/cmdproxy"
#define SNMPD_CONF             "/etc/snmp/snmpd.conf"
#define SNMPD_CONF_BAK         "/etc/snmp/snmpd.conf.bak"
#define TRANSFER_FILE          "/initrd/abin/transfer"
#define MEM_INFO_FILE          "/proc/meminfo"
#define USB_TOOL_SH            "/tstools/insusbtool.sh"
#define NEW_DBSYNC_INIT_SH     "/initrd/abin/java/dbsync/init.sh"
#define NEW_DBSYNC_RUN_SH      "/initrd/abin/java/dbsync/run.sh"
#define NEW_DBSYNC_CK_RUN_SH   "/initrd/abin/java/dbsync/check_run.sh"
#define NEW_DBSYNC_TOOL        "/initrd/abin/dbsync_tool"
#define ORIGINAL_USERCONF      "/initrd/original/precfg/USERCONF"
#define ORIGINAL_PASSWD        "/initrd/original/passwd"
#define ORIGINAL_PRECFG_DIR    "/initrd/original/precfg/"
#define PASSWD                 "/etc/passwd"
#define PUT_FILE               "/initrd/abin/putfile"
#define CHECK_LOG_FILE         "/initrd/abin/check_log"
#define DIFFCFG                "/initrd/abin/diffcfg"
#define NEW_DBSYNC_CLEAR       "/initrd/abin/java/dbsync/clear.sh"
#define CHECK_MAC_FILE         "/initrd/abin/checkmac"
#define CALL_WARTCH_DOG        "/initrd/abin/callwd"
#define WATCHDOG_TINA          "/var/cusmod/watchdog_tina"
#define PREDBSYNC_BAK          "/initrd/abin/PREDBSYNC-bak"
#define EN_FILE_PATH           "/initrd/abin/enfile"
#define DBSYNC_TOOL_PID_PATH   "/tmp/dbsync_tool_pid"       //文件锁路径  为了避免多个进程同时调用
#define LOG_MOVE_FILE          "/initrd/abin/log_mv"

#if (SUOS_V==1000)
#define LCD_TTY_DEV            "/dev/ttyS2"
#define NET_CONNTRACK_FILE     "/proc/4/net/nf_conntrack"
#else
#define LCD_TTY_DEV            "/dev/ttyS1"
#define NET_CONNTRACK_FILE     "/proc/net/nf_conntrack"
#endif

#if (SUOS_V==8) || (SUOS_V==81) || (SUOS_V==1000) || (SUOS_V==2000)
#define HOW_TO_RUN_MYSQL       "mysqld_safe --user=root&"
#define RULE_CONF              "/var/self/rules/conf/SYSRULES"
#define KEY_CONF               "/var/self/rules/conf/Key.cfg"
#define KEYUTF8_CONF           "/var/self/rules/conf/KeyUTF.cfg"
#define SYSSET_CONF            "/var/self/rules/conf/sysset.cf"
#define DEV_CONF               "/var/self/rules/conf/devconfig.cf"
#define BONDING_CONF           "/var/self/rules/conf/bonding.cf"
#define MULTICAST_CONF         "/var/self/rules/conf/multicast.cf"
#define SIP_CONF               "/var/self/rules/conf/sip.cf"
#define SIP_INTER_CNT_CONF     "/var/self/rules/conf/sip-interconnect.cf"
#define PDT_CONF               "/var/self/rules/conf/pdt.cf"
#define LINK_SIP_CONF          "/var/self/rules/conf/linksip.cf"
#define FILESYNC_CONF          "/var/self/rules/conf/filesync.cf"
#define PRIV_FILESYNC_CONF     "/var/self/rules/conf/privfsync.cf"
#define DBSYNC_CONF            "/var/self/rules/conf/dbsync.cf"
#define WEBPROXY_CONF          "/var/self/rules/conf/webproxy.cf"
#define PRECFG_DIR             "/var/self/rules/precfg/"
#define IPAUTH_CONF            "/var/self/rules/precfg/IPAUTHCONF"
#define AUTHUSERCONF           "/var/self/rules/precfg/AUTHUSERCONF"
#define USERCONF               "/var/self/rules/precfg/USERCONF"
#define NEW_DBSYNC_CONF        "/var/self/rules/precfg/PREDBSYNC"//新加
#define SYSINFO_CONF           "/var/self/sysinfo.cf"
#define SYS_AUTH_DIR           "/var/self/rules/auth/"
#define RULES_DIR              "/var/self/rules/"
#define MAC_INFO_FILE          "/var/self/mac.info"
#define RULE_CONF_TEST         "/var/self/rules_ts/conf/SYSRULES"
#define RULES_DIR_TEST         "/var/self/rules_ts/"
#define SYSSET_CONF_TEST       "/var/self/rules_ts/conf/sysset.cf"
#define KEY_CONF_TEST          "/var/self/rules_ts/conf/Key.cfg"
#define DEV_CONF_TEST          "/var/self/rules_ts/conf/devconfig.cf"
#define IPAUTH_CONF_TEST       "/var/self/rules_ts/precfg/IPAUTHCONF"
#define AUTHUSERCONF_TEST      "/var/self/rules_ts/precfg/AUTHUSERCONF"
#define SYS_AUTH_DIR_TEST      "/var/self/rules_ts/auth/"
//#define SUPPORT_DPDK           1
#define IPTABLES               "iptables"
#define CONNTRACK              "conntrack"
#define IPTABLES_RULE_FILE     "/tmp/iptables-rules"
#define IP6TABLES_RULE_FILE    "/tmp/ip6tables-rules"
#define AWK_PATH               "awk"

#elif (SUOS_V==6)
#define HOW_TO_RUN_MYSQL       "/usr/bin/safe_mysqld --user=root&"
#define RULE_CONF              "/var/www/rules/conf/SYSRULES"
#define KEY_CONF               "/var/www/rules/conf/Key.cfg"
#define KEYUTF8_CONF           "/var/www/rules/conf/KeyUTF.cfg"
#define SYSSET_CONF            "/var/www/rules/conf/sysset.cf"
#define DEV_CONF               "/var/www/rules/conf/devconfig.cf"
#define BONDING_CONF           "/var/www/rules/conf/bonding.cf"
#define MULTICAST_CONF         "/var/www/rules/conf/multicast.cf"
#define SIP_CONF               "/var/www/rules/conf/sip.cf"
#define PDT_CONF               "/var/www/rules/conf/pdt.cf"
#define SIP_INTER_CNT_CONF     "/var/www/rules/conf/sip-interconnect.cf"
#define LINK_SIP_CONF          "/var/www/rules/conf/linksip.cf"
#define FILESYNC_CONF          "/var/www/rules/conf/filesync.cf"
#define PRIV_FILESYNC_CONF     "/var/www/rules/conf/privfsync.cf"
#define DBSYNC_CONF            "/var/www/rules/conf/dbsync.cf"
#define WEBPROXY_CONF          "/var/www/rules/conf/webproxy.cf"
#define PRECFG_DIR             "/var/www/rules/precfg/"
#define IPAUTH_CONF            "/var/www/rules/precfg/IPAUTHCONF"
#define AUTHUSERCONF           "/var/www/rules/precfg/AUTHUSERCONF"
#define USERCONF               "/var/www/rules/precfg/USERCONF"
#define SYSINFO_CONF           "/var/www/sysinfo.cf"
#define SYS_AUTH_DIR           "/var/www/rules/auth/"
#define RULES_DIR              "/var/www/rules/"
#define MAC_INFO_FILE          "/var/www/mac.info"
#define RULE_CONF_TEST         "/var/www_ts/rules/conf/SYSRULES"
#define RULES_DIR_TEST         "/var/www_ts/rules/"
#define SYSSET_CONF_TEST       "/var/www_ts/rules/conf/sysset.cf"
#define KEY_CONF_TEST          "/var/www_ts/rules/conf/Key.cfg"
#define DEV_CONF_TEST          "/var/www_ts/rules/conf/devconfig.cf"
#define IPAUTH_CONF_TEST       "/var/www_ts/rules/precfg/IPAUTHCONF"
#define AUTHUSERCONF_TEST      "/var/www_ts/rules/precfg/AUTHUSERCONF"
#define SYS_AUTH_DIR_TEST      "/var/www_ts/rules/auth/"
//#define SUPPORT_DPDK           0
#define IPTABLES               "/initrd/abin/iptables"
#define CONNTRACK              "/initrd/abin/conntrack"
#define AWK_PATH               "/initrd/abin/awk"
#else
//do nothing
#endif

#endif /*_GAP_CONFIG_H_*/
