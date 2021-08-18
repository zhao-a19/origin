/*******************************************************************************************
*文件:  stop_process.h
*描述:  停止业务相关宏定义
*
*作者:  王君雷
*日期:  2019-06-25
*修改:
*       停止内网业务时，添加停止dbsync_tool                          ------> 2020-08-17
*******************************************************************************************/
#ifndef __STOP_PROCESS_H__
#define __STOP_PROCESS_H__

//重启业务时需要清理的进程
#define STOP_IN_BUSINESS   "killall dbsync_tool hotbakmain sys6_test autobak DiskMonitor sys6 msync fileclient dbsync webproxy snmpd sul2fwd gapsip ausvr nginx>/dev/null 2>&1 "
#define STOP_OUT_BUSINESS  "killall sys6_w webproxy snmpd sul2fwd nginx >/dev/null 2>&1 "

//hotbakmain启停业务时 需要清理的进程
#define STOP_IN_BUSINESS_WITHOUT_HOTB "killall sys6_test autobak msync fileclient dbsync webproxy snmpd sul2fwd gapsip sys6>/dev/null 2>&1 "

//授权到期时 需要清理的进程
#define STOP_IN_BUSINESS_LICENSE_CK   "killall autobak msync fileclient dbsync webproxy snmpd sul2fwd gapsip nginx sys6 >/dev/null 2>&1 "
#define STOP_OUT_BUSINESS_LICENSE_CK  "killall sys6_w webproxy snmpd sul2fwd gapsip nginx"

//sys6的守护进程重新拉起时 清理使用
#define STOP_BUSINESS_SYS6            "killall msync fileclient dbsync webproxy snmpd sul2fwd gapsip nginx"

#endif
