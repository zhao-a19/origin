/*******************************************************************************************
*文件:  FCSysStatus.cpp
*描述:  系统状态采集
*作者:  王君雷
*日期:  2014
*
*修改:
*       insert SYSSTEM_STATUS失败后，动执行一次repair                     ------> 2017-08-07
*       每间隔一段时间，执行一次drop_caches，释放内存碎片空间             ------> 2017-11-02
*       不在间隔段时间drop_caches，计算内存占用时cache和buffers按空闲计算 ------> 2017-11-08
*       重新设计并发数、通道状态判断方法(按采集周期内内部卡接收包数判断)  ------> 2017-11-20
*       并发数统计，使用slabinfo和ip_conntrack结合的折中方法              ------> 2018-01-15
*       线程ID使用pthread_t类型                                           ------> 2018-08-07
*       网卡吞吐量采集使用uint64类型，修改32位系统收发字节数超4G自动归零吞吐量计算错误
*       的BUG                                                             ------> 2018-09-27
*       从slabinfo中读取并发数时，兼容grep过滤后有1行 或 2行内容的情况    ------> 2019-01-24
*       获取系统状态线程移动到recvmain                                    ------> 2019-11-19-dzj
*       统计并发数时使用nf_conntrack代替ip_conntrack，解决IPV6遗漏问题    ------> 2020-03-11 wjl
*       统计并发数使用文件用宏代替，兼容arm64系统文件路径不同的问题         ------> 2020-05-15
*       把GetNetICValue函数移出本文件，放入单独文件中                     ------> 2020-06-22
*       当全局syslog日志开关变化时，重新读取开关配置                       ------> 2020-07-06
*       可以设置线程名称                                                 ------> 2021-02-23
*       改用全局结构体变量获取CPU使用率，解决采集周期过短问题               ------> 2021-08-02
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/sockios.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "FCSysStatus.h"
#include "quote_global.h"
#include "FCLogManage.h"
#include "const.h"
#include "define.h"
#include "simple.h"
#include "debugout.h"
#include "nic.h"

TNETFLOW g_netprev = {0};
CPU_INFO g_cpu_info_prev = {0};
extern bool g_slogchange;

/**
 * [get_disk_info 获取硬盘使用率]
 * @return [失败返回负值]
 */
float get_disk_info()
{
    struct statfs diskInfo;
    long long totalsize;
    long long freeDisk;
    float percent = 0;

    if (statfs("/initrd/", &diskInfo) != 0) {
        PRINT_ERR_HEAD
        print_err("statfs fail[%s]", strerror(errno));
        return -1;
    }
    totalsize = (long long)diskInfo.f_blocks * (long long)diskInfo.f_bsize / 1024 / 1024; //MB
    freeDisk = (long long)diskInfo.f_bfree * (long long)diskInfo.f_bsize / 1024 / 1024; //MB
    percent = (float)(totalsize - freeDisk) / (float)totalsize;
    return percent;
}

/**
 * [mem_usage 获取内存使用率]
 * @return [失败返回负值]
 */
float mem_usage(void)
{
    char buff[1024] = {0};
    long long int memtotal = 0;
    long long int memfree = 0;
    long long int buffers = 0;
    long long int cached = 0;

    FILE *fp = fopen(MEM_INFO_FILE, "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen fail[%s:%s]", MEM_INFO_FILE, strerror(errno));
        return -1;
    }

    //MemTotal:
    if (fgets(buff, sizeof(buff), fp) == NULL) {
        PRINT_ERR_HEAD
        print_err("fgets return null");
        goto ERR;
    }
    sscanf(buff, "MemTotal: %lld", &memtotal);
    if (memtotal <= 0) {
        PRINT_ERR_HEAD
        print_err("memtotal error[%lld]", memtotal);
        goto ERR;
    }

    //MemFree:
    BZERO(buff);
    if (fgets(buff, sizeof(buff), fp) == NULL) {
        PRINT_ERR_HEAD
        print_err("fgets return null");
        goto ERR;
    }
    sscanf(buff, "MemFree: %lld", &memfree);
    if (free < 0) {
        PRINT_ERR_HEAD
        print_err("memfree error[%lld]", memfree);
        goto ERR;
    }

    //Buffers:
    BZERO(buff);
    if (fgets(buff, sizeof(buff), fp) == NULL) {
        PRINT_ERR_HEAD
        print_err("fgets return null");
        goto ERR;
    }
    sscanf(buff, "Buffers: %lld", &buffers);
    if (buffers < 0) {
        PRINT_ERR_HEAD
        print_err("buffers error[%lld]", buffers);
        goto ERR;
    }

    //Cached:
    BZERO(buff);
    if (fgets(buff, sizeof(buff), fp) == NULL) {
        PRINT_ERR_HEAD
        print_err("fgets return null");
        goto ERR;
    }
    sscanf(buff, "Cached: %lld", &cached);
    if (cached < 0) {
        PRINT_ERR_HEAD
        print_err("cached error[%lld]", cached);
        goto ERR;
    }
    fclose(fp);

    if ((memfree + buffers + cached) > memtotal) {
        PRINT_ERR_HEAD
        print_err("Warn! %lld > %lld", memfree + buffers + cached, memtotal);
        return 0.0;
    }

    return (1.0 - (memfree + buffers + cached ) * 1.0 / memtotal);

ERR:
    fclose(fp);
    return 0.0;
}

/**
 * [get_mem_info 获取内存使用率]
 * @return  [失败返回负值]
 */
float get_mem_info(void)
{
#if 0
    long num_pages = sysconf(_SC_PHYS_PAGES);
    long free_pages = sysconf(_SC_AVPHYS_PAGES);
    float mem_per = (num_pages - free_pages) * 1.0 / num_pages;
    return mem_per;
#else
    return mem_usage();
#endif
}

/**
 * [get_cpu_info 获取CPU使用率]
 * @return  [失败返回负值]
 */
float get_cpu_info(void)
{
    CPU_INFO cpu_info;
    char cpu[21] = {0};
    char text[201] = {0};

    //打开文件
    FILE *fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen error[/proc/stat:%s]", strerror(errno));
        return -1;
    }

    //读出CPU使用信息
    while (fgets(text, 200, fp) != NULL) {
        if (strstr(text, "cpu") != NULL) {
            sscanf(text, "%s %f %f %f %f",
                   cpu, &cpu_info.user, &cpu_info.nice, &cpu_info.system, &cpu_info.idle);
            break;
        }
        BZERO(text);
    }
    cpu_info.total = (cpu_info.user + cpu_info.nice + cpu_info.system + cpu_info.idle);

    //关闭文件
    fclose(fp);

    //读取间隔太短，cpu信息还没有变化,则返回上次调用时的使用率
    if ((cpu_info.total - g_cpu_info_prev.total) < 0.000001) {
        PRINT_INFO_HEAD
        print_info("cycle too short.total[%f] prevtotal[%f]", cpu_info.total, g_cpu_info_prev.total);
        return g_cpu_info_prev.cpu_usage;
    }

    //计算CPU使用率
    cpu_info.cpu_usage = ((cpu_info.user - g_cpu_info_prev.user) +
                          (cpu_info.nice - g_cpu_info_prev.nice) +
                          (cpu_info.system - g_cpu_info_prev.system) ) /
                         (cpu_info.total - g_cpu_info_prev.total);

    //避免出现大于100%的情况发生
    if (cpu_info.cpu_usage > 1.0) {
        PRINT_ERR_HEAD
        print_err("warn cpu usage:%f", cpu_info.cpu_usage);
        cpu_info.cpu_usage = 1.0;
    }

    //把本次读出的信息存到static变量中，下次计算时使用
    memcpy(&g_cpu_info_prev, &cpu_info, sizeof(CPU_INFO));
    return cpu_info.cpu_usage;
}

/**
 * [link_count_conntrack 获取并发连接数]
 * @return [失败返回负值]
 */
int link_count_conntrack(void)
{
    char line[1024] = {0};
    char chcmd[1024] = {0};

    sprintf(chcmd, "cat %s |grep ESTABLISHED|wc -l", NET_CONNTRACK_FILE);
    FILE *fp = popen(chcmd, "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("popen error[%s][%s]", chcmd, strerror(errno));
        return -1;
    }
    fgets(line, sizeof(line), fp);
    pclose(fp);
    return atoi(line);
}

/**
 * [link_count_slabinfo 通过slabinfo文件获取并发连接数]
 * @return  [失败返回负值]
 */
int link_count_slabinfo(void)
{
    char line[1024] = {0};
    char chnum[100] = {0};
    int num = 0;

    FILE *fp = popen("cat /proc/slabinfo |grep nf_conntrack", "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("popen error[%s]", strerror(errno));
        return -1;
    }
    if (fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%*s%s", chnum);
        num = MAX(num, atoi(chnum));
    }
    if (fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%*s%s", chnum);
        num = MAX(num, atoi(chnum));
    }
    pclose(fp);
    return num;
}

/**
 * [get_link_count 获取并发连接数]
 * 先通过slabinfo统计并发数，如果统计结果大于1024，就使用该结果
 * 如果统计结果小于等于1024，则再通过conntrack文件去统计
 * slabinfo的结果不太准确，并发数多时conntrack统计太慢，所以采用了该折中方法
 * @return [失败返回负值]
 */
int get_link_count(void)
{
    int cnt = link_count_slabinfo();
    return ((cnt > 1024) ? cnt : link_count_conntrack());
}

/**
 * [get_netflow 获取系统吞吐量 按内联卡来计算的]
 * @return [失败返回负值]
 */
uint64 get_netflow()
{
#define NUM_4GB (1024 * 1024 * 1024 *4LL)

    SNDEVINFO devinfo;
    time_t now = time(NULL);
    uint64 flow = 0;
    uint64 flowbps = 0;
    int interval = 0;

    char ethname[10] = {0};
    sprintf(ethname, "eth%d", g_linklan);
    if (GetNetICValue(ethname, &devinfo) < 0) {
        return -1;
    }

    //采集间隔太短时就返回上次的结果
    interval = now - g_netprev.prevtm;
    if (interval <= 0) {
        g_netprev.prevtm = now;
        PRINT_INFO_HEAD
        print_info("cycle[%d] too short,return last value[%llu]", interval, g_netprev.prevbps);
        return g_netprev.prevbps;
    }

    if (devinfo.sbyte < g_netprev.prevsbyte) {
        if (sizeof(int *) == 4) {
            //对于32位的系统
            flow += NUM_4GB - g_netprev.prevsbyte + devinfo.sbyte;
        } else {
            //对于64位以上的系统
            flow += devinfo.sbyte;
        }
    } else {
        flow += devinfo.sbyte - g_netprev.prevsbyte;
    }
    if (devinfo.rbyte < g_netprev.prevrbyte) {
        if (sizeof(int *) == 4) {
            //对于32位的系统
            flow += NUM_4GB - g_netprev.prevrbyte + devinfo.rbyte;
        } else {
            //对于64位以上的系统
            flow += devinfo.rbyte;
        }
    } else {
        flow += devinfo.rbyte - g_netprev.prevrbyte;
    }
    flowbps = flow / interval * 8;
#if 0
    PRINT_DBG_HEAD
    print_dbg("interval:%d, rbyte:%-10llu, sbyte:%-10llu, flow:%-10lluB, flowbps:%-10llu",
              interval, devinfo.rbyte, devinfo.sbyte, flow, flowbps);
#endif
    g_netprev.prevsbyte = devinfo.sbyte;
    g_netprev.prevrbyte = devinfo.rbyte;
    g_netprev.prevbps = flowbps;
    g_netprev.prevtm = now;
    return flowbps;
}

/**
 * [get_system_status 系统状态信息采集 线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *get_system_status(void *arg)
{
    pthread_setself("systemstatus");
    char chdisk[16] = {0};
    char chmem[16] = {0};
    char chcpu[16] = {0};
    char chsyslog[1024] = {0};
    char chdesc[256] = {0};
    uint64 lastrbyte = 0;         //上个采集周期后 内联卡的收包字节数
    int cnt = 0;                  //采集次数计数
    bool btotal_status_ok = true; //设备整体状态是否ok
    bool bsecway_status_ok = true;//隔离通道状态是否ok

    PRINT_DBG_HEAD
    print_dbg("get system status begin");

    CLOGMANAGE logman;
    while (logman.Init() != E_OK) {
        PRINT_ERR_HEAD
        print_err("get system status log init retry");
        sleep(1);
    }

    while (1) {
        if (g_slogchange) {
            g_slogchange = false;
            logman.SlogReload();
        }

        BZERO(chdesc);
        btotal_status_ok = true;
        PRINT_DBG_HEAD
        print_dbg("get system status again");
        //CPU
        float cpuuse = get_cpu_info();
        sprintf(chcpu, "%f", cpuuse * 100);
        if ((cpuuse < 0) || (cpuuse > 0.9)) {
            btotal_status_ok = false;
            strcat(chdesc, "CPU warn!");
        }

        //磁盘
        float diskuse = get_disk_info();
        sprintf(chdisk, "%f", diskuse * 100);
        if ((diskuse < 0) || (diskuse > 0.9)) {
            btotal_status_ok = false;
            strcat(chdesc, "DISK warn!");
        }

        //内存
        float memuse = get_mem_info();
        sprintf(chmem, "%f", memuse * 100);
        if (memuse > 0.9) {
            btotal_status_ok = false;
            strcat(chdesc, "MEM warn!");
        }

        //用户并发数
        int usernum = get_link_count();
        if (usernum < 0) {
            btotal_status_ok = false;
            strcat(chdesc, "Link count warn!");
        }

        //吞吐量
        uint64 flowbps = get_netflow();

        //隔离通道
        if (lastrbyte == g_netprev.prevrbyte) {
            btotal_status_ok = false;
            strcat(chdesc, "secway warn");
            bsecway_status_ok = false;
        } else {
            bsecway_status_ok = true;
        }
        lastrbyte = g_netprev.prevrbyte;

        //写系统状态日志
        if (logman.WriteSysStatusLog(usernum, chcpu, chdisk, chmem, bsecway_status_ok ? "1" : "0",
                                     flowbps, btotal_status_ok ? '0' : '1', chdesc) != E_OK) {
            PRINT_ERR_HEAD
            print_err("write log err, reconnect");
            logman.DisConnect();
            logman.Init();

            if (logman.WriteToDB("repair table SYSTEM_STATUS") == E_OK) {
                PRINT_INFO_HEAD
                print_info("repair table success");
            } else {
                PRINT_ERR_HEAD
                print_err("repair table fail");
            }
            logman.DisConnect();
            logman.Init();
        }

        //每循环采集60次 记一次系统日志
        if ((cnt++) % 60 == 0) {
            snprintf(chsyslog, sizeof(chsyslog), SYSTEM_STATUS_SUMMARY, usernum, chcpu, chdisk,
                     chmem, bsecway_status_ok ? SECWAY_NORMAL : SECWAY_ABNORMAL, flowbps);

            if (logman.WriteSysLog(LOG_TYPE_SYS_STATUS, D_SUCCESS, chsyslog) != E_OK) {
                logman.DisConnect();
                logman.Init();
            }
        }

        //缩短网卡吞吐量的采集周期 防止/proc/net/dev网卡统计字节数归零次数不确定的问题
        for (int i = 0; i < GET_SYS_STATUS_CYCLE / 2 - 1; i++) {
            sleep(2);
            get_netflow();
        }
        sleep(2);
    }

    logman.DisConnect();
    PRINT_ERR_HEAD
    print_err("get system status over");

    return NULL;
}

/**
 * [StartGetSysStatus 启动系统状态采集线程]
 * @return [启动成功返回0   否则返回负值]
 */
int StartGetSysStatus(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, get_system_status, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create get status thread fail");
        return -1;
    }
    return 0;
}
