/*******************************************************************************************
*文件:  FCIptablesLog.cpp
*描述:  iptables日志处理模块。把kmsg文件中的记录，整理写入到数据库
*作者:  王君雷
*日期:  2015
*
*修改:
*       支持记录内容过滤日志                                            ------> 2017-10-25
*       修改strchr等系统函数返回值类型错误;引入zlog记录日志             ------> 2018-04-09
*       IPV6的IP转为缩写格式                                            ------> 2019-02-18
*       访问日志支持记录MAC字段信息，暂置为空                           ------> 2020-01-16
*       解决日志记录内联IP的BUG                                        ------> 2021-03-04
*******************************************************************************************/
//kmsg文件记录示例：
//<7>CALLLOG_NULL_TCP IN=eth0 OUT= MAC=00:e0:4c:2f:43:49:50:7b:9d:c6:fd:59:08:00
//   SRC=192.168.1.135 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=128 ID=30067
//   DF PROTO=TCP SPT=57116 DPT=21 WINDOW=8192 RES=0x00 SYN URGP=0
//
//<7>LINKLOG_NULL_TCP IN=eth0 OUT= MAC=00:e0:4c:2f:43:49:50:7b:9d:c6:fd:59:08:00
//   SRC=192.168.1.135 DST=192.168.1.10 LEN=56 TOS=0x00 PREC=0x00 TTL=128 ID=30750
//   DF PROTO=TCP SPT=57167 DPT=21 WINDOW=8192 RES=0x00 SYN URGP=0
//
//<7>FILTERLOG_1_0E IN=eth0 OUT=eth5 SRC=192.168.1.135 DST=1.0.0.101 LEN=81
//   TOS=0x00 PREC=0x00 TTL=127 ID=2979 DF PROTO=TCP SPT=61699 DPT=49330 WINDOW=16652
//   RES=0x00 ACK PSH FIN URGP=0
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "FCIptablesLog.h"
#include "const.h"
#include "FCLogManage.h"
#include "simple.h"
#include "debugout.h"
#include "stringex.h"
#include "quote_global.h"

extern vector<string> g_vec_FilterKey;
#define CALLLOG_HEAD "CALLLOG_"
#define LINKLOG_HEAD "LINKLOG_"
#define FILTERLOG_HEAD "FILTERLOG_"

/**
 * [GetValueByKey 从一行内容中提取某项的值]
 * @param linebuf [被查找的一行内容]
 * @param key     [要查找的项]
 * @param obuf    [输出缓冲区，存放查到的值]
 * @param bufflen [输出缓冲区长度]
 * 例如：
 * linebuf为：
 * <7>CALLLOG_NULL_TCP IN=eth0 OUT= MAC=00:e0:4c:2f:43:49:50:7b:9d:c6:fd:59:08:00
 *   SRC=192.168.1.135 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=128 ID=30067
 *   DF PROTO=TCP SPT=57116 DPT=21 WINDOW=8192 RES=0x00 SYN URGP=0
 * key为：DST=
 * 则调用后obuf为：192.168.1.10
 */
void GetValueByKey(const char *linebuf, const char *key, char *obuf, int bufflen)
{
    if ((linebuf != NULL) && (key != NULL) && (obuf != NULL) && (bufflen > 0)) {
        int keylen = strlen(key);

        const char *p1 = strstr(linebuf, key);
        if (p1 != NULL) {
            const char *p2 = strchr(p1, ' ');
            if (p2 != NULL) {
                int vallen = p2 - (p1 + keylen);
                memcpy(obuf, p1 + keylen, vallen < (bufflen - 1) ? vallen : (bufflen - 1));
            }
        }
    }
}

/**
 * [convert2bs 如果是内部跳转IP 则替换为对应的业务IP]
 * @param ip [既是入参 又是出参]
 */
void convert2bs(char *ip)
{
    if ((WORK_MODE_TRANSPARENT != g_workflag) && (ip != NULL) && (strlen(ip) > 0)) {
        map<string, string>::iterator iter = g_bsipmap.find(ip);
        if (iter != g_bsipmap.end()) {
            strcpy(ip, iter->second.c_str());
        }
    }
}

/**
 * [RecordIptablesLogFun 把iptables LOG解析后存入数据库线程函数]
 * @param  arg [未使用]
 * @return     [无特殊含义]
 */
void *RecordIptablesLogFun(void *arg)
{
    pthread_setself("iptableslog");

    char linebuf[1024];
    char *pcall = NULL;
    char *plink = NULL;
    char *pfilter = NULL;

    char srcip[IP_STR_LEN];
    char dstip[IP_STR_LEN];
    char srcport[PORT_STR_LEN];
    char dstport[PORT_STR_LEN];
    char appmodel[APP_MODEL_LEN];
    char opuser[AUTH_NAME_LEN];
    char remark[32];
    const char *kmsg = "/proc/kmsg";
    FILE *fp = NULL;
    CLOGMANAGE mlog;

    while ((fp = fopen(kmsg, "w+")) == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen[%s] fail(%s)...retry", kmsg, strerror(errno));
        sleep(5);
    }

    while (mlog.Init() != E_OK) {
        PRINT_ERR_HEAD
        print_err("mlog.Init ... retry");
        sleep(5);
    }

    while (1) {
        pcall = NULL;
        plink = NULL;
        pfilter = NULL;
        BZERO(srcip);
        BZERO(dstip);
        BZERO(srcport);
        BZERO(dstport);
        BZERO(appmodel);
        BZERO(opuser);
        BZERO(remark);
        BZERO(linebuf);

        if (fgets(linebuf, sizeof(linebuf), fp) == NULL) {
            if (feof(fp)) {
                usleep(10000);
            } else {
                PRINT_ERR_HEAD
                print_err("fgets error[%s]", strerror(errno));
            }
            continue;
        }

        //处理一行
        pcall = strstr(linebuf, CALLLOG_HEAD);
        plink = strstr(linebuf, LINKLOG_HEAD);
        pfilter = strstr(linebuf, FILTERLOG_HEAD);
        GetValueByKey(linebuf, "SRC=", srcip, sizeof(srcip));
        GetValueByKey(linebuf, "DST=", dstip, sizeof(dstip));
        GetValueByKey(linebuf, "SPT=", srcport, sizeof(srcport));
        GetValueByKey(linebuf, "DPT=", dstport, sizeof(dstport));
        str2ip6_short(srcip);
        str2ip6_short(dstip);
        convert2bs(dstip);

        if (pcall) {
            GetValueByKey(linebuf, CALLLOG_HEAD, appmodel, sizeof(appmodel));
            //GetAuthName(srcip, opuser, sizeof(opuser));
            PRINT_DBG_HEAD
            print_dbg("APPMODEL=%s SRCIP=%s DSTIP=%s SPORT=%s DPORT=%s OPUSER=%s",
                      appmodel, srcip, dstip, srcport, dstport, opuser);

            if (strstr(linebuf, "SYN") != NULL) {
                strcpy(remark, "SYN");
            }
            mlog.WriteCallLog(opuser, srcip, dstip, srcport, dstport, "", "", appmodel, "", "", D_SUCCESS, remark);
        } else if (plink) {
            GetValueByKey(linebuf, LINKLOG_HEAD, appmodel, sizeof(appmodel));
            mlog.WriteLinkLog(srcip, dstip, srcport, dstport, appmodel, "", "");
        } else if (pfilter) {
            GetValueByKey(linebuf, FILTERLOG_HEAD, appmodel, sizeof(appmodel));
            //GetAuthName(srcip, opuser, sizeof(opuser));
            PRINT_DBG_HEAD
            print_dbg("appmodel[%s]", appmodel);

            //appmodel 如: 5_0D
            int vecno = atoi(appmodel);
            if ((vecno >= 0) && (vecno < (int)g_vec_FilterKey.size())) {
                const char *p = strchr(appmodel, '_');
                if (p == NULL) {
                    PRINT_ERR_HEAD
                    print_err("wrong format,appmodel[%s]", appmodel);
                    continue;
                }

                char encodebuf[10] = {0};
                sprintf(encodebuf, "%02X", encodekey(g_vec_FilterKey[vecno].c_str()));

                //PRINT_DBG_HEAD
                //print_dbg("iptables log encodebuf[%s]", encodebuf);

                if (memcmp(encodebuf, p + 1, 2) == 0) {
                    mlog.WriteFilterLog(opuser, g_vec_FilterKey[vecno].c_str(), KEY_WORD_FORBID, "", "", "", "", "");
                }
            } else {
                PRINT_ERR_HEAD
                print_err("vecno invalid[%d], g_vec_FilterKey.size()[%d]", vecno, (int)g_vec_FilterKey.size());
            }
        } else {
            //
        }
    }

    PRINT_ERR_HEAD
    print_err("iptables log thread will exit");
    fclose(fp);
    mlog.DisConnect();
    return NULL;
}

/**
 * [RecordIptablesLog 开启记录Iptables 日志的线程]
 * @return [成功返回true]
 */
bool RecordIptablesLog(void)
{
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, RecordIptablesLogFun, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create iptables log thread fail");
        return false;
    }
    return true;
}
