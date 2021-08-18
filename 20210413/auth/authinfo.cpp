/*******************************************************************************************
*文件: authinfo.cpp
*描述: 授权文件信息相关
*作者: 王君雷
*日期: 2018-09-18
*修改:
*      添加函数auth_tofile授权信息加密写入文件;界面导入的文件必须是没有运行过的文件
*                                                                         ------> 2018-09-21
*      移动头文件中不需要暴露出去的信息                                   ------> 2018-10-15
*      对于使用CST时区的系统 签发时间做偏移                               ------> 2019-01-17
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "authinfo.h"
#include "devinfo.h"
#include "common.h"
#include "debugout.h"
#include "FCMD5.h"
#include "hardinfo.h"
#include "au_define.h"

#define AUTH_HEADMARK "AU"
#define AUTH_VERSION1 1
#define AUTH_MAX_DAYS 365
#define AUTH_INFO_SUFFIX ".syscer"
#define AUTH_FILE_SIZE 2048
#define AUTH_INFO_KEY (0X65)
#define OFFSET_OF_AUTHINFO 13

bool get_effect_data(char *info, AUTH_HEAD &authhead, AUTH_BODY &authbody);
bool read_authfile(const char *syscerpath, char *info, int len);
bool check_totalmd5(const char *info);
bool check_authhead(AUTH_HEAD &authhead);
bool check_authbody(AUTH_BODY &authbody, const char *mancardname);
bool check_bodymd5(AUTH_BODY &authbody);
bool check_bindid(int day, int64 starttime, const char *mancardname, const unsigned char *bindid);
bool check_authday(int day);
bool check_maketime(int day, int64 maketime);

/**
 * [import_syscer 导入授权文件入口函数]
 * @param  mancardname[管理口名称]
 * @param  syscerpath [传入的授权文件路径]
 * @return            [成功返回true]
 */
bool import_syscer(const char *mancardname, const char *syscerpath)
{
    AUTH_HEAD authhead;
    AUTH_BODY authbody;
    AUTH_HEAD authheadcurr;
    AUTH_BODY authbodycurr;
    struct tm tmtmp;
    char chcmd[CMD_BUF_LEN] = {0};

    if ((syscerpath == NULL)
        || (syscerpath[0] != '/')
        || (strlen(syscerpath) <= strlen(AUTH_INFO_SUFFIX))
        || (mancardname == NULL)) {

        PRINT_ERR_HEAD
        print_err("sorry:para error[%s:%s]", mancardname, syscerpath);
        return false;
    }

    //扩展名检查
    if (strcmp(syscerpath + strlen(syscerpath) - strlen(AUTH_INFO_SUFFIX), AUTH_INFO_SUFFIX) != 0) {
        PRINT_ERR_HEAD
        print_err("sorry:suffix error[%s]", syscerpath);
        return false;
    }

    if (read_authinfo(syscerpath, authhead, authbody)
        && check_auth(authhead, authbody, mancardname)
        && check_maketime(authbody.authday, authbody.maketime)
        && (authbody.starttime == 0)
        && (authbody.stoptime == 0)
        && (authbody.lastupdate == 0)) {

        //读取当前授权文件
        if (read_authinfo(AUTH_FILE_PATH1, authheadcurr, authbodycurr)) {
            //检查授权文件ID是否重复
            if (strcmp(authbody.authid, authbodycurr.authid) == 0) {
                PRINT_ERR_HEAD
                print_err("sorry:auth[%s] has been used", authbody.authid);
                printf("already has been used\n");
                return false;
            }
        }

        //覆盖现有文件
        snprintf(chcmd, sizeof(chcmd), "cp -f %s %s", syscerpath, AUTH_FILE_PATH1);
        system(chcmd);
        snprintf(chcmd, sizeof(chcmd), "cp -f %s %s", AUTH_FILE_PATH1, AUTH_FILE_PATH2);
        system(chcmd);
        system("sync");

        time_t t1 = (time_t)authbody.maketime;
        localtime_r(&t1, &tmtmp);
        char str[50] = {0};
        strftime(str, 50, "%Y-%m-%d %H:%M:%S", &tmtmp);

        PRINT_INFO_HEAD
        print_info("import auth ok[file:%s,authid:%s,authday:%d,maketime:%s]",
                   syscerpath, authbody.authid, authbody.authday, str);
        return true;
    }

    return false;
}

/**
 * [read_authinfo 从文件中读取有效信息到结构体中]
 * @param  syscerpath [授权文件路径]
 * @param  authhead   [头部]
 * @param  authbody   [body结构体]
 * @return            [读取成功返回true]
 */
bool read_authinfo(const char *syscerpath, AUTH_HEAD &authhead, AUTH_BODY &authbody)
{
    char info1[AUTH_FILE_SIZE] = {0};
    if (read_authfile(syscerpath, info1, sizeof(info1))
        && get_effect_data(info1, authhead, authbody)) {
        PRINT_DBG_HEAD
        print_dbg("effect data[%s:%d:%s:%d]", authhead.head, authhead.version, authbody.authid,
                  authbody.authday);
        return true;
    }

    return false;
}

/**
 * [read_authfile 从授权文件中读取信息到缓冲区]
 * @param  syscerpath [授权文件路径]
 * @param  info       [授权信息缓冲区 出参]
 * @param  len        [授权信息长度 入参]
 * @return            [成功返回true]
 */
bool read_authfile(const char *syscerpath, char *info, int len)
{
    //读取文件
    FILE *fd = fopen(syscerpath, "rb");
    if (fd == NULL) {
        PRINT_ERR_HEAD
        print_err("sorry:open[%s] fail[%s]", syscerpath, strerror(errno));
        return false;
    }

    int rlen = fread(info, 1, len, fd);
    if (rlen != len) {
        PRINT_ERR_HEAD
        print_err("sorry:fread[%s] fail[%d:%s]", syscerpath, rlen, strerror(errno));
        fclose(fd);
        return false;
    }

    fclose(fd);
    return true;
}

/**
 * [get_effect_data 从输入信息中读取有效信息到结构体]
 * @param  info     [输入信息]
 * @param  authhead [头部]
 * @param  authbody [body结构体]
 * @return          [读取成功返回true]
 */
bool get_effect_data(char *info, AUTH_HEAD &authhead, AUTH_BODY &authbody)
{
    CCommon common;
    char info2[AUTH_FILE_SIZE] = {0};
    char info3[AUTH_FILE_SIZE] = {0};
    int len = sizeof(AUTH_HEAD) + sizeof(AUTH_BODY);

    //字符替换还原
    common.CharReplaceReduct(info, AUTH_FILE_SIZE);

    //检查整体的MD5
    if (check_totalmd5(info)) {
        //提取有效信息 到info2
        if (common.DispersedRetract(info2, len * 2, info, AUTH_FILE_SIZE - 32, OFFSET_OF_AUTHINFO) > 0) {
            //16进制浓缩
            if (common.HexToBin(info2, len * 2, info3, sizeof(info3)) > 0) {
                //异或
                common.XOR(info3, len, AUTH_INFO_KEY);
                memcpy(&authhead, info3, sizeof(authhead));
                memcpy(&authbody, info3 + sizeof(authhead), sizeof(authbody));
                return true;
            } else {
                PRINT_ERR_HEAD
                print_err("sorry:hex to bin fail");
            }
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:retract info fail");
        }
    }

    return false;
}

/**
 * 检查整体的md5
 * @param  info [待检查信息]
 * @return      [检查通过返回true]
 */
bool check_totalmd5(const char *info)
{
    unsigned char md5buff32[32] = {0};

    if (md5sum_buff(info, AUTH_FILE_SIZE -  32, NULL, md5buff32)) {
        if (memcmp(md5buff32, info + AUTH_FILE_SIZE - 32, 32) == 0) {
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:total md5 cheack fail");
        }
    } else {
        PRINT_ERR_HEAD
        print_err("sorry:get total md5 fail");
    }
    return false;
}

/**
 * [check_auth 检查授权基本信息]
 * @param  authhead    [头部]
 * @param  authbody    [body结构]
 * @param  mancardname [管理口名称]
 * @return             [检验通过返回true]
 */
bool check_auth(AUTH_HEAD &authhead, AUTH_BODY &authbody, const char *mancardname)
{
    return (check_authhead(authhead) && check_authbody(authbody, mancardname));
}

/**
 * [check_authhead 检查头部字段]
 * @param  authhead [头部]
 * @return          [检验通过返回true]
 */
bool check_authhead(AUTH_HEAD &authhead)
{
    if (strcmp(authhead.head, AUTH_HEADMARK) == 0) {
        if (authhead.version == AUTH_VERSION1) {
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:head version check fail[%d]", authhead.version);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("sorry:head mark check fail[%s]", authhead.head);
    }
    return false;
}

/**
 * [check_authbody 检查body字段]
 * @param  authbody [body结构]
 * @param  mancardname [管理口名称]
 * @return          [检查通过返回true]
 */
bool check_authbody(AUTH_BODY &authbody, const char *mancardname)
{
    return (check_bodymd5(authbody)
            && check_bindid(authbody.authday, authbody.starttime, mancardname, authbody.bindid)
            && check_authday(authbody.authday));
}

/**
 * [check_bodymd5 检查body部分的md5]
 * @param  authbody [body结构]
 * @return          [检查通过返回true]
 */
bool check_bodymd5(AUTH_BODY &authbody)
{
    unsigned char md5buff16[16] = {0};

    //计算body部分的md5
    if (md5sum_buff((const char *) &authbody, sizeof(authbody) - sizeof(authbody.md5buff16),
                    md5buff16, NULL)) {
        if (memcmp(md5buff16, authbody.md5buff16, 16) == 0) {
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:body md5 check fail");
        }

    } else {
        PRINT_ERR_HEAD
        print_err("sorry:md5sum body info fail");
    }
    return false;
}

/**
 * [check_bindid 检查是不是本机硬件绑定码]
 * @param  day       [授权天数]
 * @param  starttime [开始时间]
 * @param  mancardname [管理口名称]
 * @param  bindid    [硬件绑定码]
 * @return           [是则返回true]
 */
bool check_bindid(int day, int64 starttime, const char *mancardname, const unsigned char *bindid)
{
    unsigned char mybindid[16] = {0};

    //默认授权天数，并且是第一次运行，不检查硬件绑定码
    if ((day == AUTH_DEFAULT) && (starttime == 0)) {
        return true;
    }

    if (get_mybindid(mancardname, mybindid)) {
        if (memcmp(mybindid, bindid, 16) == 0) {
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:bindid check fail");
        }
    }
    return false;
}

/**
 * [check_authday 检查授权天数是否正确]
 * @param  day [授权天数]
 * @return     [授权天数合法返回true]
 */
bool check_authday(int day)
{
    PRINT_DBG_HEAD
    print_dbg("check day[%d]", day);

    if ((day == AUTH_FOREVER)
        || (day == AUTH_DEFAULT)
        || ((day > 0) && (day <= AUTH_MAX_DAYS))) {

        return true;
    }

    PRINT_ERR_HEAD
    print_err("sorry:day[%d] check fail", day);
    return false;
}

/**
 * [check_maketime 检查签发时间]
 * @param  day      [授权天数]
 * @param  maketime [签发时间]
 * @return          [签发时间校验通过返回true]
 */
bool check_maketime(int day, int64 maketime)
{
    if (day == AUTH_FOREVER) {
        return true;
    }

    if (day == AUTH_DEFAULT) {
        PRINT_ERR_HEAD
        print_err("sorry:default auth is not allowed to import");
        return false;
    }

    int64 tnow = time(NULL);
    int64 stoptime = CST_CALIBRATE(maketime) + day * SECONDS_PER_DAY;

    if (tnow > stoptime) {
        PRINT_ERR_HEAD
        print_err("sorry:maketime check fail.now[%lld],maketime[%lld],stoptime[%lld]",
                  tnow, CST_CALIBRATE(maketime), stoptime);
        printf("auth expired.\n");
        return false;
    }

    //如果设备时间比签发时间还要早 不准导入 提示错误
    if (tnow < CST_CALIBRATE(maketime)) {
        PRINT_ERR_HEAD
        print_err("maketime check fail.now[%lld],maketime[%lld],stoptime[%lld]",
                  tnow, CST_CALIBRATE(maketime), stoptime);
        printf("please be consistent in Beijing time.\n");
        return false;
    }

    return true;
}

/**
 * [get_mybindid 获取本机对应的硬件绑定码]
 * @param  mancardname [管理口名称]
 * @param  bindid [硬件绑定码 出参]
 * @return        [获取成功返回true]
 */
bool get_mybindid(const char *mancardname, unsigned char *bindid)
{
#pragma pack(push, 1)
//本结构不会直接出现在授权文件中 对本结构进行MD5摘要得到 16字节 的硬件绑定码
    typedef struct AUTH_BIND_V1 {
        char cpudesc[64];          //CPU描述
        unsigned char manmac[6];   //网卡MAC
        int cardnum;               //网卡数目
        int cardspeed;             //网卡速率
        char diskid[64];           //磁盘ID
        char mark[64];             //为增加破解难度，防止穷举组合得到MD5的计算方法，而引入该字段
    } AUTH_BIND_V1, *PAUTH_BIND_V1;
#pragma pack(pop)
#define AUTH_BIND_MARK_V1 "AM100202043043040340056SU06040343501232456020185234535324032534"

    AUTH_BIND_V1 bind1;
    memset(&bind1, 0, sizeof(bind1));

    //获取本机的硬件信息
    if (get_cpudesc(bind1.cpudesc)
        && get_mac(mancardname, NULL, bind1.manmac)
        && get_cardnum(bind1.cardnum)
        && get_cardspeed(bind1.cardnum, bind1.cardspeed)
        && get_diskid(bind1.diskid)) {

        strcpy(bind1.mark, AUTH_BIND_MARK_V1);

        //计算本机的硬件绑定码
        if (md5sum_buff((const char *)&bind1, sizeof(bind1), bindid, NULL)) {
            PRINT_DBG_HEAD
            print_dbg("bindid ok, bindinfo size[%d]", (int)sizeof(bind1));
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("sorry:md5sum fail while get my bind id");
        }
    }

    return false;
}

/**
 * [auth_tofile 对授权的有效信息进行加密 编码 并写入文件]
 * @param  head [头部]
 * @param  body [body]
 * @param  file [文件路径]
 * @return      [成功返回true]
 */
bool auth_tofile(AUTH_HEAD &head, AUTH_BODY &body, const char *file)
{
    char info1[AUTH_FILE_SIZE] = {0};
    char info2[AUTH_FILE_SIZE] = {0};
    char info3[AUTH_FILE_SIZE] = {0};
    int len = 0;
    int wlen = 0;
    CCommon common;

    //MD5摘要
    if (!md5sum_buff((const char *)&body, sizeof(body) - sizeof(body.md5buff16), body.md5buff16,
                     NULL)) {
        PRINT_ERR_HEAD
        print_err("sorry:md5sum body info fail");
        return false;
    }

    memcpy(info1, &head, sizeof(head));
    memcpy(info1 + sizeof(head), &body, sizeof(body));

    len = sizeof(head) + sizeof(body);

    //异或
    common.XOR(info1, len, AUTH_INFO_KEY);

    //16进制扩展
    if (common.BinToHex(info1, len, info2, sizeof(info2)) < 0) {
        PRINT_ERR_HEAD
        print_err("sorry:bin to hex fail");
        return false;
    }

    //生成随机字符
    if (!common.RandomHexChar(info3, sizeof(info3))) {
        PRINT_ERR_HEAD
        print_err("sorry:random hex char fail");
        return false;
    }

    //分散存储
    if (common.DispersedStore(info2, len * 2, info3, sizeof(info3) - 32, OFFSET_OF_AUTHINFO) < 0) {
        PRINT_ERR_HEAD
        print_err("sorry：dispersed storage fail");
        return false;
    }

    //把前2048-32个字节的md5 存到文件最后32B
    if (!md5sum_buff((const char *)info3, sizeof(info3) - 32, NULL,
                     (unsigned char *)(info3 + sizeof(info3) - 32))) {
        PRINT_ERR_HEAD
        print_err("sorry:total md5sum fail");
        return false;
    }

    //字符置换
    common.CharReplace(info3, sizeof(info3));

    //写入文件
    FILE *fd = fopen(file, "wb+");
    if (fd == NULL) {
        print_err("sorry:open[%s] error[%s]", file, strerror(errno));
        return false;
    }

    wlen = fwrite(info3, 1, sizeof(info3), fd);
    if (wlen != sizeof(info3)) {
        PRINT_ERR_HEAD
        print_err("sorry:fwrite error[%d:%s:%s]", wlen, file, strerror(errno));
        fclose(fd);
        return false;
    }

    fclose(fd);

    PRINT_DBG_HEAD
    print_dbg("auth to file ok");
    return true;
}

/**
 * [cst_seconds_offset 返回使用CST时区的系统 需要偏移的秒数]
 * @return  [秒数]
 */
int cst_seconds_offset(void)
{
    int sec = 0;
    CCommon common;
    char outinfo[128] = {0};

    if (common.Sysinfo("date", outinfo, sizeof(outinfo)) != NULL) {
        if (strstr(outinfo, "CST") != NULL) {
            sec -= 8 * 60 * 60;
            PRINT_DBG_HEAD
            print_dbg("system use cst timezone[%s]", outinfo);
        } else {
            PRINT_DBG_HEAD
            print_dbg("system not use cst timezone[%s]", outinfo);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("exec date command fail");
    }
    return sec;
}
