/*******************************************************************************************
*文件:  FCKey.cpp
*描述:  key操作相关类
*作者:  王君雷
*日期:  2016-04-15
*修改:
*       绑定的网卡改用内部通信卡                                       ------> 2016-04-27
*       使用zlog;把获取硬件信息相关函数移动到其他文件里                ------> 2018-09-09
*       把生成随机字符、计算字符串md5等移到公共工具中，他处也可使用    ------> 2018-09-19
*******************************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/hdreg.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <errno.h>

#include "FCKey.h"
#include "FCMD5.h"
#include "hardinfo.h"
#include "debugout.h"
#include "define.h"
#include "common.h"

KEY::KEY(const char *keyfile, int ethno)
{
    BZERO(m_keyfile);
    BZERO(m_md5val);
    strcpy(m_keyfile, keyfile);
    m_ethno = ethno;
}

KEY::~KEY(void)
{
}

/**
 * [KEY::file_exist 判断文件是否存在]
 * @param  file [文件]
 * @return      [存在返回true]
 */
bool KEY::file_exist(const char *file)
{
    if ((file == NULL) || (strlen(file) == 0)) {
        PRINT_ERR_HEAD
        print_err("para err[%s]", file);
        return false;
    }

    struct stat buf;
    if (stat(file, &buf) < 0) {
        return false;
    }

    if (S_ISREG(buf.st_mode)) {
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("not reg file[%s]", file);
        return false;
    }
}

/**
 * [KEY::build_key 使用需要绑定的硬件信息，生成md5并写入key文件]
 * @return [成功返回true]
 */
bool KEY::build_key()
{
    CCommon common;
    char chcmd[2048] = {0};
    char randstr[1025] = {0};

    if (calc_md5(m_md5val) && common.RandomHexChar(randstr, 1024)) {
        memcpy(randstr + 100, m_md5val, 32);
        sprintf(chcmd, "echo %s > %s", randstr, m_keyfile);
        system(chcmd);
        system("sync");

        PRINT_DBG_HEAD
        print_dbg("build key ok");
        return true;
    }

    return false;
}

/**
 * [KEY::md5 对字符串md5加密]
 * @param  ch    [待加密的字符串]
 * @param  chlen [待加密的字符串长度]
 * @param  chout [输出参数]
 * @return       [成功返回true]
 */
bool KEY::md5(const char *ch, int chlen, char *chout)
{
    if ((ch == NULL) || (chlen < 0) || (chout == NULL)) {
        PRINT_ERR_HEAD
        print_err("para error[%s][%d][%s]", ch, chlen, chout);
        return false;
    }

    return md5sum_buff(ch, chlen, NULL, (unsigned char *)chout);
}

/**
 * [KEY::md5_ck 计算ch的md5值，存放到chout，并比较chout跟chin是否相同]
 * @param  ch    [待加密的字符串]
 * @param  chlen [待加密字符串的长度]
 * @param  chout [输出参数]
 * @param  chin  [输入参数]
 * @return       [相同返回true]
 */
bool KEY::md5_ck(const char *ch, int chlen, char *chout, const char *chin)
{
    if ((ch == NULL) || (chlen < 0) || (chout == NULL) || (chin == NULL)) {
        PRINT_ERR_HEAD
        print_err("para error[%s][%d]", ch, chlen);
        return false;
    }

    if (!md5(ch, chlen, chout)) {
        return false;
    }

    return (strcmp(chin, chout) == 0);
}

/**
 * [KEY::md5_ck 判断时间点tm按协议对应的md5串 是否跟输入的md5串相同]
 * @param  tm   [输入的时间点]
 * @param  chin [输入的md5串]
 * @return      [相同返回true]
 */
bool KEY::md5_ck(const time_t tm, const char *chin)
{
    if ((tm < 0) || (chin == NULL) || (strlen(chin) != 32)) {
        PRINT_ERR_HEAD
        print_err("para error[%ld][%s]", tm, chin);
        return false;
    }

    char chmd5[33] = {0};
    return (md5(tm, chmd5) && (strcmp(chin, (const char *)chmd5) == 0));
}

/**
 * [KEY::md5 根据时间点 返回MD5值]
 * @param  tm    [传入的时间点]
 * @param  chout [MD5值 出参]
 * @return       [成功返回true]
 */
bool KEY::md5(const time_t tm, char *chout)
{
    if ((tm < 0) || (chout == NULL)) {
        PRINT_ERR_HEAD
        print_err("para error[%ld][%s]", tm, chout);
        return false;
    }

    char chstr[40] = {0};

    //按协议组串
    sprintf(chstr, "SU+[%ld]+SU", tm);
    return md5(chstr, strlen(chstr), chout);
}

/**
 * [KEY::read_key 读取key文件中的md5 到缓冲区chout]
 * @param  chout [MD5 出参]
 * @return       [成功返回true]
 */
bool KEY::read_key(char *chout)
{
    FILE *fp = NULL;
    char readbuf[1025] = {0};

    //打开key
    fp = fopen(m_keyfile, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen error[%s][%s]", m_keyfile, strerror(errno));
        return false;
    }

    //读取key
    if (fread(readbuf, 1, 1024, fp) != 1024) {
        PRINT_ERR_HEAD
        print_err("fread error[%s][%s]", m_keyfile, strerror(errno));
        fclose(fp);
        return false;
    }

    //关闭
    fclose(fp);
    memcpy(chout, readbuf + 100, 32);
    return true;
}

/**
 * [KEY::calc_md5 计算当前设备对应的md5 并保存到chout]
 * @param  chout [出参 存放md5值]
 * @return       [成功返回true]
 */
bool KEY::calc_md5(char *chout)
{
    char chmac[MAC_STR_LEN] = {0};
    char chdiskid[64] = {0};
    char chstr[512] = {0};//待加密的字符串

    if (get_mac(m_ethno, chmac) && get_diskid(chdiskid)) {
        sprintf(chstr, "AM[%s]+[%s]AM", chmac, chdiskid);
        return md5(chstr, strlen(chstr), chout);
    }
    return false;
}

