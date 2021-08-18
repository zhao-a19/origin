/*******************************************************************************************
*文件: devinfo.cpp
*描述: 收集设备硬件信息相关函数
*作者: 王君雷
*日期: 2018-09-18
*修改:
*      管理口信息通过命令行参数传进去，不用读取配置文件了               ------> 2018-09-28
*      移动头文件中不需要暴露出去的信息                                 ------> 2018-10-15
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include "common.h"
#include "hardinfo.h"
#include "debugout.h"
#include "FCMD5.h"
#include "devinfo.h"
#include "au_define.h"

#define HARDINFO_KEY        (0x7B)    //获取硬件信息时 异或加解密使用的字符
#define HEADINFO_MARK       "GAPDEV"  //头部 用于校验
#define HDINFO_VERSION      2         //协议版本号
#define DEVFILESIZE         2048      //设备信息文件大小
#define OFFSET_OF_DEVINFO   317       //设备信息分散存储时使用的偏移量

#pragma pack(push, 1)
typedef struct HARD_INFO_HEAD {
    char head[8];
    int version;
} HARD_INFO_HEAD, *PHARD_INFO_HEAD;

typedef struct HARD_INFO_BODY {
    int64 exporttime;           //导出时间
    char cpudesc[64];           //CPU描述
    int memsize;                //内存大小
    unsigned char manmac[6];    //管理口MAC
    int cardnum;                //网卡数目
    int cardspeed;              //网卡速率
    int disksize;               //磁盘总容量
    char diskid[64];            //磁盘ID
    unsigned char reserved[128];//保留字段
    unsigned char md5buff16[16];      //上述信息的MD5（包括HARD_INFO_HEAD结构）
} HARD_INFO_BODY, *PHARD_INFO_BODY;
#pragma pack(pop)

/**
 * [print_head_body 打印信息]
 * @param head [头部]
 * @param body [消息体]
 */
void print_head_body(HARD_INFO_HEAD &head, HARD_INFO_BODY &body)
{
    PRINT_INFO_HEAD
    print_info("head[%s],version[%d],cpudesc[%s],memsize[%d],manmac[%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x],"
               "cardnum[%d],cardspeed[%d],disksize[%d],diskid[%s]",
               head.head,
               head.version,
               body.cpudesc,
               body.memsize,
               body.manmac[0], body.manmac[1], body.manmac[2], body.manmac[3], body.manmac[4], body.manmac[5],
               body.cardnum,
               body.cardspeed,
               body.disksize,
               body.diskid);
}

/**
 * [get_info 获取硬件相关信息]
 * @param  mancardname [管理口网卡名称]
 * @param  filename    [获取到的信息存放到该文件中]
 * @return             [成功返回true]
 */
bool get_info(const char *mancardname, const char *filename)
{
    CCommon common;
    int len = 0;
    int wlen = 0;
    char info1[DEVFILESIZE] = {0};//存放加密前的信息
    char info2[DEVFILESIZE] = {0};//存放16进制扩展之后的信息
    char info3[DEVFILESIZE] = {0};//存放加密后的信息

    HARD_INFO_HEAD headinfo;
    HARD_INFO_BODY bodyinfo;
    BZERO(headinfo);
    BZERO(bodyinfo);

    strcpy(headinfo.head, HEADINFO_MARK);
    headinfo.version = HDINFO_VERSION;

    bodyinfo.exporttime = time(NULL);
    if (get_cpudesc(bodyinfo.cpudesc)
        && get_memsize(bodyinfo.memsize)
        && get_mac(mancardname, NULL, bodyinfo.manmac)
        && get_cardnum(bodyinfo.cardnum)
        && get_cardspeed(bodyinfo.cardnum, bodyinfo.cardspeed)
        && get_disksize(bodyinfo.disksize)
        && get_diskid(bodyinfo.diskid)) {

        memcpy(info1, &headinfo, sizeof(headinfo));
        memcpy(info1 + sizeof(headinfo), &bodyinfo, sizeof(bodyinfo));

        len = sizeof(headinfo) + sizeof(bodyinfo);

        print_head_body(headinfo, bodyinfo);

        if (!md5sum_buff((const char *)info1, len - sizeof(bodyinfo.md5buff16),
                         (unsigned char *)(info1 + len - sizeof(bodyinfo.md5buff16)), NULL)) {
            PRINT_ERR_HEAD
            print_err("md5sum fail");
            return false;
        }

        //异或
        common.XOR(info1, len, HARDINFO_KEY);

        //16进制扩展
        if (common.BinToHex(info1, len, info2, sizeof(info2)) < 0) {
            PRINT_ERR_HEAD
            print_err("bin to hex fail");
            return false;
        }

        //PRINT_DBG_HEAD
        //print_dbg("[%d:%s]", len, info2);

        //产生随机字符
        if (!common.RandomHexChar(info3, sizeof(info3))) {
            PRINT_ERR_HEAD
            print_err("random hex char fail");
            return false;
        }

        //分散存储
        if (common.DispersedStore(info2, len * 2, info3, sizeof(info3) - 32, OFFSET_OF_DEVINFO) < 0) {
            PRINT_ERR_HEAD
            print_err("dispaersed storage fail");
            return false;
        }

        //把前2048-32个字节的md5 存到文件最后32B
        if (!md5sum_buff((const char *)info3, sizeof(info3) - 32, NULL,
                         (unsigned char *)(info3 + sizeof(info3) - 32))) {
            PRINT_ERR_HEAD
            print_err("md5sum fail");
            return false;
        }

        //写入文件
        FILE *fd = fopen(filename, "wb+");
        if (fd == NULL) {
            PRINT_ERR_HEAD
            print_err("open[%s] error[%s]", filename, strerror(errno));
            return false;
        }

        wlen = fwrite(info3, 1, sizeof(info3), fd);
        if (wlen != sizeof(info3)) {
            PRINT_ERR_HEAD
            print_err("fwrite error[%d:%s:%s]", wlen, filename, strerror(errno));
            fclose(fd);
            return false;
        }

        fclose(fd);
        return true;
    }

    return false;
}
