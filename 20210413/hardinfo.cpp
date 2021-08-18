/*******************************************************************************************
*文件:  hardinfo.cpp
*描述:  硬件信息操作
*作者:  王君雷
*日期:  2018-09-09
*修改:
*       可以使用网卡号、网卡名获取网卡的mac                           ------> 2018-09-19
*       添加通过SCSI通用驱动器获取磁盘ID注释                          ------> 2018-09-29
*       获取网卡速率失败时按默认值1000处理                            ------> 2018-12-17
*       获取CPU描述、磁盘ID失败给默认值，解决ARM移植发现的问题          ------> 2020-02-12
*       ARM64系统获取磁盘ID时使用固定串                               ------> 2020-05-14
*       重新约定SUOS_V，arm64对应1000                                 ------> 2020-07-27
*       arm64平台，用cid当做磁盘ID使用                                 ------> 2021-02-02
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/hdreg.h>
#include <fcntl.h>
#include <scsi/sg.h>

#include "debugout.h"
#include "hardinfo.h"
#include "common.h"
#include "FCDelSpace.h"

#ifndef ANMIT_BOND_NO
#define ANMIT_BOND_NO         99 //负载均衡 约定网卡号
#endif
#ifndef BZERO
#define BZERO(ch) memset(&(ch), 0, sizeof(ch))
#endif

int get_diskid_sda_scsi_io(int fd, unsigned char *cdb, unsigned char cdb_size, int xfer_dir,
                           unsigned char *data, unsigned int *data_size,
                           unsigned char *sense, unsigned int *sense_len);

/**
 * [get_mac 获取网卡MAC]
 * @param  no     [网卡号]
 * @param  mac    [MAC 出参]
 * @param  binmac [二进制格式的mac 出参]
 * @return        [成功返回true]
 */
bool get_mac(int no, char *mac, unsigned char *binmac)
{
    char device[32] = {0};
    if (ANMIT_BOND_NO == no) {
        sprintf(device, "bond0");
    } else {
        sprintf(device, "eth%d", no);
    }

    return get_mac(device, mac, binmac);
}

/**
 * [get_mac 获取网卡MAC]
 * @param  device [网卡名称 如eth0]
 * @param  mac    [网卡MAC 出参]
 * @param  binmac [二进制格式的mac 出参]
 * @return        [成功返回true]
 */
bool get_mac(const char *device, char *mac, unsigned char *binmac)
{
    unsigned char macaddr[6];
    struct ifreq req;

    if ((device == NULL) || (strlen(device) >= sizeof(req.ifr_name))) {
        PRINT_ERR_HEAD
        print_err("device[%s] error", device);
        return false;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        PRINT_ERR_HEAD
        print_err("socket err[%s]", strerror(errno));
        return false;
    }
    strcpy(req.ifr_name, device);
    int ret = ioctl(s, SIOCGIFHWADDR, &req); //执行取MAC地址操作
    close(s);

    if (ret != -1) {
        memcpy(macaddr, req.ifr_hwaddr.sa_data, ETH_ALEN);
        if (mac != NULL) {
            sprintf(mac, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
                    macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
        }

        if (binmac != NULL) {
            memcpy(binmac, macaddr, 6);
        }
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("ioctl err[%s:%s]", device, strerror(errno));
        return false;
    }
}

/**
 * [get_diskid_cid 通过获取cid当做磁盘ID]
 * @param  diskid [磁盘ID 出参]
 * @return        [成功返回true]
 */
bool get_diskid_cid(char *diskid)
{
    bool flag = false;
    CCommon common;
    if (common.Sysinfo("cat /sys/block/mmcblk0/device/cid", diskid, 64) != NULL) {
        PRINT_INFO_HEAD
        print_info("diskid:%s", diskid);
        flag = true;
    } else {
        PRINT_ERR_HEAD
        print_err("get cid fail");
    }
    return flag;
}

/**
 * [get_diskid 获取磁盘的ID 先按sda方式获取，获取失败再按hda方式获取]
 * @param  diskid   [磁盘ID 出参]
 * @return        [成功返回true]
 */
#define DEFAULT_DISKID "mmcblk0"
bool get_diskid(char *diskid)
{
    if (diskid == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

#if (SUOS_V==1000)
    if (!get_diskid_cid(diskid)) {
        strcpy(diskid, DEFAULT_DISKID);
        PRINT_ERR_HEAD
        print_err("arm64 os,use default %s", diskid);
    }
    return true;
#endif

    if (get_diskid_sda(diskid) || get_diskid_hda(diskid)) {
    } else {
        strcpy(diskid, DEFAULT_DISKID);
        PRINT_ERR_HEAD
        print_err("get diskid fail,use default %s", diskid);
    }
    return true;
}

/**
 * [get_diskid_sda 获取磁盘的ID 按sda方式获取]
 * @param  diskid   [磁盘ID 出参]
 * @return        [成功返回true]
 */
bool get_diskid_sda(char *diskid)
{
    if (diskid == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    int fd = 0;
    int vers = 0;

    //参考:https://www.ibm.com/developerworks/cn/linux/l-scsi-api/
    //     http://blog.chinaunix.net/uid-12545990-id-202351.html
    //每个 SCSI 命令都由 Command Descriptor Block (CDB) 描述,它定义 SCSI 设备执行的操作
    unsigned char cdb[] = {0x12,//0x12 :Inquiry 请求目标设备的摘要信息
                           0x01,//EVPD，为 0 并且 Page Code 参数字节为 0，那么目标将返回标准 inquiry 数据
                           //为 1 那么目标将返回对应 page code 字段的特定于供应商的数据
                           0x80,//Page Code.Page Code 和 EVPD 字段皆设置为 0 的标准响应很复杂。
                           //根据标准，供应商 ID 从第 8 字节扩展到第 15 字节，产品 ID 从第 16 字节扩展到第 31 字节，
                           //产品版本从第 32 字节扩展到第 35 字节。必须获取这些信息，以检查命令是否成功执行。
                           0,
                           0,
                           0
                          };
    unsigned int data_size = 0x00ff;
    unsigned char data[data_size];
    unsigned int sense_len = 32;
    unsigned char sense[sense_len];
    cdb[3] = (data_size >> 8) & 0xff;
    cdb[4] = data_size & 0xff;

    if ((fd = open("/dev/sda", O_RDWR)) < 0) {
        PRINT_ERR_HEAD
        print_err("open /dev/sda fail[%s]", strerror(errno));
        return false;
    }

    //
    //Sg驱动版本号：早期的sg驱动或者没有版本号，或者以2开头，现在的sg驱动版本号以3为主版本号
    //格式为“x.y.z”，通过ioctl()得到的数值是x*10000+y*100+z，还可以从cat/proc/scsi/sg/version获得
    //cat /proc/scsi/sg/version
    //30534   3.5.34 [20061027]
    //
    if ((ioctl(fd, SG_GET_VERSION_NUM, &vers) < 0) || (vers < 30000)) {
        PRINT_ERR_HEAD
        print_err("/dev/sda is not an sg device, or old sg driver[%d]", vers);
        close(fd);
        return false;
    }

    //SG_DXFER_FROM_DEV 从设备输出数据,使用 SCSI READ 命令。
    if (get_diskid_sda_scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense,
                               &sense_len) < 0) {
        close(fd);
        return false;
    }

    //Page Length
    int pl = data[3];
    int cnt = 0;
    for (int i = 4; i < (pl + 4); i++) {
        diskid[cnt++] = data[i] & 0xff;
    }

    close(fd);

    PRINT_INFO_HEAD
    print_info("diskid[%s]", diskid);
    return true;
}

/**
 * [get_diskid_sda_scsi_io 通过SCSI通用驱动器获取磁盘ID]
 * @param  fd        [描述符]
 * @param  cdb       [指向将要执行的SCSI命令的指针]
 * @param  cdb_size  [SCSI命令的字节长度]
 * @param  xfer_dir  [用于确定数据传输的方向]
 * @param  data      [指向数据传输时的用户内存的指针]
 * @param  data_size [数据传输的用户内存的长度]
 * @param  sense     [缓冲检测指针 出错信息会返回到这里]
 * @param  sense_len [当sense为输出时，可以写回到sense的最大大小]
 * @return           [成功返回0]
 */
#define SCSI_TIMEOUT 5000 //ms
int get_diskid_sda_scsi_io(int fd, unsigned char *cdb, unsigned char cdb_size, int xfer_dir,
                           unsigned char *data, unsigned int *data_size,
                           unsigned char *sense, unsigned int *sense_len)
{
    sg_io_hdr_t io_hdr;
    BZERO(io_hdr);

    //要求设置为S
    io_hdr.interface_id = 'S';

    //CDB
    io_hdr.cmdp = cdb;
    io_hdr.cmd_len = cdb_size;

    //Where to store the sense_data, if there was an error
    io_hdr.sbp = sense;
    io_hdr.mx_sb_len = *sense_len;
    *sense_len = 0;

    //Transfer direction, either in or out. Linux does not yet support bidirectional SCSI transfers?
    io_hdr.dxfer_direction = xfer_dir;

    //Where to store the DATA IN/OUT from the device and how big the buffer is
    io_hdr.dxferp = data;
    io_hdr.dxfer_len = *data_size;

    //SCSI timeout in ms
    io_hdr.timeout = SCSI_TIMEOUT;

    //SG_IO 表明将 sg_io_hdr 对象作为 ioctl() 函数的第三个参数提交，并且在 SCSI 命令结束时返回
    if (ioctl(fd, SG_IO, &io_hdr) < 0) {
        PRINT_ERR_HEAD
        print_err("ioctl error[%s]", strerror(errno));
        return -1;
    }

    //now for the error processing
    if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        if (io_hdr.sb_len_wr > 0) {
            *sense_len = io_hdr.sb_len_wr;
            return 0;
        }
    }

    if (io_hdr.masked_status) {
        PRINT_ERR_HEAD
        print_err("status=0x%x  masked_status=0x%x", io_hdr.status, io_hdr.masked_status);
        return -2;
    }

    if (io_hdr.host_status) {
        PRINT_ERR_HEAD
        print_err("host_status=0x%x", io_hdr.host_status);
        return -3;
    }

    if (io_hdr.driver_status) {
        PRINT_ERR_HEAD
        print_err("driver_status=0x%x", io_hdr.driver_status);
        return -4;
    }

    return 0;
}

/**
 * [get_diskid_hda 获取磁盘的ID 按hda方式获取]
 * @param  diskid   [磁盘ID 出参]
 * @return        [成功返回true]
 */
bool get_diskid_hda(char *diskid)
{
    if (diskid == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    struct hd_driveid driveid;
    BZERO(driveid);

    int fd = open("/dev/hda", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("open error[%s]", strerror(errno));
        return false;
    }

    if (ioctl(fd, HDIO_GET_IDENTITY, &driveid) < 0) {
        PRINT_ERR_HEAD
        print_err("ioctl error[%s]", strerror(errno));
        close(fd);
        return false;
    }
    sprintf(diskid, "%20s", driveid.serial_no);
    close(fd);

    PRINT_INFO_HEAD
    print_info("diskid[%s]", diskid);
    return true;
}

/**
 * [get_cpudesc 获取CPU描述信息]
 * 由于CPU的ID不好获取，所以直接使用/proc/cpuinfo中的信息来表示
 * 如：Intel(R) Celeron(R) CPU G3900 @ 2.80GHz
 * @param  cpudesc [CPU描述 出参]
 * @return        [成功返回true]
 */
bool get_cpudesc(char *cpudesc)
{
    CCommon common;
    char buff[64] = {0};

    if (cpudesc != NULL) {
        if (common.Sysinfo("cat /proc/cpuinfo |grep \"model name\"", buff, sizeof(buff)) != NULL) {
            char *ptr = strchr(buff, ':');
            if (ptr != NULL ) {
                a_trim(cpudesc, ptr + 1);

                PRINT_DBG_HEAD
                print_dbg("cpudesc[%s]", cpudesc);
                return true;
            } else {
                PRINT_ERR_HEAD
                print_err("not find :");
            }
        } else {
            PRINT_ERR_HEAD
            print_err("sysinfo fail");
        }
#if 1
        if (cpudesc[0] == 0) {
            strcpy(cpudesc, "xxxx-xxxx-xxxx-xxxx");
            PRINT_INFO_HEAD
            print_info("get cpudesc fail,use default %s", cpudesc);
            return true;
        }
#endif
    } else {
        PRINT_ERR_HEAD
        print_err("para null");
    }
    return false;
}

/**
 * [get_cardnum 获取网卡个数]
 * @param  cardnum [网卡个数 出参]
 * @return         [成功返回true]
 */
#define MAX_CARD_NUM 50 //最大50个
bool get_cardnum(int &cardnum)
{
    CCommon common;
    char buff[64] = {0};

    if (common.Sysinfo("cat /proc/net/dev|grep eth|wc -l", buff, sizeof(buff)) != NULL) {
        cardnum = atoi(buff);
        PRINT_DBG_HEAD
        print_dbg("cardnum[%d]", cardnum);
        return (cardnum > 0);
    } else {
        PRINT_ERR_HEAD
        print_err("sysinfo fail");
        return false;
    }
}

/**
 * [get_memsize 获取内存总容量 单位MB]
 * @param  memsize [内容总容量 出参]
 * @return         [成功返回true]
 */
bool get_memsize(int &memsize)
{
    int num_pages = sysconf (_SC_PHYS_PAGES);
    int page_size = sysconf (_SC_PAGESIZE);
    memsize = (num_pages / 1024) * (page_size / 1024);
    return true;
}

/**
 * [get_disksize 获取磁盘容量 单位MB]
 * @param  disksize [磁盘容量 出参]
 * @param  path     [挂载路径]
 * @return          [成功返回true]
 */
bool get_disksize(int &disksize, const char *path)
{
    if (path == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    struct statfs diskInfo;
    if (statfs(path, &diskInfo) != 0) {
        PRINT_ERR_HEAD
        print_err("statfs error[%s]", strerror(errno));
        return false;
    }

    disksize = (diskInfo.f_blocks / 1024) * (diskInfo.f_bsize / 1024);
    return true;
}

/**
 * [get_cardspeed 获取所有网卡中速率最快的 速率值]
 * @param  cardnum   [总网卡数]
 * @param  cardspeed [网卡速率 出参]
 * @return           [成功返回true]
 */
bool get_cardspeed(int cardnum, int &cardspeed)
{
    if (cardnum <= 0) {
        PRINT_ERR_HEAD
        print_err("cardnum err[%d]", cardnum);
        return false;
    }

    int ret = 0;

    for (int i = 0; i < cardnum; ++i) {
        if ((ret = get_one_cardspeed(i)) < 0) {
            PRINT_ERR_HEAD
            print_err("get speed[eth%d] fail", i);
            return false;;
        } else {
            if (ret > cardspeed) {
                cardspeed = ret;
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("cardspeed [%d]", cardspeed);
    return true;
}

/**
 * [get_one_cardspeed 获取指定网卡速率值]
 * @param  id [网卡号]
 * @return    [失败返回负值]
 */
#define CARD_DEFAULT_SPEED 1000
int get_one_cardspeed(int id)
{
    if (id < 0) {
        PRINT_ERR_HEAD
        print_err("card id err[eth%d]", id);
        return -1;
    }

    CCommon common;
    char chcmd[64] = {0};
    char buff[64] = {0};
    int speed = -1;

    sprintf(chcmd, "ethtool eth%d |grep 10000base|wc -l", id);
    if (common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) {
        if (atoi(buff) > 0) {
            speed = 10000;
            goto _out;
        }
    }

    sprintf(chcmd, "ethtool eth%d |grep 1000base|wc -l", id);
    if (common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) {
        if (atoi(buff) > 0) {
            speed = 1000;
            goto _out;
        }
    }

    sprintf(chcmd, "ethtool eth%d |grep 100base|wc -l", id);
    if (common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) {
        if (atoi(buff) > 0) {
            speed = 100;
            goto _out;
        }
    }

    sprintf(chcmd, "ethtool eth%d |grep 10base|wc -l", id);
    if (common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) {
        if (atoi(buff) > 0) {
            speed = 10;
            goto _out;
        }
    }

_out:

    if (speed < 0) {
        speed = CARD_DEFAULT_SPEED;
        PRINT_INFO_HEAD
        print_info("[eth%d] get speed fail. set to default[%d]", id, speed);
    } else {
        PRINT_DBG_HEAD
        print_dbg("[eth%d] speed [%d]", id, speed);
    }
    return speed;
}
