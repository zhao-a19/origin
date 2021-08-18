/*******************************************************************************************
*文件:  hardinfo.h
*描述:  硬件信息操作
*作者:  王君雷
*日期:  2018-09-09
*修改:
*       可以使用网卡号、网卡名获取网卡的mac                           ------> 2018-09-19
*******************************************************************************************/
#ifndef __HARD_INFO_H__
#define __HARD_INFO_H__
#include <stddef.h> //arm64 for NULL

bool get_cpudesc(char *cpudesc);

bool get_memsize(int &memsize);

bool get_diskid_sda(char *diskid);
bool get_diskid_hda(char *diskid);
bool get_diskid(char *diskid);
bool get_disksize(int &disksize, const char *path = "/initrd/");

bool get_mac(int no, char *mac, unsigned char *binmac = NULL);
bool get_mac(const char *device, char *mac, unsigned char *binmac = NULL);
bool get_cardnum(int &cardnum);
bool get_cardspeed(int cardnum, int &cardspeed);
int get_one_cardspeed(int id);

#endif
