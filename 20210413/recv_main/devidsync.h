/*******************************************************************************************
*文件:  devidsync.h
*描述:  把内网的设备ID号同步到外网
*作者:  王君雷
*日期:  2020-02-14
*修改:
*******************************************************************************************/
#ifndef __DEV_ID_SYNC_H__
#define __DEV_ID_SYNC_H__

bool StartDevIDSync(void);
int read_devid(char *devid, int size);
int write_devid(const char *devid);

#endif
