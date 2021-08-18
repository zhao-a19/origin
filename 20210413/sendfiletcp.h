/*******************************************************************************************
*文件:  sendfiletcp.h
*描述:  TCP方式发送文件接口
*作者:  王君雷
*日期:  2020-02-24
*修改:
*******************************************************************************************/
#ifndef __SEND_FILE_TCP_H__
#define __SEND_FILE_TCP_H__

int send_file_tcp(const char *srcfile, const char *dstfile, int perm = 0, int mode = 1);

#endif
