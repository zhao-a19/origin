/*******************************************************************************************
*文件:  FCSendFileUdp.h
*描述:  UDP方式发送文件接口
*作者:  王君雷
*日期:  2016-03
*修改:
*       send_file_udp失败超过一定次数后可选择返回错误，避免无限循环       ----> 2017-08-16
*******************************************************************************************/
#ifndef __FC_SEND_FILE_UDP_H__
#define __FC_SEND_FILE_UDP_H__

#define TRY_FOREVER -1

//文件传输开始 结束 每次读块的长度
#define FILE_BEGIN         -1
#define FILE_END           -2
#define FILE_BLOCKSIZE     1000

#define TMP_SUFFIX_FILE ".anmit_tmp" //临时文件后缀

int send_file_udp(const char *srcfile, const char *dstfile = NULL, int trytimes = TRY_FOREVER);

#endif
