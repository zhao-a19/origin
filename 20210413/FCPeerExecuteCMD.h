/*******************************************************************************************
*文件:  FCPeerExecuteCMD.h
*描述:  让对端执行命令接口
*作者:  王君雷
*日期:  2016-03
*修改:
*         添加PeerExecuteCMD2接口函数                                   ------> 2018-07-19
*******************************************************************************************/
#ifndef __FC_PEER_EXECUTE_CMD_H__
#define __FC_PEER_EXECUTE_CMD_H__

int PeerExecuteCMD(const char *cmd, int timeout = 1);
int PeerExecuteCMD2(const char *cmd, const char *dip, int dport, int timeout = 1);

#endif
