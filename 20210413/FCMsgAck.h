/*******************************************************************************************
*文件:  FCMsgAck.h
*描述:  发送和接收消息确认接口
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_MSG_ACK_H__
#define __FC_MSG_ACK_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define MSG_ACK_OK    0
#define MSG_ACK_FAIL -1

int RecvMsgAck(int fd, struct sockaddr_in *addr, socklen_t addrlen, int msgtype, int *ptime = NULL);
int SendMsgAck(int fd, struct sockaddr_in *addr, socklen_t addrlen, int msgtype, int res, int *ptime = NULL);

#endif
