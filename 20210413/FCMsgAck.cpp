/*******************************************************************************************
*文件:  FCMsgAck.cpp
*描述:  发送接收消息确认
*作者:  王君雷
*日期:  2014
*
*修改:
*        函数添加参数ptime,发送或接收确认成功时记录下时间          ------> 2016-01-25
*******************************************************************************************/
#include "FCMsgAck.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

//
//向对端发送消息确认，告诉对端已经正确接收到了
//参数：
//	fd	socket描述符
//	addr 发往的地址
//	addrlen 发往的地址长度
//	msgtype 所确认的消息的类型
//	res	处理结果
//返回值：
//	0 成功
//	-1 失败
//	--wangjunlei 20141125--
//
int SendMsgAck(int fd, struct sockaddr_in *addr, socklen_t addrlen, int msgtype, int res, int* ptime)
{
    //组发送的内容
    char buf[16] = "";
    memcpy(buf, &msgtype, 4);
    memcpy(buf + 4, &res, 4);

    int ret = sendto(fd, buf, 8, 0, (struct sockaddr *)addr, addrlen);
    if (ret < 0)
    {
        perror("SendMsgAck sendto");
        printf("SendMsgAck error![%d]\n", msgtype);
        return -1;
    }

    if (ptime != NULL)
    {
        *ptime = time(NULL);
    }
    return 0;
}

//
//接收对端的消息确认
//参数：
//	fd	socket描述符
//	addr 接收的地址
//	addrlen 接收的地址长度
//	msgtype 所确认的消息的类型
//返回值：
//	0 成功
//	-1 超时
//	-2 recvfrom调用失败
//	-3 消息类型不对
//	-4 对端成功接收到了 但处理失败
//	--wangjunlei 20141125--
//
int RecvMsgAck(int fd, struct sockaddr_in *addr, socklen_t addrlen, int msgtype, int *ptime)
{
    char buf[16] = "";
    int type = 0;
    int result = 0;

    int ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)addr, &addrlen);
    if (ret < 0)
    {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
        {
            printf("RecvMsgAck timeout![%d]\n", msgtype);
            return -1;
        }
        else
        {
            perror("RecvMsgAck recvfrom");
            printf("RecvMsgAck error![%d]\n", msgtype);
            return -2;
        }
    }

    if (ret < 8)
    {
        printf("RecvMsgAck length error!len[%d] < 8\n", ret);
        return -3;
    }
    memcpy(&type, buf, 4);
    memcpy(&result, buf + 4, 4);

    if (type != msgtype)
    {
        printf("RecvMsgAck type error! type[%d] != [%d]\n", type, msgtype);
        return -3;
    }

    if (ptime != NULL)
    {
        *ptime = time(NULL);
    }

    if (result != 0)
    {
		printf("RecvMsgAck[%d] ok, but peer want resend! result=%d\n", type, result);
        return -4;
    }

    return 0;
}
