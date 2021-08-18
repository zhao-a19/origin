/*******************************************************************************************
*文件: ausvr.h
*描述: 授权服务程序
*作者: 王君雷
*日期: 2018-09-20
*修改:
*      移动头文件中不需要暴露出去的信息                                ------> 2018-10-15
*******************************************************************************************/
#ifndef __AUTH_SVR_H__
#define __AUTH_SVR_H__

#define UNIX_AUTHSVR  "/tmp/ausvr"
#define HEARTBEAT_REQUEST_LEN 12  //心跳请求的长度

enum {
    AUSVR_RESULT_FAIL = -1,
    AUSVR_RESULT_OK = 0,
};

#pragma pack(push, 1)
typedef struct AU_RESPONSE {
    unsigned char md5buff32[32];
    int result;
} AU_RESPONSE;
#pragma pack(pop)

#endif
