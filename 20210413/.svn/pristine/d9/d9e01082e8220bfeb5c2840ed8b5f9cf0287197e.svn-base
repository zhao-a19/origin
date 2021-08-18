/*******************************************************************************************
*文件:  FCHttpSingle.h
*描述:  HTTP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*
*作者:  宋宇
*修改:
*     增加解析method和url的函数                                             ------> 2019-05-15
*     把除IfRequest函数外的所有私有成员函数变成公有成员函数                     ------> 2019-05-15
*******************************************************************************************/
#ifndef __FC_HTTP_SINGLE_H__
#define __FC_HTTP_SINGLE_H__

#include <pthread.h>
#include "FCSingle.h"
//#include "my_http_parser.h"

#define MAX_HTTP_CMD_LEN 128
#define MAX_HTTP_URL_LEN 1024
#define MAX_HTTP_DATA_LEN 2048

class CHTTPSINGLE : public CSINGLE
{
public:
    CHTTPSINGLE(void);
    virtual ~CHTTPSINGLE(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeReply(unsigned char *sdata, int slen);
    int index_str(const char *main_str, int main_len, const char *key_str, int key_len,int *next);
private:
    static bool IfRequest(const char *chrequest);
    void get_next(const char *key_str, int len, int *next);

private:
    char httpdata[MAX_HTTP_DATA_LEN];
    char ch_cmd[MAX_HTTP_CMD_LEN];
    char ch_url[MAX_HTTP_URL_LEN];
    char end_str[MAX_HTTP_CMD_LEN];
    int next_arr[MAX_HTTP_CMD_LEN];

};

#endif
