/*******************************************************************************************
*文件:  FCS7.h
*描述:  S7模块
*作者:  王君雷
*日期:  2017-12-12
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_S7_H__
#define __FC_S7_H__

#include "FCSingle.h"

#pragma pack(push, 1)

//s7comm header+parameter
typedef struct _s7commstate {
    //s7coomm header
    unsigned char protocol_id;     //s7协议标识：0x32
    unsigned char rosctr;          //rosctr类型
    unsigned short reserved;        //保留字
    unsigned short data_unit_reference; //数据单元保留字
    unsigned short para_len;    //参数长度
    unsigned short data_len;    //数据长度

    //Parameter
    union {
        //job
        struct {
            unsigned char job_func;   //function type字段
        } JOB;
        //ack和ack_data
        struct {
            unsigned char error_class; //error class
            unsigned char error_code;  //error code
            unsigned char ack_func;   //function type字段
        } S7ACK;
        //user_data
        struct {
            unsigned int param; //paramter head+length
            unsigned char unknown;   //unknown
            unsigned char type;       //type+functiong group type
            unsigned char sub_func;   //subfunction
        } USERDATA;
    } PARM;

} S7COMMSTATE, *PS7COMMSTATE;

#pragma pack(pop)

class CS7 : public CSINGLE
{
public:
    CS7(void);
    ~CS7(void);
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    int CheckTpkt(unsigned char *sdata, int slen);
    bool DecodeRequest(unsigned char *sdata, int slen);
    bool CheckPduType(unsigned char ch);
    bool GetOnlyCmd(unsigned char ch);
    bool GetUserDataInfo(unsigned char type, unsigned char sub_func);
    bool GetUserDataType(unsigned char ch);
    bool GetFuncGroup(unsigned char ch);
    bool GetSubFunc(unsigned char funcgroup, unsigned char ch);

    bool FilterCode(char *cherror);
    bool MatchCode(const char *chcmd);
    bool MatchPara(const char *chpara);
    bool MatchPara2(const char *chpara2);
    void MakeString(char *strcmd, int cmdlen, char *strpara, int paralen);
private:
    int m_pdu_type;
    int m_rw;
    char m_chcmd[MAX_CMD_NAME_LEN];
    char m_chpara[MAX_PARA_NAME_LEN];
    char m_chpara2[MAX_PARA_NAME_LEN];
};

#endif
