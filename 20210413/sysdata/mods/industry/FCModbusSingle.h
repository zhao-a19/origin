/*******************************************************************************************
*文件:  FCModbusSingle.h
*描述:  MODBUS模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_MODBUS_H__
#define __FC_MODBUS_H__

#include "FCSingle.h"

//modbus报文头长度
#define MODBUSMBAP_LEN 7

#define COIL_R   1   //读线圈
#define BIT_R    2   //读离散量输入
#define REGHD_R  3   //读保持寄存器
#define REGIN_R  4   //读输入寄存器
#define COIL_W   5   //写单个线圈
#define REG_W    6   //写单个寄存器
#define COIL_WM  15  //写多个线圈
#define REG_WM   16  //写多个寄存器
#define FILE_R   20  //读文件记录
#define FILE_W   21  //写文件记录
#define REG_MASK 22  //屏蔽写寄存器
#define REG_RW   23  //读写多个寄存器
#define DEV_R    43  //读设备识别码

class CMODBUSSINGLE : public CSINGLE
{
public:
    CMODBUSSINGLE();
    ~CMODBUSSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool FilterCode(const char *chcodeid, unsigned char *sdata, int slen, char *cherror);
    const char *GetRFCString(const char *chcodeid);
    bool GetParaSection(const char *chpara, int &leftval, int &rightval);
    void GetDataSection(unsigned char *chdata, int &leftval, int &rightval);
    bool GetValueSection(const char *chcmd, const char *chvalue, int &value_sec_l, int &value_sec_r);
private:
    char m_chcmd[MAX_CMD_NAME_LEN];
    char m_chpara[MAX_PARA_NAME_LEN];
};

#endif
