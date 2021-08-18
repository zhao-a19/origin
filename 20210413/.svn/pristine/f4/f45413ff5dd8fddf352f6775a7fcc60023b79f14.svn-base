/*******************************************************************************************
*文件:  FCHotBakBS.h
*描述:  CHOTBAKBS类
*作者:  王君雷
*日期:  2016-03
*修改:
*       完善注释信息，引入zlog                                          ------> 2018-11-21
*       新增InNetMonitor、OutNetMonitor等函数，缩小ListenFunc函数体行数 ------> 2018-11-27
*******************************************************************************************/
#ifndef __FC_HOTBAK_BS_H__
#define __FC_HOTBAK_BS_H__

#include "FCDevBS.h"
#include "FCYWBS.h"
#include "struct_info.h"

//接收信息处理信息业务
class CHOTBAKBS
{
public:
    CHOTBAKBS(void);
    virtual ~CHOTBAKBS(void);
    bool Start(void);
    void SetDevBS(CDEVBS *p_devbs);
    void SetYWBS(CYWBS *p_ywbs);

private:
    friend void *ListenFunc(void *para);
    friend void *CtrlFunc(void *para);
    int UpInNet(void);
    int UpOutNet(void);
    int DownInNet(int except_eth = -1);
    int DownOutNet(int except_eth = -1);
    int UpDownInNet(int except_eth = -1);
    int UpDownOutNet(int except_eth = -1);
    int GetOutCardStatus(char *ethname);
    int SetOutRoute(void);
    int ReadOutDefGW(void);
    void CollectMac(void);
    void CollectMacInNet(void);
    void CollectMacOutNet(void);
    bool InNetMonitor(int &badethno, char *badethname, int &badarea);
    bool OutNetMonitor(int &badethno, char *badethname, int &badarea);
    int GetBadCardStatus(int badethno, char *badethname, int badarea);
    int MakeReportInfo(char *report, int rlen, int nicstatus);

public:
    CDEVBS *m_devbs;    //设备管理业务
    CYWBS *m_ywbs;

private:
    CThread m_hotbakth; //网口连接检测及汇报线程
    CThread m_ctrlth;
    char m_outdefgw[IP_STR_LEN];
    int m_nicnum_in;
    int m_nicnum_out;
    NIC_MAC_STRUCT m_nic_in[MAX_NIC_NUM];
    NIC_MAC_STRUCT m_nic_out[MAX_NIC_NUM];
};

void *ListenFunc(void *para);
void *CtrlFunc(void *para);

#endif
