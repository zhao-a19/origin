/*******************************************************************************************
*文件:  FCDPDK.h
*描述:  启动DPDK相关接口函数
*作者:  王君雷
*日期:  2016-11-29
*修改:
*******************************************************************************************/
#ifndef __FC_DPDK_H__
#define __FC_DPDK_H__

#include <iostream>
using namespace std;
#include <vector>

int StartDPDK();
int ClearDPDK();

//DPDK容器  用来处理调用sul2fwd命令行参数信息
class DPDK_CONTAINER
{
public:
    DPDK_CONTAINER();
    virtual ~DPDK_CONTAINER();
    int CombineString(char *chcmd);
    void SetFilter(bool filter);
private:
    bool m_bfilter;
};

#endif
