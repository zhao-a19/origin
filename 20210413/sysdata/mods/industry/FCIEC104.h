/*******************************************************************************************
*文件:  FCIEC104.h
*描述:  IEC104模块
*作者:  王君雷
*日期:  2017-11-22
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_IEC104_H__
#define __FC_IEC104_H__

#include "FCSingle.h"
using namespace std;
#include <vector>

#pragma pack(push, 1)
typedef struct _apci_ {
    unsigned char head;
    unsigned char len;              //不包含头和自身，最大253B
    union {
        unsigned int ctrl;        //控制域
        struct {
            unsigned char ctrl1;
            unsigned char ctrl2;
            unsigned char ctrl3;
            unsigned char ctrl4;
        } ctrl_st;
    };

} IECAPCI, *PIECAPCI;

//此结构仅适合标准的主站（即reason，station和point长度定义为2,2,3）
typedef struct _asdue_ {
    unsigned char idtype;               //类型标识
    union {
        unsigned char qualifier;        //限定词
        struct {
            unsigned char qf_num: 7;
            unsigned char qf_sq: 1;     //0离散信息报告，1顺序信息报告
        } qualifier_st;
    };

    union {
        unsigned short reason;          //传输原因
        struct {
            unsigned char rs_cause: 6;
            unsigned char rs_pn: 1;     //0未试验，1试验
            unsigned char rs_t: 1;      //0肯定确认，1否定确认
            unsigned char rs_src;       //源发地址
        } reason_st;
    };

    unsigned short station;             //公共地址
    unsigned char  point[3];            //信息体地址
} IECASDU_E, *PIECASDU_E;

#pragma pack(pop)

#define IEC104_HEAD     (0x68)
#define IEC104_MAXLEN   (253)
#define IEC104_MINLEN   (4)

//控制域格式  不是标准里规定的值，是自己约定使用的
#define I_FRAME   0
#define U_FRAME   1
#define S_FRAME   2
#define UN_FRAME -1

class IEC104TYPEDEFINE
{
public:
    IEC104TYPEDEFINE(unsigned char incmd, char *inenglish, int inrw, char *inchinese);
    ~IEC104TYPEDEFINE();

public:
    unsigned char cmd;
    int rw;
    char english[16];//英文注释
    char chinese[64];//中文注释
};

class CIEC104 : public CSINGLE
{
public:
    CIEC104();
    ~CIEC104();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    void InitCodeDefine();
    int getframe(IECAPCI &head);
    bool DecodeRequest(unsigned char *sdata, int slen, int apcilen, char *cherror);
    bool getval(unsigned char *data, int len, unsigned int &val);
    void GetIECString();
    void GetIECCodeString();
    bool FilterCode(char *cherror);
    bool MatchCode(const char *chcmd);
    bool MatchAddr(const char *chaddr);
    bool MatchPoint(const char *chpoint);

private:
    char m_chcmd[MAX_CMD_NAME_LEN];
    char m_chpara[MAX_PARA_NAME_LEN];

    vector<IEC104TYPEDEFINE> m_codedefine;

    unsigned int m_code;
    unsigned int m_addr;
    unsigned int m_point;
    int m_rw;
};

/*******************************************************************************************
*
*                               ASDU类型标识定义
*
*******************************************************************************************/

//1--1 监视方向的过程信息, RTU向主站上传的报文类型
#define M_SP_NA_1 0x01    //单点信息              （总召唤遥信、变位遥信）
#define M_SP_TA_1 0x02    //带时标单点信息        （SOE事项）
#define M_DP_NA_1 0x03    //双点信息
#define M_DP_TA_1 0x04    //带时标双点信息     ？？标准里的定义重复, 根据PMA修订
#define M_ST_NA_1 0x05    //步位置信息
#define M_ST_TA_1 0x06    //带时标步位置信息
#define M_BO_NA_1 0x07    //32比特串
#define M_BO_TA_1 0x08    //带时标32比特串
#define M_ME_NA_1 0x09    //测量值，规一化值      （越限遥测）
#define M_ME_TA_1 0x0A    //测量值，带时标规一化值
#define M_ME_NB_1 0x0B    //测量值，标度化值
#define M_ME_TB_1 0x0C    //测量值，带时标标度化值
#define M_ME_NC_1 0x0D    //测量值，短浮点数
#define M_ME_TC_1 0x0E    //测量值，带时标短浮点数
#define M_IT_NA_1 0x0F    //累计量               （电度量）
#define M_IT_TA_1 0x10    //带时标累计量
#define M_EP_TA_1 0x11    //带时标继电保护装置事件
#define M_EP_TB_1 0x12    //带时标继电保护装置成组启动事件
#define M_EP_TC_1 0x13    //带时标继电保护装置成组输出电路信息
#define M_PS_NA_1 0x14    //具有状态变位检出的成组单点信息         ？？标准里的定义重复, 根据PMA修订
#define M_ME_ND_1 0x15    //测量值，不带品质描述的规一化值    （总召唤遥测量）

#define M_SP_TB_1 0x1E    //带时标CP56TimE2A的单点信息
#define M_DP_TB_1 0x1F    //带时标CP56TimE2A的双点信息
#define M_ST_TB_1 0x20    //带时标CP56TimE2A的步位信息
#define M_BO_TB_1 0x21    //带时标CP56TimE2A的32位串
#define M_ME_TD_1 0x22    //带时标CP56TimE2A的规一化测量值
#define M_ME_TE_1 0x23    //测量值，带时标CP56TimE2A的标度化值
#define M_ME_TF_1 0x24    //测量值，带时标CP56TimE2A的短浮点数
#define M_IT_TB_1 0x25    //带时标CP56TimE2A的累计值
#define M_EP_TD_1 0x26    //带时标CP56TimE2A的继电保护装置事件
#define M_EP_TE_1 0x27    //带时标CP56TimE2A的成组继电保护装置成组启动事件
#define M_EP_TF_1 0x28    //带时标CP56TimE2A的继电保护装置成组输出电路信息

//1--2 在监视方向的系统信息, RTU向主站上传的报文类型
#define M_EI_NA_1 0x46    //初始化结束

//2--1 在控制方向的过程信息, RTU须逐条对命令用相同报文确认
#define C_SC_NA_1 0x2D    //单命令               （遥控）
#define C_DC_NA_1 0x2E    //双命令               （遥控）
#define C_RC_NA_1 0x2F    //升降命令
#define C_SE_NA_1 0x30    //设定值命令，规一化值 （遥调）
#define C_SE_NB_1 0x31    //设定值命令，标度化值
#define C_SE_NC_1 0x32    //设定值命令，短浮点数
#define C_BO_NA_1 0x33    //32比特串

#define C_SC_TA_1 0x3A    //带时标CP56TimE2A的单命令
#define C_DC_TA_1 0x3B    //带时标CP56TimE2A的双命令
#define C_RC_TA_1 0x3C    //带时标CP56TimE2A的升降命令
#define C_SE_TA_1 0x3D    //带时标CP56TimE2A的设定值命令，规一化值
#define C_SE_TB_1 0x3E    //带时标CP56TimE2A的设定值命令，标度化值
#define C_SE_TC_1 0x3F    //带时标CP56TimE2A的设定值命令，短浮点数
#define C_BO_TA_1 0x40    //带时标CP56TimE2A的32比特串

//2--2 在控制方向的系统信息, RTU须逐条形成镜像报文
#define C_IC_NA_1 0x64    //总召唤命令        （总召唤）
#define C_CI_NA_1 0x65    //电能脉冲召唤命令  （召唤电度量）
#define C_RD_NA_1 0x66    //读命令
#define C_CS_NA_1 0x67    //时钟同步命令      （校时）
#define C_TS_NA_1 0x68    //测试命令
#define C_RP_NA_1 0x69    //复位进程命令
#define C_CD_NA_1 0x6A    //延时传输命令
#define C_TS_TA_1 0x6B    //带时标CP56TimE2A的测试命令

//2--3 在控制方向的参数命令
#define P_ME_NA_1 0x6E    //测量值参数，规一化值
#define P_ME_NB_1 0x6F    //测量值参数，标度化值
#define P_ME_NC_1 0x70    //测量值参数，短浮点数
#define P_AC_NA_1 0x71    //参数激活

//3--1 文件传输
#define F_FR_NA_1 0x78    //文件准备好
#define F_SR_NA_1 0x79    //节已准备好
#define F_SC_NA_1 0x7A    //召唤目录，选择文件，召唤文件，召唤节
#define F_LS_NA_1 0x7B    //最后的节，最后的度
#define F_AF_NA_1 0x7C    //确认文件，确认节
#define F_SG_NA_1 0x7D    //段
#define F_DR_TA_1 0x7E    //目录

#endif
