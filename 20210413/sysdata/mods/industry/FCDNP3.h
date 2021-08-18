/*******************************************************************************************
*文件:  FCDNP3.h
*描述:  DNP3模块
*作者:  王君雷
*日期:  2017-11-09
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_DNP3_H__
#define __FC_DNP3_H__

#include "FCSingle.h"
using namespace std;
#include <vector>

#define DNP3_HEAD1 (0x05)
#define DNP3_HEAD2 (0x64)
#define DNP3_MAXSIZE 255        //DNP链路层报文的最大长度为10+(250/16)×18+(250%16+2)=292字节
#define DNP3_MINSIZE 5          //DNP链路层报文的最小长度，即链路层有效长度

//dnp3块不携带crc时16一组，携带crc时18一组
#define DNP3_USERSIZE   16
#define DNP3_USERSIZECRC 18

//链路层控制字+目的地址+源地址
#define DNP3LPDU_LEN 5

//计算LPDU的长度转换为数据包大小
#define BLOCK_SIZE(l)   ((((l) - DNP3LPDU_LEN) >> 4) * DNP3_USERSIZECRC + sizeof(DNP3LPDU))
#define BLOCK_SIZE_(l)   (((l) - DNP3LPDU_LEN) & 0x0f)
#define DNP3_LEN2SIZE(l) (BLOCK_SIZE_(l) != 0) ? (BLOCK_SIZE(l) + BLOCK_SIZE_(l) + DNP3_USERSIZECRC - DNP3_USERSIZE) : BLOCK_SIZE(l)


#pragma pack(push, 1)
typedef struct _lpdu {
    unsigned char identifier[2];//标识符
    unsigned char length;       //数据长度
    unsigned char ctrl;         //链路层功能码
    unsigned char dst_addr[2];  //目的地址
    unsigned char src_addr[2];  //源地址
    unsigned char crc[2];       //crc校验值
} DNP3LPDU, *PDNP3LPDU;

//应用层（包含传输层的一个字节）
typedef struct _apdu {          //主站发
    unsigned char th;           //传输层字节
    unsigned char ctrl;         //应用层控制字
    unsigned char cmd;          //应用层功能码
    unsigned char object[2];    //对象
    unsigned char aq;           //限定词
} DNP3APDU, *PDNP3APDU;

typedef struct _apdu_iin {      //子站发
    unsigned char th;           //传输层字节
    unsigned char ctrl;         //应用层控制字
    unsigned char cmd;          //应用层功能码
    unsigned char iin[2];       //子站状态  内部信号字
    unsigned char object[2];    //对象
    unsigned char aq;           //限定词
} DNP3APDU_IIN, *PDNP3APDU_IIN;

#pragma pack(pop)

//dnp3数据包的状态
enum status {
    PDU_ONLYLPDU = 0,            //仅存在链路层
    PDU_APDUACMD = 1,            //不存在应用层数据对象部分
    PDU_APDUAQ = 2,              //存在限定词，不存在应用层变程部分
    PDU_APDUAR = 3,              //存在变程部分

    PDU_ERROR = -1,              //数据处理出错
};

class DNP3CMDDEFINE
{
public:
    DNP3CMDDEFINE(unsigned char incmd, int inrw, char *inchremark);
    ~DNP3CMDDEFINE();

public:
    unsigned char cmd;
    int rw;
    char chremark[64];
};

class AQDEFINE
{
public:
    AQDEFINE(unsigned char inaq, unsigned char inar_len, bool inmode);
    ~AQDEFINE();

public:
    unsigned char aq;//限定词的值
    unsigned char ar_len;//变程长度
    bool mode;//起止模式?
};

class CDNP3 : public CSINGLE
{
public:
    CDNP3();
    ~CDNP3();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    int getlpdu(const unsigned char *sdata, int slen, char *cherror);
    int getapdu(const unsigned char *sdata, int slen, char *cherror);
    unsigned short GetCRC16_DNP(const unsigned char *buf, int len);
    int data_crc_check(const unsigned char *data, int len);
    bool SendByMaster();
    void InitCmdDefine();
    void InitAQDefine();
    void GetCmdString(unsigned char c);
    bool FilterCode(char *cherror);
    bool FirstBlock(unsigned char c);
    int GetARValue(const unsigned char *buff, const unsigned char len);
    bool MatchCode(const char *chcmd);
    bool MatchAQ(const char *chcmd);
    bool MatchAR(const char *chcmd, bool action);

private:

    struct {
        unsigned char lctrl;       //链路层控制字
        unsigned char  len;        //长度
        unsigned char  acmd;       //应用层功能码
        unsigned char  aq;         //限定词
        int ar_start;     //兼容数量模式
        int ar_end;       //变程
        int  status;               //数据包状态标志位
    } m_pdu;

    vector<DNP3CMDDEFINE> m_cmddefine;
    vector<AQDEFINE> m_aqdefine;
    char m_chcmd[MAX_CMD_NAME_LEN];//功能码描述
    char m_chpara[MAX_PARA_NAME_LEN];//限定词描述
    int m_rw;
    bool m_firstblock;
};

#endif
