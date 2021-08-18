/*******************************************************************************************
*文件:  lcdmanager.h
*描述:  LCD管理
*作者:  王君雷
*日期:  2016-03
*修改:
*       拆分为LCDMANAGER、LCDBASE等多个类，可以展示内存、CPU使用率     ------> 2019-04-10
*       如果配置了IPV6的管理IP，液晶屏也展示出来                       ------> 2019-04-11
*       LCD每侧展示的IP最大支持个数改为MAX_INPNUM 即500                ------> 2019-07-20
*******************************************************************************************/
#ifndef __LCD_MANAGER_H__
#define __LCD_MANAGER_H__

#include "define.h"
#include "lcdbase.h"

#define LCD_MAX_IP_NUM MAX_IPNUM
#define LCD_MAX_IP_LEN IP_STR_LEN

class LCDMANAGER
{
public:
    LCDMANAGER(void);
    virtual ~LCDMANAGER(void);
    bool read_flag(void);
    void loop(void);
    bool use_lcd(void);
    bool init(void);

private:
    int current_flag(void);
    void read_info(void);
    bool judge_status(void);
    static bool read_recvpkt(long long int &pkt);
    void show(const char *info);
    void show(const char *info1, const char *info2);
    void show_inip(void);
    void show_outip(void);

private:
    LCDBASE *m_worker;                //负责具体液晶屏展示的工人
    int m_lcdflag_in;                 //内网使用什么类型的液晶屏
    int m_lcdflag_out;                //外网使用什么类型的液晶屏
    bool m_is_inside;                 //是否为内网
    int m_inipnum;
    int m_outipnum;
    int m_inbondipnum;
    int m_outbondipnum;
    char *m_inip[LCD_MAX_IP_NUM];     //内网业务IP
    char *m_outip[LCD_MAX_IP_NUM];    //外网业务IP
    char *m_inbondip[LCD_MAX_IP_NUM]; //内网bond IP
    char *m_outbondip[LCD_MAX_IP_NUM];//外网bond IP
    char m_manip[LCD_MAX_IP_LEN];     //管理IP
    char m_manipv6[LCD_MAX_IP_LEN];   //管理IPv6
    char m_lcdbuf[64];                //读取LCD配置缓冲区
    char m_linkstatus[20];            //运行状态
    char m_wk[32];                    //工作模式
    long long int m_recvpkts;         //内部通信卡，接收数据包个数
};

bool StartShowLCD(void);

#endif
