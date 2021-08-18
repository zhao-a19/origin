/*******************************************************************************************
*文件:  secway.h
*描述:  安全通道
*作者:  王君雷
*日期:  2018-12-29
*修改:
*******************************************************************************************/
#ifndef __SEC_WAY_H__
#define __SEC_WAY_H__

#define SECWAY_NAME_LEN 100          //安全通道名称长度

class SEC_WAY
{
public:
    SEC_WAY(void);
    SEC_WAY(const char *pwayname, int area, int indev, int outdev);
    virtual ~SEC_WAY(void);

    bool equal(int area, int indev, int outdev);
    bool equal(SEC_WAY &secway);

    void setarea(int way);
    void setindev(int dev);
    void setoutdev(int dev);
    void setway(const char *pwayname, int area, int indev, int outdev);

    int getarea(void);
    int getindev(void);
    int getoutdev(void);
    const char *getwayname(void);

    const char *iptables_bridge(bool binnet, int linklan);
private:
    const char *iptables_bridge(const char *comelan, const char *golan);
private:
    char m_wayname[SECWAY_NAME_LEN];
    int m_area;
    int m_indev;
    int m_outdev;
    char m_bridge_str[128];
};

#endif
