/*******************************************************************************************
*文件:  secway.cpp
*描述:  安全通道
*作者:  王君雷
*日期:  2018-12-29
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "define.h"
#include "debugout.h"
#include "secway.h"

SEC_WAY::SEC_WAY(void)
{
    BZERO(m_wayname);
    m_area = 0;
    m_indev = -1;
    m_outdev = -1;
}

/**
 * [SEC_WAY::SEC_WAY 构造函数]
 * @param  pwayname [通道名称]
 * @param  area     [通道方向]
 * @param  indev    [内网接口]
 * @param  outdev   [外网接口]
 */
SEC_WAY::SEC_WAY(const char *pwayname, int area, int indev, int outdev)
{
    setway(pwayname, area, indev, outdev);
}

SEC_WAY::~SEC_WAY(void)
{
}

/**
 * [SEC_WAY::setway 设置安全通道信息]
 * @param pwayname [安全通道名称]
 * @param area     [通道方向 内到外 or 外到内]
 * @param indev    [内网网口号]
 * @param outdev   [外网网口号]
 */
void SEC_WAY::setway(const char *pwayname, int area, int indev, int outdev)
{
    if ((pwayname == NULL) || (area < 0) || (indev < 0) || (outdev < 0)) {
        PRINT_ERR_HEAD
        print_err("set way.input para error[%s:%d:%d:%d]", pwayname, area, indev, outdev);
    } else {
        strncpy(m_wayname, pwayname, sizeof(m_wayname) - 1);
        m_area = area;
        m_indev = indev;
        m_outdev = outdev;
    }
}

/**
 * [SEC_WAY::equal 通道是否相同]
 * @param  area     [通道方向]
 * @param  indev    [内网接口]
 * @param  outdev   [外网接口]
 * @return          [相同返回true]
 */
bool SEC_WAY::equal(int area, int indev, int outdev)
{
    if ((area < 0) || (indev < 0) || (outdev < 0)) {
        PRINT_ERR_HEAD
        print_err("input para error[area:%d indev:%d outdev:%d]", area, indev, outdev);
        return false;
    } else {
        return (indev == m_indev) && (outdev == m_outdev) && (area == m_area);
    }
}

/**
 * [SEC_WAY::equal 判断通道是否相同]
 * @param  secway [通道对象的引用]
 * @return        [相同返回true]
 */
bool SEC_WAY::equal(SEC_WAY &secway)
{
    return (secway.m_indev == m_indev) && (secway.m_outdev == m_outdev) && (secway.m_area == m_area);
}

/**
 * [SEC_WAY::iptables_bridge 制作当前通道对应的iptables控制网口进出的串]
 * @param  binnet  [是否为内网]
 * @param  linklan [内部连接网口号]
 * @return         [返回字符串]
 */
const char *SEC_WAY::iptables_bridge(bool binnet, int linklan)
{
    char comelan[20] = {0}; //进口
    char golan[20] = {0}; //出口

    if (linklan < 0) {
        PRINT_ERR_HEAD
        print_err("linklan error[%d]", linklan);
        return NULL;
    }

    if (binnet) {
        if (m_area == 0) { //内到外
            INT_TO_CARDNAME(m_indev, comelan);
            sprintf(golan, "eth%d", linklan);
        } else { //外到内
            sprintf(comelan, "eth%d", linklan);
            INT_TO_CARDNAME(m_indev, golan);
        }
    } else {
        if (m_area == 0) { //内到外
            sprintf(comelan, "eth%d", linklan);
            INT_TO_CARDNAME(m_outdev, golan);
        } else { //外到内
            INT_TO_CARDNAME(m_outdev, comelan);
            sprintf(golan, "eth%d", linklan);
        }
    }
    return iptables_bridge(comelan, golan);
}

/**
 * [SEC_WAY::setarea 设置通道方向]
 * @param area [通道方向]
 */
void SEC_WAY::setarea(int area)
{
    m_area = area;
}

/**
 * [SEC_WAY::setindev 设置内网使用的接口]
 * @param dev [接口号]
 */
void SEC_WAY::setindev(int dev)
{
    if (dev < 0) {
        PRINT_ERR_HEAD
        print_err("set in dev,para error[%d]", dev);
    } else {
        m_indev = dev;
    }
}

/**
 * [SEC_WAY::setoutdev 设置外网使用的接口]
 * @param dev [接口号]
 */
void SEC_WAY::setoutdev(int dev)
{
    if (dev < 0) {
        PRINT_ERR_HEAD
        print_err("set out dev,para error[%d]", dev);
    } else {
        m_outdev = dev;
    }
}

/**
 * [SEC_WAY::getarea 获取通道方向]
 * @return  [通道方向]
 */
int SEC_WAY::getarea(void)
{
    return m_area;
}

/**
 * [SEC_WAY::getindev 获取 内网接口号]
 * @return  [接口号]
 */
int SEC_WAY::getindev(void)
{
    return m_indev;
}

/**
 * [SEC_WAY::getoutdev 获取 外网接口号]
 * @return  [接口号]
 */
int SEC_WAY::getoutdev(void)
{
    return m_outdev;
}

const char *SEC_WAY::getwayname(void)
{
    return m_wayname;
}

/**
 * [SEC_WAY::iptables_bridge 组装网桥iptables语句]
 * @param  comelan [进口]
 * @param  golan   [出口]
 * @return         [返回组装好的字符串]
 */
const char *SEC_WAY::iptables_bridge(const char *comelan, const char *golan)
{
    if ((comelan == NULL) || (golan == NULL)) {
        PRINT_ERR_HEAD
        print_err("comelan[%s] golan[%s] error", comelan, golan);
        return NULL;
    }
    snprintf(m_bridge_str, sizeof(m_bridge_str),
             "-m physdev --physdev-is-bridged --physdev-in %s --physdev-out %s", comelan, golan);
    return m_bridge_str;
}
