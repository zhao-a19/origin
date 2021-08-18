/*******************************************************************************************
*文件:    platform.h
*描述:    硬件平台配置管理
*
*作者:    张冬波
*日期:    2015-06-08
*修改:    创建文件                            ------>     2015-06-08
*         增加字符集配置                      ------>     2015-09-15
*         默认带LCD显示                       ------>     2017-03-31
*         添加申威平台支持                    ------>     2017-05-27
*         统一端口管理                        ------>     2017-07-27
*         添加视频通道                        ------>     2019-07-27
*
*******************************************************************************************/
#ifndef __PLATFORM_H__
#define __PLATFORM_H__

/**
 * 安盟平台
 */
#ifdef SU_UNIGAP_XXX

#define __USE_LCD__
#define LCD_PORT "/dev/ttyS1"

#else
#endif

/**
 * 申威平台
 */
#ifdef SW_UNIGAP_XXX
#else
#endif

/**
 *  内外网通讯
 */
#define SU_DEVOUTER_IP  "1.0.0.1"
#define SU_DEVINNER_IP  "1.0.0.2"

#define SU_DEVINNER_PORT_FERRYD 65525
#define SU_DEVINNER_PORT_FERRYC 65526
#define SU_DEVINNER_PORT_HA     65527
#define SU_DEVINNER_PORT_TCP    65528
#define SU_DEVINNER_PORT_UDP    65529
#define SU_DEVINNER_PORT_VLC    65200

#define is_sysport(p) ((SU_DEVINNER_PORT_UDP == (p)) || (SU_DEVINNER_PORT_TCP == (p)) ||  \
        (SU_DEVINNER_PORT_FERRYD == (p)) || (SU_DEVINNER_PORT_FERRYC == (p)) || \
        (SU_DEVINNER_PORT_HA == (p)))


/**
 * 系统字符集
 */
#define SU_SYSCHARSET   "CP936"
#define SU_SYSCHARGBK   "GBK"
#endif

