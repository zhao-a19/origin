/*******************************************************************************************
*文件:  FCLicenseMod.h
*描述:  模块授权相关操作类
*
*       文件加密协议如下：
*       SUGAP(5B) + 接口MAC(17B) + 模块掩码(32B)
*       对上述信息先异或加密，再BASE64编码
*       解码过程进行相反操作
*作者:  王君雷
*日期:  2018-01-03
*修改:
*******************************************************************************************/
#ifndef __FC_LICENSE_MOD_H__
#define __FC_LICENSE_MOD_H__

#include <stdio.h>
#include "define.h"

#define MOD_LICENSE_NUM  32 //最多支持32个模块的授权管理
#define MOD_LICENSE_HEAD "SUGAP"
#define MOD_LICENSE_FILE "/etc/httpd/sumod.cer" //模块授权证书文件
#define MOD_LICENSE_CONF "/etc/httpd/modcer.cf" //模块授权配置文件

class CLicenseMod
{
public:
    CLicenseMod(int ethno);
    ~CLicenseMod();
    bool readfile(const char *filename = MOD_LICENSE_FILE);
    bool license_exist(const char *filename = MOD_LICENSE_FILE); //模块授权文件是否存在
    bool create_license(const char *filename = MOD_LICENSE_FILE);//创建模块授权文件
    bool write_conf(const char *filename = MOD_LICENSE_CONF);    //把模块授权配置信息写入文件 文件不存在就创建
    bool have_right(int index);
    void set_right(int index, int right);

private:
    bool get_mac(int ethno);

private:
    bool m_readok;
    char m_mac[MAC_STR_LEN];
    char m_mod[MOD_LICENSE_NUM];
};

#endif
