/*******************************************************************************************
*文件:  FCLicenseMod.cpp
*描述:  模块授权相关操作类
*作者:  王君雷
*日期:  2018-01-03
*修改:
*       添加函数set_right                         ------> 2018-02-05
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "FCLicenseMod.h"
#include "common.h"
#include "define.h"
#include "fileoperator.h"

CLicenseMod::CLicenseMod(int ethno)
{
    m_readok = false;
    memset(m_mac, 0, sizeof(m_mac));
    memset(m_mod, 1, sizeof(m_mod));//默认值为1
    get_mac(ethno);
}

CLicenseMod::~CLicenseMod()
{
}

/*******************************************************************************************
*描述:  获取网卡号为ethno的网卡的mac 取出的mac存放到成员变量m_mac
*作者:  王君雷
*日期:  2018-01-03
*参数:
*修改:
*******************************************************************************************/
bool CLicenseMod::get_mac(int ethno)
{
    if (ethno < 0) {
        printf("%s[%d] para error![%d]\n", __FUNCTION__, __LINE__, ethno);
        return false;
    }

    char device[32] = {0};
    sprintf(device, "eth%d", ethno);

    unsigned char macaddr[6];
    struct ifreq req;

    int s = socket(AF_INET, SOCK_DGRAM, 0); //internet协议族的数据报类型套接口
    if (s < 0) {
        perror("socket");
        printf("%s[%d]socket error!\n", __FUNCTION__, __LINE__);
        return false;
    }
    strcpy(req.ifr_name, device); //将设备名作为输入参数传入
    int err = ioctl(s, SIOCGIFHWADDR, &req); //执行取MAC地址操作
    close(s);

    if (err != -1) {
        memcpy(macaddr, req.ifr_hwaddr.sa_data, ETH_ALEN); //取输出的MAC地址
        sprintf(m_mac, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
                macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
        return true;
    }

    return false;
}

/*******************************************************************************************
*描  述:  读取模块授权文件信息
*作  者:  王君雷
*日  期:  2018-01-03
*参  数:  filename           模块授权文件
*修  改:
*返回值:
*         读取成功返回true
*******************************************************************************************/
bool CLicenseMod::readfile(const char *filename)
{
    CCommon common;
    char readbuf[1024] = {0};//存放从文件读取出的信息
    char decodebuff[1024] = {0};//存放解码后的信息

    //打开文件
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("%s[%d]fopen[%s] fail!\n", __FUNCTION__, __LINE__, filename);
        return false;
    }

    //读取文件
    int rlen = fread(readbuf, 1, sizeof(readbuf), fp);
    if (rlen < 0) {
        printf("%s[%d]fread[%s] fail!\n", __FUNCTION__, __LINE__, filename);
        fclose(fp);
        fp = NULL;
        return false;
    }

    //关闭文件
    fclose(fp);
    fp = NULL;

    //BASE64解码
    int dlen = common.base64_decode((const char *)readbuf, rlen, (unsigned char *)decodebuff, sizeof(decodebuff));
    if (dlen < 5 + 17 + MOD_LICENSE_NUM) {
        printf("%s[%d]license invalid(%d)\n", __FUNCTION__, __LINE__, dlen);
        return false;
    }

    //异或解密
    common.XOR(decodebuff, dlen, MOD_LICENSE_KEY);

    //校验头部
    if (memcmp(decodebuff, MOD_LICENSE_HEAD, 5) != 0) {
        printf("%s[%d]license invalid!\n", __FUNCTION__, __LINE__);
        return false;
    }

    //校验MAC
    if (memcmp(decodebuff + 5, m_mac, 17) != 0) {
        printf("%s[%d]license invalid!!\n", __FUNCTION__, __LINE__);
        return false;
    }

    //校验模块掩码信息
    for (int i = 0; i < MOD_LICENSE_NUM; i++) {
        //如果出现0和1之外的值 则认为非法
        if ((decodebuff[5 + 17 + i] != 0) && (decodebuff[5 + 17 + i] != 1)) {
            printf("%s[%d]license invalid(%d)!!!\n", __FUNCTION__, __LINE__, decodebuff[5 + 17 + i]);
            return false;
        }
    }
    memcpy(m_mod, decodebuff + 5 + 17, MOD_LICENSE_NUM);

    m_readok = true;
    return true;
}

/*******************************************************************************************
*描  述:  返回模块授权文件是否存在
*作  者:  王君雷
*日  期:  2018-01-03
*参  数:  filename  模块授权文件
*修  改:
*返回值:
*         存在返回true
*******************************************************************************************/
bool CLicenseMod::license_exist(const char *filename)
{
    if (filename == NULL) {
        printf("%s[%d]para null\n", __FUNCTION__, __LINE__);
        return false;
    }
    struct stat buf;
    if (stat(filename, &buf) < 0) {
        return false;
    }

    if (S_ISREG(buf.st_mode)) {
        return true;
    } else {
        printf("不是普通文件!\n");
        return false;
    }
}

/*******************************************************************************************
*描  述:  创建模块授权文件
*作  者:  王君雷
*日  期:  2018-01-03
*参  数:  filename  模块授权文件
*修  改:
*返回值:
*         成功返回0
*******************************************************************************************/
bool CLicenseMod::create_license(const char *filename)
{
    if (filename == NULL) {
        printf("%s[%d]para null\n", __FUNCTION__, __LINE__);
        return false;
    }
    CCommon common;
    char tmpbuff[1024];
    char encodebuff[1024];//存放编码后的信息
    memset(tmpbuff, 0, sizeof(tmpbuff));
    memset(encodebuff, 0, sizeof(encodebuff));

    //按协议组串
    memcpy(tmpbuff, MOD_LICENSE_HEAD, 5);
    memcpy(tmpbuff + 5, m_mac, 17);
    memcpy(tmpbuff + 5 + 17, m_mod, MOD_LICENSE_NUM);
    int bufflen = 5 + 17 + MOD_LICENSE_NUM;

    //异或加密
    common.XOR(tmpbuff, bufflen, MOD_LICENSE_KEY);

    //BASE64编码
    int enlen = common.base64_encode((const unsigned char *)tmpbuff, bufflen, encodebuff, sizeof(encodebuff));
    if (enlen < 0) {
        printf("%s[%d]base64_encode fail!\n", __FUNCTION__, __LINE__);
        return false;
    }

    //打开文件
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("%s[%d]fopen[%s] fail!\n", __FUNCTION__, __LINE__, filename);
        return false;
    }

    //写入文件
    int wlen = fwrite(encodebuff, 1, enlen, fp);
    if (wlen != enlen) {
        printf("%s[%d]fwrite[%s] fail![%d]\n", __FUNCTION__, __LINE__, filename, wlen);
        fclose(fp);
        fp = NULL;
        return false;
    }

    //关闭文件
    fclose(fp);
    fp = NULL;

    m_readok = true;
    return true;
}

/*******************************************************************************************
*描  述:  把模块授权配置信息写入文件 文件不存在就创建
*作  者:  王君雷
*日  期:  2018-01-03
*参  数:  filename  模块授权配置文件路径
*修  改:
*返回值:
*         成功返回true
*******************************************************************************************/
bool CLicenseMod::write_conf(const char *filename)
{
    if (filename == NULL) {
        printf("%s[%d]para null\n", __FUNCTION__, __LINE__);
        return false;
    }

    char subitem[64];
    char value[10];

    CFILEOP fileop;
    int ret = fileop.OpenFile(filename, "w+");
    if (ret != E_FILE_OK) {
        printf("%s[%d]open file fail![%s]\n", __FUNCTION__, __LINE__, filename);
        return false;
    }

    for (int i = MOD_LICENSE_NUM - 1; i >= 0 ; i--) {
        memset(subitem, 0, sizeof(subitem));
        sprintf(subitem, "MOD%d", i);
        if (m_mod[i] == 0) {
            strcpy(value, "0");
        } else {
            strcpy(value, "1");
        }

        fileop.WriteCfgFile("SYSTEM", subitem, value);
        printf("%s[%d]%s %s\n", __FUNCTION__, __LINE__, subitem, value);
    }

    fileop.CloseFile();
    return true;
}

/*******************************************************************************************
*描  述:  判断模块有没有授权
*作  者:  王君雷
*日  期:  2018-01-08
*参  数:  index   模块对应的下标
*                 范围 0 ~ MOD_LICENSE_NUM-1
*修  改:
*返回值:
*         成功返回true
*******************************************************************************************/
bool CLicenseMod::have_right(int index)
{
    if ((index >= 0) && (index <= MOD_LICENSE_NUM - 1)) {
        if (m_readok) {
            return (m_mod[index] == 1);
        }
    }
    return false;
}

/*******************************************************************************************
*描  述:  设置模块授权
*作  者:  王君雷
*日  期:  2018-02-05
*参  数:  index   模块对应的下标
*                 范围 0 ~ MOD_LICENSE_NUM-1
*          right  权限
*修  改:
*返回值:
*         成功返回true
*******************************************************************************************/
void CLicenseMod::set_right(int index, int right)
{
    if ((index >= 0) && (index <= MOD_LICENSE_NUM - 1)) {
        m_mod[index] = right;
    }
}
