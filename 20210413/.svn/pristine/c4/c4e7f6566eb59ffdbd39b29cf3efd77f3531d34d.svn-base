/*******************************************************************************************
*文件:    sysvirus.h
*描述:    病毒库
*
*作者:    张冬波
*日期:    2015-04-28
*修改:    创建文件                            ------>     2015-04-28
*         修改环境变量                        ------>     2015-05-07
*         添加安天引擎接口                    ------>     2017-12-17
*         添加江民引擎接口                    ------>     2020-07-15
*******************************************************************************************/
#ifndef __SYSVIRUS_H__
#define __SYSVIRUS_H__

#include "datatype.h"
#include "Ivirus.h"

#define _CRT_SECURE_NO_WARNINGS
#include "Windows.h"
#include "tchar.h"
#include "ScanSimpleSDK.h"

static cpchar VIRUS_PATHENV = "RAV_INSTALLPATH";                //瑞星引擎强制限制
static cpchar VIRUS_LOGENV = "RAV_LOGLEVEL";

#define ZIPLEVEL        20                                     // 江民病毒引擎 最大解压层数
#define ZIPRATIO        50                                     // 江民病毒引擎 解压文件时最大的压缩率，即压缩率大于该值则不再解压
#define VIRUS_PATH      "/initrd/viruslib/"
#define JM_VIRUS_PATH   "/lib64/"
#define MAX_VIR_FILE_PATH_LEN   2048
#define VERSION         12

/**
 * CLAMAV 病毒库
 */
class CCLAMAV: public IVIRUS
{
public:
    CCLAMAV();
    virtual ~CCLAMAV();

    void *InitEngine(void);
    void release(void);
    bool scanvirus(const pchar filepath, pchar virus);
    //bool killvirus(cpchar filepath, pchar virus);

    //bool scanvirus(cpchar buff, uint32 size, pchar virus);
    //bool killvirus(cpchar buff, uint32 size, pchar virus);

    cpchar getversion(void);
    static cpchar getversion(pchar user);

};

/**
 * 瑞星 病毒库
 */
class CRISINGAV: public IVIRUS
{
public:
    CRISINGAV();
    virtual ~CRISINGAV();

    void *InitEngine(void);
    void release(void);
    bool scanvirus(const pchar filepath, pchar virus);
    bool killvirus(cpchar filepath, pchar virus);

    bool scanvirus(cpchar buff, uint32 size, pchar virus);
    bool killvirus(cpchar buff, uint32 size, pchar virus);

    cpchar getversion(void);

private:
    /**
     * [_rising 病毒查杀]
     * @param  data  [数据地址or文件路径]
     * @param  size  [数据大小]
     * @param  virus [病毒类型，可为NULL]
     * @param  bfile [true 文件]
     * @param  bkill [true 杀毒]
     * @return       [true 成功]
     */
    bool _rising(const void *data, uint32 size, pchar virus, bool bfile, bool bkill);
    static long GetScanNumforMAV(void);
};

#if 0
/**
 * CAVL 安天病毒库
 */
class CAVL: public IVIRUS
{
public:
    CAVL();
    virtual ~CAVL();

    void *InitEngine(void);
    void release(void);
    bool scanvirus(cpchar filepath, pchar virus);
    //bool killvirus(cpchar filepath, pchar virus);

    bool scanvirus(cpchar buff, uint32 size, pchar virus);
    //bool killvirus(cpchar buff, uint32 size, pchar virus);

    cpchar getversion(void);

private:
    bool _avlscan(const void *data, uint32 size, pchar virus, bool bfile, cpchar filepath);

    void *m_NT;    //病毒名称翻译

};
#endif

#if 1
/**
 * 江民病毒库
 */

class CJMAV: public IVIRUS
{
public:
    CJMAV();
    virtual ~CJMAV();
    void *InitEngine(void);
    void release(void);
    bool scanvirus(const pchar filepath, pchar virus);
    bool killvirus(cpchar filepath, pchar virus);
    bool scanvirus(cpchar buff, uint32 size, pchar virus);
    bool killvirus(cpchar buff, uint32 size, pchar virus);
    cpchar getversion(void);

private:
    IScanSimple *pScan;
    bool _scankill(const void *data, uint32 size, pchar virus, bool bfile, bool bkill);
    void setoptions(bool bkill, uint32 ziplevel, uint32 zipratio);
};
#endif

#endif

