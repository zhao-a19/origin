/*******************************************************************************************
*文件:    Cjmav.cpp
*描述:    江民病毒库
*
*作者:    赵子昂
*日期:    2020-05-06
*修改:    创建文件                            ------>     2020-05-06
*
*******************************************************************************************/
#define _CRT_SECURE_NO_WARNINGS
#include "Windows.h"
#include "tchar.h"
#include "ScanSimpleSDK.h"
#include "datatype.h"
#include "sysvirus.h"
#include "filename.h"
#include "mavapi.h"
#include "debugout.h"
#include "stringex.h"

CJMAV::CJMAV()
{

}

CJMAV::~CJMAV()
{
    if (pScan != NULL) {
        release();
    }
}
/**
 * [CJMAV::InitEngine 病毒库初始化]
 * @return
 */
void *CJMAV::InitEngine(void)
{
    char EnginePath[_FILEPATHMAX] = {0};
    make_filepath(VIRUS_PATH, "jmlib/lib64/libavemgr.so", EnginePath);
    ScanSetModPath(EnginePath);
    if ((pScan = ScanSimpleCreate()) == NULL) {
        PRINT_ERR_HEAD;
        print_err("Error: Init scanengine fail");
        printf("Init scanengine fail\n");
        return NULL;
    }

    return pScan;
}
/**
 * [CJMAV::release 释放资源]
 *
 */
void CJMAV::release(void)
{
    pScan->Dispose();
    ScanClean();
    pScan = NULL;
}
/**
 * [CJMAV::getversion 获取版本信息]
 * @return  []
 */
cpchar CJMAV::getversion(void)
{
    return ScanGetVersion();
}
/**
 * [CJMAV::setoptions 设置扫描选项]
 * @param bkill    [true:杀毒,false:查毒]
 * @param ziplevel [最大解压层数]
 * @param zipratio [解压文件时最大的压缩率，即压缩率大于该值则不再解压]
 */
void CJMAV::setoptions(bool bkill, uint32 ziplevel, uint32 zipratio)
{
    ScanOptions scanOptions{};
    memset(&scanOptions, 0, sizeof(scanOptions));
    scanOptions.m_dwSize = sizeof(scanOptions);
    scanOptions.m_dwFlags = scanUnpack | scanBackup | scanUnzip | scanUseFigner;
    scanOptions.m_handeMode = bkill ? modeCure : modeFind;
    scanOptions.m_unUnzipLevel = ziplevel;
    scanOptions.m_unMaxUnzipRatio = zipratio;
    pScan->SetOtpions(&scanOptions);

}
/**
 * [CJMAV::scanvirus 按文件路径查找病毒]
 * @param  filepath [文件路径]
 * @param  virus    [病毒名称]
 * @return          []
 */
bool CJMAV::scanvirus(const pchar filepath, pchar virus)
{
    setoptions(false, ZIPLEVEL, ZIPRATIO);
    return _scankill(filepath, 0, virus, true, false);
}
/**
 * [CJMAV::killvirus 按文件路径查杀病毒]
 * @param  filepath [文件路径]
 * @param  virus    [病毒名称]
 * @return          []
 */
bool CJMAV::killvirus(cpchar filepath, pchar virus)
{
    setoptions(true, ZIPLEVEL, ZIPRATIO);
    return _scankill(filepath, 0, virus, true, true);
}
/**
 * [CJMAV::scanvirus 按内存扫描病毒]
 * @param  buff  [内存]
 * @param  size  [空间大小]
 * @param  virus [病毒名称]
 * @return       []
 */
bool CJMAV::scanvirus(cpchar buff, uint32 size, pchar virus)
{
    setoptions(false, ZIPLEVEL, ZIPRATIO);
    return _scankill(buff, size, virus, false, false);
}
/**
 * [CJMAV::killvirus 按内存杀毒]
 * @param  buff  [内存]
 * @param  size  [空间大小]
 * @param  virus [病毒名称]
 * @return       []
 */
bool CJMAV::killvirus(cpchar buff, uint32 size, pchar virus)
{
    setoptions(true, ZIPLEVEL, ZIPRATIO);
    return _scankill(buff, size, virus, false, true);
}
/**
 * [CJMAV::scankillvirus 扫描接口]
 * @param  data  [任意数据类型]
 * @param  size  [空间大小]
 * @param  virus [病毒名称]
 * @param  bfile [是否为文件路径]
 * @param  bkill [保留参数]
 * @return       [description]
 */
bool CJMAV::_scankill(const void *data, uint32 size, pchar virus, bool bfile, bool bkill)
{

    if (bfile) {
        if (!is_file((char *)data)) return false;
    } else {
        if ((data == NULL) || (size == 0))   return false;
    }

    ScanResult result{};
    memset(&result, 0, sizeof(ScanResult));
    result.m_dwSize = sizeof(ScanResult);

    if (bfile) {
        if (!pScan->ScanFile((pchar )data, 0, &result)) {
            PRINT_ERR_HEAD;
            print_err("scanfile virus error");
        }
    } else {
        if (!pScan->ScanMemoryFile((void *)data, size, "", 0, &result)) {
            PRINT_ERR_HEAD;
            print_err("scanmem virus error");
        }
    }

    if (result.m_result != scanNormal) {
        strcpy(virus, result.m_szVirusName);
        if (bfile) {
            PRINT_DBG_HEAD;
            print_dbg("File: %s , Find Virus: %s , result: (%d)", (pchar)data, result.m_szVirusName, result.m_result);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("Find Virus: %s , result: (%d)", result.m_szVirusName, result.m_result);
        }
        return true;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("Not Find Virus!");
        return false;
    }

    return true;

}
