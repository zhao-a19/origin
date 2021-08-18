/*******************************************************************************************
*文件:    fileoperator.h
*描述:    重构之前实现，继承CSYSCFG，保留所有外部接口
*
*作者:    张冬波
*日期:    2015-01-07
*修改:    创建文件                            ------>     2015-01-07
*         修改打开文件接口                    ------>     2015-03-18
*         添加函数WriteCfgFileInt             ------>     2020-07-03 wjl
*******************************************************************************************/
#ifndef __FILEOPERATOR_H__
#define __FILEOPERATOR_H__
#include "datatype.h"
#include "syscfg.h"

//原有定义
const int E_CFILEOP_ZIP          = -101;
const int E_CFILEOP_RAR          = -102;
const int E_CFILEOP_LINUX_EXE    = -103;
const int E_CFILEOP_DLL          = -104;
const int E_CFILEOP_EXE          = -105;
const int E_FILE_OK = 1;
const int E_FILE_FALSE = -1;

class  CFILEOP: private CSYSCFG
{
public:
    CFILEOP();
    virtual ~CFILEOP();

public:
    //打开目标文件
    int OpenFile(const char *FileDirName, char *chpar = "r", bool cfg = false);

    //创建文件
    int CreateNewFile(char *FileDirName);

    //写文件生数据
    int WriteFile(const unsigned char *p_chValue, int iValueLen);

    //读文件生数据若文件结束则返回结束标志
    int ReadFile(unsigned char *p_chValue, int iValueLen);

    //写文件结束
    int WriteFileEnd();

    //输出文件大小
    int PutFileSize();

    //输出文件类型
    int PutFileType();

    //按字节读
    int ByteRead(int iFirstPos, unsigned char *p_chValue, int iValueLen);
    //按字节写
    int ByteWrite(int iFirstPos, const unsigned char *p_chValue, int iValueLen);

    //收索目标串
    //int SearchTxt(const unsigned char *chDestTxt, int iTxtLen);

    //按格式读配置文件（ini)子项
    int ReadCfgFile(const char *ItemName, const char *SubItemName, char *ReturnValue, int iReSize);

    //按格式读配置文件（ini)整型子项
    int ReadCfgFileInt(const char *ItemName, const char *SubItemName, int *RetValue);

    //按格式写配置文件子项
    int WriteCfgFile(const char *ItemName, const char *SubItemName, const char *SubItemValue);

    int WriteCfgFileInt(const char *ItemName, const char *SubItemName, int ItemValue);

    //关闭文件
    int CloseFile();

    bool Equal(CFILEOP &obj);
    bool FindDiff(const CFILEOP &obj, map<string, bool> &cmp, bool &other, bool bfuzzy = false);


private:
    int iWritePos;
    int iReadPos;

    //分析是否为ZIP RAR EXE DLL文件类型
    int Analyse_File(const unsigned char *data, int len);

    //int SearchDestKeyPos(const unsigned char *DestKey, int KeyLen, const unsigned char *SrcData, int nLen);
};

#endif
