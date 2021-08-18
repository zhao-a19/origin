
/*******************************************************************************************
*文件:    fileoperator.cpp
*描述:    重构之前实现，继承CSYSCFG，保留所有外部接口
*
*作者:    张冬波
*日期:    2015-01-07
*修改:    创建文件                            ------>     2015-01-07
*         修改打开文件接口                    ------>     2015-03-18
*         修改文件类型bug                     ------>     2015-05-08
*         修复文件类型判断错误bug             ------>     2015-09-09
*         修复文件类型判断错误bug, EXE&DLL    ------>     2016-12-05
*         OpenFile使用strcmp判断打开方式      ------>     2020-07-03 wjl
*******************************************************************************************/
#include "datatype.h"
#include "stringex.h"
#include "filename.h"
#include "fileoperator.h"

/*******************************************************************************************
*功能:    构造
*参数:
*
*注释:
*******************************************************************************************/
CFILEOP::CFILEOP()
{

}

/*******************************************************************************************
*功能:    析构
*参数:
*
*注释:
*******************************************************************************************/
CFILEOP::~CFILEOP()
{
    CloseFile();
}

/*******************************************************************************************
*功能:    打开文件
*参数:    FileDirName             ---->   文件路径
*         chpar                   ---->   fopen的第二个参数
*         cfg                     ---->   系统配置文件
*         返回值                  ---->   E_FILE_OK 成功
*
*注释:
*******************************************************************************************/
int CFILEOP::OpenFile(const char *FileDirName, char *chpar, bool cfg)
{
    if ((FileDirName == NULL) || (chpar == NULL))  return false;

    if ((strcmp(chpar, "r") == 0) || (strcmp(chpar, "rb") == 0)) {
        return this->open(FileDirName, true, cfg) ? E_FILE_OK : E_FILE_FALSE;
    }
    return this->open(FileDirName, false) ? E_FILE_OK : E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    创建一个新文件
*参数:    FileDirName             ---->   文件路径
*         返回值                  ---->   E_FILE_OK 成功
*
*注释:
*******************************************************************************************/
int CFILEOP::CreateNewFile(char *FileDirName)
{
    char cmd[_FILEPATHMAX + 20] = {0};

    sprintf(cmd, "rm -f \"%s\"", FileDirName);         //强制删除当前文件
    system(cmd);

    return OpenFile(FileDirName, "w+");
}

/*******************************************************************************************
*功能:    获取文件大小
*参数:    返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::PutFileSize()
{
    if (fop == NULL)    return E_FILE_FALSE;

    fseek(fop, 0, SEEK_END);
    return ftell(fop);
}

/*******************************************************************************************
*功能:    写入文件
*参数:    p_chValue               ---->   写入数据
*         iValueLen               ---->   数据长度
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::WriteFile(const unsigned char *p_chValue, int iValueLen)
{
    if ((fop != NULL) && (p_chValue != NULL) && (iValueLen > 0)) {
        if (ByteWrite(iWritePos, p_chValue, iValueLen) == E_FILE_OK) {
            iWritePos = iWritePos + iValueLen;
            return E_FILE_OK;
        }
    }

    return E_FILE_FALSE;

}

/*******************************************************************************************
*功能:    读取文件
*参数:    p_chValue               ---->   读出数据
*         iValueLen               ---->   数据长度
*         返回值                  ---->   有效数据长度，E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::ReadFile(unsigned char *p_chValue, int iValueLen)
{
    if ((fop != NULL) && (p_chValue != NULL) && (iValueLen > 0)) {

        int k = ByteRead(iReadPos, p_chValue, iValueLen);

        iReadPos = iReadPos + iValueLen;

        if (k < iValueLen)  iReadPos = 0;       //文件尾部

        return k;
    }

    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    写文件结束
*参数:    返回值                  ---->   文件大小，E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::WriteFileEnd()
{
    if (fop == NULL )   return E_FILE_FALSE;

    int iFileSize;

    fseek(fop, 0, SEEK_END);
    iFileSize = ftell(fop);

    CloseFile();
    return iFileSize;
}


/*******************************************************************************************
*功能:    判断文件类型，分析头数据
*参数:    data                    ---->   数据
*         返回值                  ---->   文件类型 E_FILE_OK表示其他类型
*
*注释:
*         E_CFILEOP_ZIP 为ZIP包
*         E_CFILEOP_RAR 为RAR包
*         E_CFILEOP_EXE 为EXE
*         E_CFILEOP_LINUX_EXE 为EXE
*         E_CFILEOP_DLL 为DLL
*
*******************************************************************************************/
//文件类型定义
static const uint8 Pe_Head[4] = {0x50, 0x45, 0x00, 0x00};
static const uint8 Dos_Head[2] = {0x4D, 0x5A};
static const uint8 Rar_Head[7] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
static const uint8 Zip_Head[4] = {0x50, 0x4B, 0x03, 0x04};
static const uint8 Lin_Exe_Head[7] = {0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01};
static const uint8 Ne_Head[2] = {0x4E, 0x45};

#pragma pack(push, 1)
/**
 * Windows PE File Format
 */
struct IMAGE_DOS_HEADER {
    uint16 e_magic;
    uint16 e_cblp;
    uint16 e_cp;
    uint16 e_crlc;
    uint16 e_cparhdr;
    uint16 e_minalloc;
    uint16 e_maxalloc;
    uint16 e_ss;
    uint16 e_sp;
    uint16 e_csum;
    uint16 e_ip;
    uint16 e_cs;
    uint16 e_lfarlc;
    uint16 e_ovno;
    uint16 e_res[4];
    uint16 e_oemid;
    uint16 e_oeminfo;
    uint16 e_res2[10];
    uint32 e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16 Machine;
    uint16 NumberOfSections;
    uint32 TimeDateStamp;
    uint32 PointerToSymbolTable;
    uint32 NumberOfSymbols;
    uint16 SizeOfOptionalHeader;
    uint16 Characteristics;
#define IMAGE_FILE_EXECUTABLE_IMAGE   (1<<1)
#define IMAGE_FILE_DLL                (1<<13)

};

struct IMAGE_NT_HEADERS {
    uint32 Signature;
    struct IMAGE_FILE_HEADER FileHeader;
    //OptionalHeader ignored
};

struct NE_FILE_HEADER {
    uint8 LinkVerMajor;
    uint8 LinkVerMinor;
    uint16 EntryOffset;
    uint16 EntrySize;
    uint32 Reserved_1;
    uint16 ModelFlag;
#define NE_FILE_DLL                ((1<<15)|1)
    uint16 DGROUPseg;
    uint16 InitLocalHeapSize;
    uint16 InitStackSize;
    uint16 InitIP;
    uint16 InitCS;
    uint16 InitSP;
    uint16 InitSS;
    uint16 SegTableEntrys;
    uint16 ModelRefEntrys;
    uint16 NoResdNameTableSize;
    uint16 SegTableOffset;
    uint16 ResourceOffset;
    uint16 ResdNameTableOffset;
    uint16 ModelRefOffset;
    uint16 InputNameTableOffset;
    uint32 NoResdNameTableOffset;
    uint16 MovableEntrys;
    uint16 SegStartOffset;
    uint16 ResTableEntrys;
    uint8 OperatingSystem;
    uint8 ExtFlag;
    uint16 FLAOffsetBySector;
    uint16 FLASectors;
    uint16 Reserved_2;
    uint16 ReqWindowsVer;
};

struct IMAGE_NE_HEADERS {
    uint16 Signature;
    struct NE_FILE_HEADER FileHeader;
};
#pragma pack(pop)

#define _GETTYPE_(d, h, r) {if(memcmp(d, h, sizeof(h)) == 0) return r;}

int CFILEOP::Analyse_File(const unsigned char *data, int len)
{
    if (data == NULL)  return E_FILE_FALSE;

    _GETTYPE_(data, Zip_Head, E_CFILEOP_ZIP);
    _GETTYPE_(data, Rar_Head, E_CFILEOP_RAR);
    _GETTYPE_(data, Lin_Exe_Head, E_CFILEOP_LINUX_EXE);

    if (memcmp(data, Dos_Head, sizeof(Dos_Head)) == 0) {
        struct IMAGE_DOS_HEADER dos;

        memcpy(&dos, data, sizeof(dos));
        if (memcmp(data + dos.e_lfanew, Pe_Head, sizeof(Pe_Head)) == 0) {
            //PE格式
            struct IMAGE_NT_HEADERS pe;
            memcpy(&pe, data + dos.e_lfanew, sizeof(pe));

            if (pe.FileHeader.Characteristics & IMAGE_FILE_DLL) return E_CFILEOP_DLL;
            if (pe.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) return E_CFILEOP_EXE;
        } else if (memcmp(data + dos.e_lfanew, Ne_Head, sizeof(Ne_Head)) == 0) {
            //NE格式
            struct IMAGE_NE_HEADERS ne;
            memcpy(&ne, data + dos.e_lfanew, sizeof(ne));
            if ((ne.FileHeader.ModelFlag & NE_FILE_DLL) == NE_FILE_DLL) return E_CFILEOP_DLL;
            return E_CFILEOP_EXE;   //暂时按EXE处理
        }

    }

    return E_FILE_OK;
}

/*******************************************************************************************
*功能:    判断文件类型
*参数:    返回值                  ---->   文件类型 E_FILE_OK表示其他类型
*
*注释:
*
*******************************************************************************************/
int CFILEOP::PutFileType()
{
    uint8 buff[TMPBUFFMAX] = {0};

    if (ByteRead(0, buff, sizeof(buff)) == E_FILE_OK) {
        return Analyse_File((const puint8)buff, sizeof(buff));
    }
    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    读取文件
*参数:    iFirstPos               ---->   文件位置
*         p_chValue               ---->   读出数据
*         iValueLen               ---->   数据长度
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::ByteRead(int iFirstPos, unsigned char *p_chValue, int iValueLen)
{

    if ((fop != NULL) && (p_chValue != NULL) && (iValueLen > 0)) {
        int k = 0;
        memset(p_chValue, 0, iValueLen);
        fseek(fop, iFirstPos, SEEK_SET);

        k = fread(p_chValue, 1, iValueLen, fop);
        if (k > 0)  return E_FILE_OK;
        if (feof(fop) != 0) return E_FILE_OK;
    }

    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    写入文件
*参数:    iFirstPos               ---->   文件位置
*         p_chValue               ---->   读出数据
*         iValueLen               ---->   数据长度
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::ByteWrite(int iFirstPos, const unsigned char *p_chValue, int iValueLen)
{
    if ((fop != NULL) && (p_chValue != NULL) && (iValueLen > 0)) {

        fseek(fop, iFirstPos, SEEK_SET);
        if (fwrite(p_chValue, 1, iValueLen, fop) == (size_t)iValueLen) {

            return E_FILE_OK;
        }
    }

    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    读取配置信息
*参数:    ItemName                ---->   父项名
*         SubItemName             ---->   子项名
*         ReturnValue             ---->   结果字符串
*         iReSize                 ---->   有效长度
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::ReadCfgFile(const char *ItemName, const char *SubItemName, char *ReturnValue, int iReSize)
{
    pchar p;

    if ((p = getitem((const pchar)ItemName, (const pchar)SubItemName)) != NULL) {

        memset(ReturnValue, 0, iReSize);
        strncpy(ReturnValue, p, iReSize - 1);
        return E_FILE_OK;
    }
    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    读取配置信息(数值型)
*参数:    ItemName                ---->   父项名
*         SubItemName             ---->   子项名
*         RetValue                ---->   整数
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::ReadCfgFileInt(const char *ItemName, const char *SubItemName, int *RetValue)
{
    if (RetValue != NULL) {
            //读取字符转化为整数
        if (getitem((const pchar)ItemName, (const pchar)SubItemName, (int32 &)(*RetValue)))   return E_FILE_OK;
    }

    return E_FILE_FALSE;
}

/*******************************************************************************************
*功能:    写入配置信息
*参数:    ItemName                ---->   父项名
*         SubItemName             ---->   子项名
*         SubItemValue            ---->   子项内容
*         返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::WriteCfgFile(const char *ItemName, const char *SubItemName, const char *SubItemValue)
{
    if (SubItemValue != NULL) {
        if (setitem((const pchar)ItemName, (const pchar)SubItemName, (const pchar)SubItemValue)) return  E_FILE_OK;
    }

    return E_FILE_FALSE;
}

int CFILEOP::WriteCfgFileInt(const char *ItemName, const char *SubItemName, int ItemValue)
{
    char buff[64] = {0};
    sprintf(buff, "%d", ItemValue);
    return WriteCfgFile(ItemName, SubItemName, buff);
}

/*******************************************************************************************
*功能:    关闭文件
*参数:    返回值                  ---->   E_FILE_FALSE 错误
*
*注释:
*******************************************************************************************/
int CFILEOP::CloseFile()
{
    return this->close() ? E_FILE_OK : E_FILE_FALSE;
}

bool CFILEOP::Equal(CFILEOP &obj)
{
    return *((CSYSCFG *)this) == *((CSYSCFG *)&obj);
}

bool CFILEOP::FindDiff(const CFILEOP &obj, map<string, bool> &cmp, bool &other, bool bfuzzy)
{

    return this->finddiff(*((CSYSCFG *)&obj), cmp, other, bfuzzy);
}


