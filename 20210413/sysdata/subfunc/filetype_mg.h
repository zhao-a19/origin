/*******************************************************************************************
*文件:  filetype_mg.h
*描述:  文件类型过滤管理
*作者:  王君雷
*日期:  2020-11-02
*修改:
*******************************************************************************************/
#ifndef __FILE_TYPE_MG_H__
#define __FILE_TYPE_MG_H__

using namespace std;
#include <string>
#include <vector>
#include <semaphore.h>
#include "critical.h"

class FileTypeMG
{
public:
    static FileTypeMG &GetInstance(void);
    virtual ~FileTypeMG(void);
    bool Filter(const char *fname, char *cherror);
    int ReadConf(void);
    int Size(void);

private:
    FileTypeMG(void);
    FileTypeMG(const FileTypeMG &other);
    FileTypeMG &operator=(const FileTypeMG &other);
    void InitLock(void);
    void Separate(void);

private:
    sem_t m_lock;
    int m_cktype;
    vector<string> m_filetype;
    char m_filetypestr[C_MAX_FILTERFILETYPE_LEN];
};

#endif
