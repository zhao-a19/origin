/*******************************************************************************************
*文件:    sip_record.cpp
*描述:    SIP通道记录
*
*作者:    张冬波
*日期:    2018-04-24
*修改:    创建文件                                                     ------> 2018-04-24
*         修改程序，在网闸中使用                                       ------> 2018-07-19 王君雷
*         记录数超过最大支持值20000时，删除vec元素同时，也删除对应的iptables
*                                                                      ------> 2018-08-02
*******************************************************************************************/
#include "datatype.h"
#include "debugout.h"
#include <vector>
#include "sip_record.h"

using namespace std;
#pragma pack(push, 1)

typedef struct _sipdatax {
    char name[64];
    char recvip[16];    //光闸接收IP:PORT
    uint16 recvport;
    char sendip[16];    //光闸发送IP
    char srvip[16];     //视频服务IP:PORT
    uint16 srvport;
} SIPDATAX, *PSIPDATAX;

#pragma pack(pop)

static vector<SIPDATAX> sipch;
static const pchar recfile_default = "/initrd/data/sipch.dat";
static uint32 siptotal = 0;

vector<SIPDATAX> sipvec;

/**
 * [sipload 读取记录]
 * @param  recpath [记录文件路径]
 * @return         [记录总数]
 */
int32 sipload(const pchar recpath)
{
#if SIP_NOREC
    return 0;
#else
    FILE *fop;
    pchar filepath = recpath;
    sipch.clear();

    if (filepath == NULL) { filepath = recfile_default; }

    if ((fop = fopen(filepath, "rd")) != NULL) {

        SIPDATAX data;
        while (fread(&data, 1, sizeof(data), fop) ==  sizeof(data)) {
            sipch.push_back(data);
        }

        fclose(fop);

        PRINT_DBG_HEAD;
        print_dbg("SIPREC %s = %d", filepath, sipch.size());
        siptotal = sipch.size();
        return sipch.size();
    }

    PRINT_DBG_HEAD;
    print_dbg("SIPREC %s = %d", filepath, sipch.size());
    return 0;
#endif
}

/**
 * [sipsave 保存记录]
 * @param  recpath [记录文件路径]
 * @return         [记录总数，-1失败]
 */
int32 sipsave(const pchar recpath)
{
#if SIP_NOREC
    return 0;
#else
    char tmp[100];
    pchar filepath = recpath;

    if (filepath == NULL) { filepath = recfile_default; }

    sprintf(tmp, "%s.tmp", filepath);

    //写入临时文件
    FILE *fop;
    if ((fop = fopen(tmp, "wb")) != NULL) {

        vector<SIPDATAX>::iterator data = sipch.begin();

        while (data != sipch.end()) {
            fwrite(data->name, 1, sizeof(SIPDATAX), fop);
            data++;
        }
        fclose(fop);

        //更新文件
        rename(tmp, filepath);

        PRINT_DBG_HEAD;
        print_dbg("SIPREC %s = %d", filepath, sipch.size());
        return sipch.size();
    }

    PRINT_ERR_HEAD;
    print_err("SIPREC %s = %d", filepath, sipch.size());
    return -1;
#endif
}

/**
 * [sipgetone 读取一条记录，结合sipload使用]
 * @param  idx  [记录索引]
 * @param  data [记录内容]
 * @return      [记录索引，-1失败]
 */
int32 sipgetone(int32 idx, void *data)
{
#if SIP_NOREC
    return idx;
#else
    if ((idx < sipch.size()) && (data != NULL)) {

        *((PSIPDATAX)data) = sipch[idx];
        PRINT_DBG_HEAD;
        print_dbg("SIPREC ONE %s", ((PSIPDATAX)data)->name);
        return idx;
    }

    PRINT_ERR_HEAD;
    print_err("SIPREC %d = %d", idx, sipch.size());
    return -1;
#endif
}

/**
 * [sipaddone 添加一条记录]
 * @param  data [记录内容]
 * @return      [true成功]
 */
bool sipaddone(void *data)
{
#if SIP_NOREC
    return true;
#else
    if (data == NULL) { return false; }

    PRINT_DBG_HEAD;
    print_dbg("SIPREC ADD %s = %d", ((PSIPDATAX)data)->name, ++siptotal);
    if (sipch.size() > 20000) {

        //删除旧记录
        PRINT_DBG_HEAD;
        print_dbg("SIPREC OVERLOAD");

        sipch[siptotal % 20000 - 1] = *((PSIPDATAX)data);

        return true;
    }
    sipch.push_back(*((PSIPDATAX)data));
    return true;
#endif
}

/**
 * [sipaddone 添加一条记录]
 * @param  data [记录内容]
 * @return      [true成功]
 */
bool sipaddone2(void *data)
{
    void sipdel(PSIPDATAX data);

    if (data == NULL) { return false; }
    if (sipvec.size() > 20000) {
        SIPDATAX datatmp;
        datatmp = *sipvec.begin();
        sipdel(&datatmp);
        sipvec.erase(sipvec.begin());
    }
    sipvec.push_back(*((PSIPDATAX)data));
    return true;
}

/**
 * [sipdelone 删除记录]
 * @param  data   [记录内容]
 * @param  bclear [true清除所有]
 * @return        [true成功]
 */
bool sipdelone(void *data, bool bclear)
{
#if SIP_NOREC
    return true;
#else
    if (bclear) {
        sipch.clear();
        PRINT_DBG_HEAD;
        print_dbg("SIPREC CLEAR = %d", sipch.size());
        return true;
    }

    if (data == NULL) { return false; }

    PRINT_DBG_HEAD;
    print_dbg("SIPREC DEL %s", ((PSIPDATAX)data)->name);

    vector<SIPDATAX>::iterator dr = sipch.begin();
    while (dr != sipch.end()) {
        PSIPDATAX _data = (PSIPDATAX)data;
        if ((strcmp(dr->name, _data->name) == 0) &&
            (strcmp(dr->recvip, _data->recvip) == 0) && (dr->recvport == _data->recvport) &&
            (strcmp(dr->srvip, _data->srvip) == 0) && (dr->srvport == _data->srvport) &&
            (strcmp(dr->sendip, _data->sendip) == 0)) {
            sipch.erase(dr);
            return true;
        }
        dr++;
    }

    PRINT_DBG_HEAD;
    print_dbg("SIPREC DEL %s", ((PSIPDATAX)data)->name);
    return false;
#endif
}

/**
 * [sipdelone 删除记录]
 * @param  data   [记录内容]
 * @return        [true成功]
 */
bool sipdelone2(void *data)
{
    if (data == NULL) { return false; }
    vector<SIPDATAX>::iterator dr = sipvec.begin();
    while (dr != sipvec.end()) {
        PSIPDATAX _data = (PSIPDATAX)data;
        if ((strcmp(dr->name, _data->name) == 0) &&
            (strcmp(dr->recvip, _data->recvip) == 0) && (dr->recvport == _data->recvport) &&
            (strcmp(dr->srvip, _data->srvip) == 0) && (dr->srvport == _data->srvport) &&
            (strcmp(dr->sendip, _data->sendip) == 0)) {
            sipvec.erase(dr);
            return true;
        }
        dr++;
    }
    return false;
}
