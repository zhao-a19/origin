/*******************************************************************************************
*文件:  FC4BytesSingle.cpp
*描述:  4bytes模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       响应信息只允许为1Byte，值为0或1                              ------> 2019-07-30
*******************************************************************************************/
#include "FC4BytesSingle.h"
#include "debugout.h"

C4BYTESSINGLE::C4BYTESSINGLE()
{
}

C4BYTESSINGLE::~C4BYTESSINGLE()
{
}

bool C4BYTESSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool C4BYTESSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/**
 * [C4BYTESSINGLE::DoDstMsg 处理响应信息]
 * @param  sdata   [IP开头的数据包]
 * @param  slen    [长度]
 * @param  cherror [出错信息 出参]
 * @return         [允许通过返回true]
 */
bool C4BYTESSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    //SYN,FIN,ACK等允许通过
    if (datalen <= 0) {
        return true;
    }

    if ((datalen == 1)
        && ((sdata[hdlen] == 0x00) || (sdata[hdlen] == 0x01))) {
        return true;
    } else {
        RecordCallLog(sdata, "", "", MULTI_BYTE_PASS, false);
        PRINT_ERR_HEAD
        print_err("1bit model transfer [%d]Byte value[%d]", datalen, sdata[hdlen]);
        return false;
    }
}
