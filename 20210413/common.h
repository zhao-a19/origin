/*******************************************************************************************
*文件:  common.h
*描述:  通用函数类
*作者:  王君雷
*日期:  2016-03
*修改：     添加BASE64编解码函数                               ------> 20180102 王君雷
*           添加异或加解密函数                                 ------> 20180103 王君雷
*           添加ip2str函数                                     ------> 20180320
*           添加UnSortArray函数                                ------> 20180713
*           添加DelChar函数                                    ------> 20180724
*           添加Sysinfo函数                                    ------> 20180910
*           添加十六进制扩展还原、随机字符产生、分散存储和还原、
*           字符替换和还原相关函数，删除ChToHex等不使用的函数     ------> 20180919
*           添加FindString函数                                 ------> 20190216
*           添加ProcessRuning函数                              ------> 20190613
*           添加SpecialChar函数                                ------> 20200119 wjl
*           添加ProcessRuningCMD函数                           ------> 20200515 wjl
*           添加FileExist函数                                  ------> 20200902 wjl
*           添加GetStrMd5函数                                  ------> 20210507 wjl
*******************************************************************************************/
#ifndef __COMMON_H__
#define __COMMON_H__

const int E_COMM_OK = 1;
const int E_COMM_FALSE = -1;

class CCommon
{
public:
    CCommon(void);
    virtual ~CCommon(void);

    int wbstrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1);
    int casestrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1);
    int Binstrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1, int s2_len);
    int Search0D0A(unsigned char *pData, int nLen);
    void SmallToBig(unsigned char *packet, int begin, int end);
    int CharToHex(char input);
    //convert the ip from doted-decimal to hex
    int IpToHex(unsigned char *hexip, char *inputip);
    int AsscToDec(unsigned char *szHexBuff);

    //BASE64编解码
    int base64_encode(const unsigned char *indata, int datalen, char *buffout, int bufflen);
    int base64_decode(const char *indata, int datalen, unsigned char *buffout, int bufflen);

    void XOR(char *indata, int datalen, char keyword);
    char *ip2str(const int ip, char *ipstr);
    void UnSortArray(int a[], int n);
    void DelChar(char *data, char c);
    const char *Sysinfo(const char *cmd, char *out, int size);

    //字符串扩展为16进制字符串 及其逆过程
    int BinToHex(const char *input, int inputlen, char *output, int outlen);
    int HexToBin(const char *input, int inputlen, char *output, int outlen);

    //产生0~f的随机字符
    bool RandomHexChar(char *ch, int len);

    //分散存储 及其逆过程
    int DispersedStore(const char *effectdata, int effectlen, char *dst, int dstlen, int offset);
    int DispersedRetract(char *effectdata, int effectlen, const char *dst, int dstlen, int offset);

    //加密的一种方法 -- 字符替换 及其逆过程
    void CharReplace(char *info, int len);
    void CharReplaceReduct(char *info, int len);

    const char *FindString(const char *str,  int slen, int begin, const char *substr, int sublen, int &offsetlen);

    bool ProcessRuning(const char *proc);

    bool SpecialChar(const char *name, int len, char *nameout, int outlen);
    bool FileExist(const char *file);

    bool GetStrMd5(const char *name, char *nameout, int outlen);

private:
    bool ProcessRuningCMD(const char *cmd);
};

#endif
