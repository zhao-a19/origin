/*************************************************************************************
*文件名: common.cpp
*创建人:罗来庚
*日  期:2002-12-20
*描  述:控制层
*
*版  本:V1.0
*修改：     添加BASE64编解码函数                               ------> 20180102 王君雷
*           添加异或加解密函数                                 ------> 20180103 王君雷
*           添加ip2str函数                                     ------> 20180320
*           添加UnSortArray函数                                ------> 20180713
*           添加DelChar函数                                    ------> 20180724
*           添加Sysinfo函数                                    ------> 20180910
*           添加十六进制扩展还原、随机字符产生、分散存储和还原、
*           字符替换和还原相关函数，删除ChToHex等不使用的函数  ------> 20180919
*           添加FindString函数                                 ------> 20190216
*           添加ProcessRuning函数                              ------> 20190613
*           Sysinfo函数返回字符串去掉回车换行符                ------> 20200116 wjl
*           添加SpecialChar函数                                ------> 20200119 wjl
*           添加ProcessRuningCMD函数                           ------> 20200515 wjl
*           修改DelChar中的错误                                ------> 20210324 wjl
***************************************************************************************/
#include "common.h"
#include "debugout.h"
#include <math.h>
#include <errno.h>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const char *g_base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//使用字符替换加密时 会用到这个表
struct rep_chars {
    char before;
    char after;
} g_char_replace_table[] = {
    {'0', '9'},
    {'1', '5'},
    {'2', '6'},
    {'3', '0'},
    {'4', 'f'},
    {'5', '7'},
    {'6', 'e'},
    {'7', 'a'},
    {'8', '4'},
    {'9', '3'},
    {'a', 'b'},
    {'b', '2'},
    {'c', '8'},
    {'d', 'c'},
    {'e', 'd'},
    {'f', '1'},
};

CCommon::CCommon(void)
{

}

CCommon::~CCommon(void)
{

}

/**
 * [CCommon::SmallToBig 把字符串指定区域小写字母替换为大写]
 * @param packet     [字符串]
 * @param begin      [开始替换的位置]
 * @param end        [结束替换的位置]
 */
void CCommon::SmallToBig(unsigned char *packet, int begin, int end)
{
    for (int i = begin; i < end; i++) {
        if ((packet[i] >= 'a') && (packet[i] <= 'z')) {
            packet[i] -= 'a' - 'A';
        }
    }
}

/**
 * [CCommon::CharToHex 把一个16进制表示的字符转换为对应整数]
 * @param  input [16进制表示的字符]
 * @return       [字符对应的整数值]
 */
int CCommon::CharToHex(char input)
{
    if ((input >= '0') && (input <= '9')) {
        return input - '0';
    } else if ((input >= 'a') && (input <= 'f')) {
        return input - 'a' + 10;
    } else if ((input >= 'A') && (input <= 'F')) {
        return input - 'A' + 10;
    } else {
        printf("input error[%d]\n", input);
        return 0;
    }
}

/*****************************************************************
** 函数名:wbstrstr
** 输  入:
** 输  出:
** 功能描述: 查找字符串s1从第n到n1中是否有s2
** 全局变量:无
** 调用模块:
** 作  者:杨功柱
** 日  期:03-04-03
** 修  改:
** 日  期:
** 版本：V1.0
****************************************************************/
int CCommon::wbstrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1)
{
    unsigned long s2Len;

    s2Len = strlen((char *)s2);
    if (s2Len == 0) {
        return E_COMM_OK;
    }
    if ((int)s2Len > n1 - n) {
        return E_COMM_FALSE;
    }
    for (int i = n; i <= (n1 - (int)s2Len); i ++) {
        if (memcmp(s1 + i, s2, s2Len) == 0) {
            return E_COMM_OK;
        }
    }
    return E_COMM_FALSE;
}

/*****************************************************************
** 函数名:casestrstr
** 输  入:
** 输  出:
** 功能描述: 查找字符串s1从第n到n1中是否有s2，不区分大小写
** 全局变量:无
** 调用模块:
** 作  者:杨功柱
** 日  期:03-04-03
** 修  改:
** 日  期:
** 版本：V1.0
****************************************************************/
int CCommon::casestrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1)
{
    unsigned long s2Len;

    s2Len = strlen((char *)s2);
    if (s2Len == 0) {
        return E_COMM_OK;
    }
    if ((int)s2Len > n1 - n) {
        return E_COMM_FALSE;
    }
    for (int i = n; i <= (n1 - (int)s2Len); i ++) {
        if (strncasecmp((char *)(s1 + i), (char *)s2, s2Len) == 0) {
            return E_COMM_OK;
        }
    }
    return E_COMM_FALSE;
}

/*****************************************************************
** 函数名:IpToHex
** 输  入:
** 输  出:
** 功能描述:
** 全局变量:无
** 调用模块:
** 作  者:
** 日  期:
** 修  改:
** 日  期:
** 版本：V1.0
****************************************************************/
int CCommon::IpToHex(unsigned char *hexip, char *inputip)
{
    int seck = 0, bitn = 1, len = strlen(inputip);
    double fang = 0.0, base = 0x10;

    for (int i = 0; i < len; i++) {
        if (inputip[i] != '.') {
            hexip[seck] = hexip[seck] + CharToHex(inputip[i] * bitn);
            bitn = (int)pow(base, fang);
            fang++;
        } else {
            seck++;
            bitn = 0;
        }
    }

    return E_COMM_OK;
}

/*****************************************************************
** 函数名:Search0D0A
** 输  入: 查找源，查找源长度
** 输  出: E_COMM_FALSE 或0D0A的位置
** 功能描述:查找0D0A的位置
** 全局变量:无
** 调用模块:
** 作  者:张大伟
** 日  期:030809
** 版本：V1.0
****************************************************************/
int CCommon::Search0D0A(unsigned char *pData, int nLen)
{
    char tmpBuf[2] = {0x0D, 0x0A};
    for (int i = 0; i <= nLen - 2; i ++) {
        if (memcmp(pData + i, tmpBuf, 2) == 0) {
            return i;
        }
    }
    return E_COMM_FALSE;
}

/*****************************************************************
** 函数名:AsscToDec
** 输  入:ASSCII串
** 输  出:
** 功能描述:ASCII值转换为十进制数
** 全局变量:
** 调用模块:
** 作  者:
** 日  期:
** 修  改:
** 日  期:
** 版本:V1.0
****************************************************************/
int CCommon::AsscToDec(unsigned char *szHexBuff)
{
    int nLen = strlen((char *)szHexBuff);
    int nTmp;
    int nResult = 0;
    for (int i = 0; i < nLen; i ++) {
        switch (szHexBuff[i]) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            nTmp = szHexBuff[i] - 48;
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            nTmp = szHexBuff[i] - 55;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            nTmp = szHexBuff[i] - 87;
            break;
        default:
            return E_COMM_FALSE;
        }
        nResult = nResult << 4 | nTmp;
    }
    return nResult;
}

/*****************************************************************
** 函数名:Binstrstr
** 输  入:
** 输  出:
** 功能描述: 查找字符串s1从第n到n1中是否有s2,s2len为s2的长度
** 全局变量:无
** 调用模块:
** 作  者:杨功柱
** 日  期:03-04-03
** 修  改:
** 日  期:
** 版本：V1.0
****************************************************************/
int CCommon::Binstrstr(const unsigned char *s1, const unsigned char *s2, int n, int n1, int s2_len)
{
    int s2Len = s2_len;
    if (s2Len == 0) {
        return E_COMM_OK;
    }
    if (s2Len > n1 - n) {
        return E_COMM_FALSE;
    }
    for (int i = n; i <= (n1 - s2Len); i ++) {
        if (memcmp(s1 + i, s2, s2Len) == 0) {
            return E_COMM_OK;
        }
    }

    return E_COMM_FALSE;
}

/**
 * [CCommon::base64_encode 对输入数据进行BASE64编码]
 * @param  indata  [输入的待编码的数据]
 * @param  datalen [输入数据的长度]
 * @param  buffout [输出缓冲区]
 * @param  bufflen [输出缓冲区的长度]
 * @return         [失败返回-1 成功返回编码后的数据的长度]
 */
int CCommon::base64_encode(const unsigned char *indata, int datalen, char *buffout, int bufflen)
{
    int i, j;
    unsigned char current = 0;

    //计算编码后的长度应该为多少
    int enlen = 0;
    if ((datalen % 3) == 0) {
        enlen = datalen / 3 * 4;
    } else {
        enlen = datalen / 3 * 4 + 4;
    }

    if (bufflen < enlen) {
        printf("%s[%d]buff too short! bufflen=%d, datalen=%d\n",
               __FUNCTION__, __LINE__, bufflen, datalen);
        return -1;
    }

    for (i = 0, j = 0; i < datalen ; i += 3) {
        current = (indata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        buffout[j++] = g_base64char[(int)current];

        current = ( (unsigned char)(indata[i] << 4)) & ( (unsigned char)0x30) ;
        if (i + 1 >= datalen) {
            buffout[j++] = g_base64char[(int)current];
            buffout[j++] = '=';
            buffout[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(indata[i + 1] >> 4)) & ( (unsigned char) 0x0F);
        buffout[j++] = g_base64char[(int)current];

        current = ( (unsigned char)(indata[i + 1] << 2)) & ( (unsigned char)0x3C) ;
        if (i + 2 >= datalen) {
            buffout[j++] = g_base64char[(int)current];
            buffout[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(indata[i + 2] >> 6)) & ( (unsigned char) 0x03);
        buffout[j++] = g_base64char[(int)current];

        current = ( (unsigned char)indata[i + 2]) & ( (unsigned char)0x3F) ;
        buffout[j++] = g_base64char[(int)current];
    }
    return j;
}

/**
 * [CCommon::base64_decode 对输入数据进行BASE64解码]
 * @param  indata  [输入的待解码的数据]
 * @param  datalen [输入数据的长度]
 * @param  buffout [输出缓冲区]
 * @param  bufflen [输出缓冲区的长度]
 * @return         [失败返回-1 成功返回解码后的数据的长度]
 */
int CCommon::base64_decode(const char *indata, int datalen, unsigned char *buffout, int bufflen)
{
    int i = 0, j = 0;
    unsigned char k = 0;
    unsigned char temp[4];

    //要求被解码的数据长度是4的倍数
    if ((datalen < 0) || (datalen % 4 != 0)) {
        printf("%s[%d]datalen wronge %d\n", __FUNCTION__, __LINE__, datalen);
        return -1;
    }

    //判断输出缓冲区够不够长
    if (bufflen < datalen / 4 * 3) {
        printf("%s[%d]bufflen too short[%d], must be more than %d\n",
               __FUNCTION__, __LINE__, bufflen, datalen / 4 * 3);
        return -1;
    }

    //判断有没有不准出现的字符
    for (i = 0; i < datalen; i++) {
        if (indata[i] == '=') {
            continue;
        }

        bool flag = false;
        for (j = 0; j < (int)strlen(g_base64char); j++) {
            if (g_base64char[j] == indata[i]) {
                flag =  true;
                break;
            }
        }
        if (!flag) {
            printf("%s[%d]invalid char[%d]\n", __FUNCTION__, __LINE__, indata[i]);
            return -1;
        }
    }

    for (i = 0, j = 0; i < datalen; i += 4) {
        memset(temp, 0xFF, sizeof(temp));
        for (k = 0 ; k < 64 ; k ++) {
            if (g_base64char[k] == indata[i]) {
                temp[0] = k;
                break;
            }
        }
        for (k = 0 ; k < 64 ; k ++) {
            if (g_base64char[k] == indata[i + 1]) {
                temp[1] = k;
            }
        }
        for (k = 0 ; k < 64 ; k ++) {
            if (g_base64char[k] == indata[i + 2]) {
                temp[2] = k;
            }
        }
        for (k = 0 ; k < 64 ; k ++) {
            if (g_base64char[k] == indata[i + 3]) {
                temp[3] = k;
            }
        }

        buffout[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2)) & 0xFC)) |
                       ((unsigned char)((unsigned char)(temp[1] >> 4) & 0x03));
        if (indata[i + 2] == '=') {
            break;
        }

        buffout[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4)) & 0xF0)) |
                       ((unsigned char)((unsigned char)(temp[2] >> 2) & 0x0F));
        if (indata[i + 3] == '=') {
            break;
        }

        buffout[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6)) & 0xF0)) |
                       ((unsigned char)(temp[3] & 0x3F));
    }
    return j;
}

/**
 * [CCommon::XOR 对数据进行异或加解密]
 * @param indata  [待加解密的数据  既是输入又是输出]
 * @param datalen [数据长度]
 * @param keyword [进行异或的字符]
 */
void CCommon::XOR(char *indata, int datalen, char keyword)
{
    if (indata != NULL) {
        for (int i = 0; i < datalen; i++) {
            indata[i] ^= keyword;
        }
    }
}

/**
 * [CCommon::ip2str IP地址转换]
 * @param  ip    [地址]
 * @param  ipstr [格式化字符串，可为NULL]
 * @return       [字符串首地址]
 */
char *CCommon::ip2str(const int ip, char *ipstr)
{
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = ip;

    if (ipstr != NULL) {
        strcpy(ipstr, inet_ntoa(addr.sin_addr));
        return (char *)ipstr;
    }

    return inet_ntoa(addr.sin_addr);
}

/**
 * [CCommon::UnSortArray 把数组的元素随机打乱]
 * @param a [数组名称]
 * @param n [数组元素个数]
 */
void CCommon::UnSortArray(int a[], int n)
{
    int index, tmp;
    srand(time(NULL));

    for (int i = 0; i < n; ++i) {
        index = rand() % (n - i) + i;
        if (index != i) {
            tmp = a[i];
            a[i] = a[index];
            a[index] = tmp;
        }
    }
}

/**
 * [CCommon::DelChar 把字符串data中的字符c去除掉]
 * @param data [待处理的字符串，既是入参又是出参]
 * @param c    [待去除的字符]
 */
void CCommon::DelChar(char *data, char c)
{
    if (data == NULL) { return; }

    int len = strlen(data);
    int j = 0;

    char *tmp = (char *)malloc(len + 1);
    if (tmp == NULL) {
        return ;
    }
    memset(tmp, 0, len + 1);

    for (int i = 0; i < len; i++) {
        if (data[i] != c) {
            tmp[j++] = data[i];
        }
    }
    strcpy(data, tmp);
    free(tmp);
}

/**
 * [CCommon::Sysinfo 通过系统命令获取信息]
 * @param  cmd  [命令]
 * @param  out  [输出信息]
 * @param  size [输出缓冲区长度]
 * @return      [失败返回NULL]
 */
const char *CCommon::Sysinfo(const char *cmd, char *out, int size)
{
    if ((cmd != NULL) && (strcmp(cmd, "") != 0) && (out != NULL)) {

        FILE *pp;
        memset(out, 0, size);
        if ((pp = popen(cmd, "r")) != NULL) {
            if (fgets(out, size, pp) != NULL) {
                if ((strcmp(out, "") == 0)
                    || (strstr(out, "No such file or directory") != NULL)) {
                    out = NULL;
                } else {
                    int len = strlen(out);
                    for (int i = 0; i < len; ++i) {
                        if (out[i] == '\r' || out[i] == '\n') {
                            out[i] = '\0';
                            break;
                        }
                    }
                }
            } else {
                out = NULL;
            }
            pclose(pp);
        } else {
            out = NULL;
        }
        return out;
    }

    return NULL;
}

/**
 * [CCommon::BinToHex 把二进制字符串转换为可见字符的字符串，比如 "ab" 转换为 "6162"]
 * @param  input    [输入字符串]
 * @param  inputlen [输入长度]
 * @param  output   [输出字符串]
 * @param  outlen   [输出缓冲区长度]
 * @return          [成功返回转换后的长度 失败返回负值]
 */
int CCommon::BinToHex(const char *input, int inputlen, char *output, int outlen)
{
    if ((input == NULL) || (output == NULL) || (inputlen <= 0) || (outlen < inputlen * 2)) {
        printf("bin to hex para error\n");
        return -1;
    }

    memset(output, 0, outlen);

    char tmp[3] = {0};
    unsigned char c = 0;
    for (int i = 0; i < inputlen; i++) {
        c = input[i];
        sprintf(tmp, "%02x", c);
        memcpy(output + i * 2, tmp, 2);
    }

    return inputlen * 2;
}

/**
 * [CCommon::HexToBin 把可见字符串（由0~9 a~f组成） 转换为二进制字符串]
 * @param  input    [输入字符串]
 * @param  inputlen [输入长度]
 * @param  output   [输出字符串]
 * @param  outlen   [输出缓冲区长度]
 * @return          [成功返回转换后的长度 失败返回负值]
 */
int CCommon::HexToBin(const char *input, int inputlen, char *output, int outlen)
{
    if ((input == NULL) || (output == NULL) || (inputlen <= 0)
        || (inputlen % 2 != 0) || (outlen < inputlen / 2)) {
        printf("hex to bin para error\n");
        return -1;
    }

    int j = 0;
    for (int i = 0; i < inputlen; i += 2) {
        output[j++] = CharToHex(input[i]) * 16 + CharToHex(input[i + 1]);
    }
    return j;
}

/**
 * [CCommon::RandomHexChar 生成随机字符（0~f）]
 * @param ch      [字符指针]
 * @param len     [大小]
 * @return        [成功返回true]
 */
bool CCommon::RandomHexChar(char *ch, int len)
{
    if ((ch == NULL) || (len < 0)) {
        printf("random char para error\n");
        return false;
    }

    char chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                      'a', 'b', 'c', 'd', 'e', 'f'
                     };
    srand(time(NULL));

    for (int i = 0; i < len; i++) {
        ch[i] = chars[rand() % 16];
    }

    return true;
}

/**
 * [CCommon::DispersedStore 分散存储]
 * @param  effectdata [有效信息]
 * @param  effectlen  [有效信息长度]
 * @param  dst        [目的存储字符串]
 * @param  dstlen     [目的存储字符串长度]
 * @param  offset     [偏移量]
 * @return            [成功返回有效信息长度 失败返回负值]
 */
int CCommon::DispersedStore(const char *effectdata, int effectlen, char *dst, int dstlen, int offset)
{
    if ((effectdata == NULL) || (dst == NULL) || (effectlen <= 0) || (dstlen <= 0) || (offset < 0)) {
        printf("store para error\n");
        return -1;
    }

    //目的存储字符串按输入偏移之后 剩下的长度不能小于有效数据的2倍
    if (dstlen - offset < effectlen * 2 ) {
        printf("dstlen[%d] offset[%d] effectlen[%d],para error\n", dstlen, offset, effectlen);
        return -1;
    }

    for (int i = 0; i < effectlen; i++) {
        dst[offset + i * 2] = effectdata[i];
    }
    return effectlen;
}

/**
 * [CCommon::DispersedRetract 从分散存储的内容中取回有效数据]
 * @param  effectdata [有效数据  出参]
 * @param  effectlen  [有效数据长度]
 * @param  dst        [分散存储的字符串]
 * @param  dstlen     [分散存储的字符串长度]
 * @param  offset     [偏移量]
 * @return            [成功返回有效信息长度 失败返回负值]
 */
int CCommon::DispersedRetract(char *effectdata, int effectlen, const char *dst, int dstlen, int offset)
{
    if ((effectdata == NULL) || (dst == NULL) || (effectlen <= 0) || (dstlen <= 0) || (offset < 0)) {
        printf("retract para error\n");
        return -1;
    }

    //目的存储字符串按输入偏移之后 剩下的长度不能小于有效数据的2倍
    if (dstlen - offset < effectlen * 2 ) {
        printf("dstlen[%d] offset[%d] effectlen[%d],retract para error\n", dstlen, offset, effectlen);
        return -1;
    }

    for (int i = 0; i < effectlen; i++) {
        effectdata[i] = dst[offset + i * 2];
    }

    return effectlen;
}

/**
 * [CCommon::CharReplace 字符置换]
 * @param info [待处理的信息]
 * @param len  [待处理的信息长度]
 */
void CCommon::CharReplace(char *info, int len)
{
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < (int)(sizeof(g_char_replace_table) / sizeof(g_char_replace_table[0])); j++) {
            if (info[i] == g_char_replace_table[j].before) {
                info[i] = g_char_replace_table[j].after;
                break;
            }
        }
    }

    return;
}

/**
 * [CCommon::CharReplaceReduct 字符置换还原]
 * @param info [待处理的信息]
 * @param len  [待处理的信息长度]
 */
void CCommon::CharReplaceReduct(char *info, int len)
{
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < (int)(sizeof(g_char_replace_table) / sizeof(g_char_replace_table[0])); j++) {
            if (info[i] == g_char_replace_table[j].after) {
                info[i] = g_char_replace_table[j].before;
                break;
            }
        }
    }

    return;
}

/**
 * [CCommon::FindString 查找字符串子串]
 * @param  str       [字符串]
 * @param  slen      [字符串长度]
 * @param  begin     [开始查找的位置]
 * @param  substr    [被查的字符串子串]
 * @param  sublen    [子串长度]
 * @param  offsetlen [查找到的位置 相对于str的偏移 当查找成功时有意义]
 * @return           [查找成功返回位置指针 失败返回NULL]
 */
const char *CCommon::FindString(const char *str,  int slen, int begin,
                                const char *substr, int sublen, int &offsetlen)
{
    if ((str == NULL) || (substr == NULL) || (slen <= 0) || (sublen <= 0) || (begin >= slen)) {
        return NULL;
    }
    for (int i = begin; i <= slen - sublen; ++i) {
        if (memcmp(str + i, substr, sublen) == 0) {
            offsetlen = i;
            return str + i;
        }
    }
    return NULL;
}

/**
 * [CCommon::ProcessRuning 判断进程是否在运行]
 * @param  proc [进程名]
 * @return      [运行返回true]
 */
bool CCommon::ProcessRuning(const char *proc)
{
    if (proc == NULL) {
        return false;
    }
    char chcmd1[1024] = {0};
    char chcmd2[1024] = {0};
    snprintf(chcmd1, sizeof(chcmd1), "ps |grep %s|grep -v grep|wc -l", proc);
    snprintf(chcmd2, sizeof(chcmd2), "ps -ef|grep %s|grep -v grep|wc -l", proc);

    return (ProcessRuningCMD(chcmd1) || ProcessRuningCMD(chcmd2));
}

/**
 * [CCommon::ProcessRuningCMD 判断进程是否在运行]
 * @param  cmd  [测试用命令]
 * @return      [运行返回true]
 */
bool CCommon::ProcessRuningCMD(const char *cmd)
{
    if (cmd == NULL) {
        return false;
    }
    char chout[128] = {0};
    if (Sysinfo(cmd, chout, sizeof(chout)) != NULL) {
        return (atoi(chout) > 0);
    }
    return false;
}

/**
 * [CCommon::SpecialChar 处理特殊字符 防止插入DB时出错]
 * @param  name    [待处理的字符串]
 * @param  len     [字符串长度]
 * @param  nameout [输出缓冲区]
 * @param  outlen  [缓冲区长度]
 * @return         [成功返回true]
 */
bool CCommon::SpecialChar(const char *name, int len, char *nameout, int outlen)
{
    if ((name == NULL) || (nameout == NULL) || (len < 0) || (outlen < len)) {
        return false;
    }
    memset(nameout, 0, outlen);
    char *p = nameout;

    for (int i = 0; i < len; ++i) {
        switch (name[i]) {
        case '\'':
        case '\"':
        case '%':
        case '\\':
            *p++ = '\\';
        default:
            *p++ = name[i];
            break;
        }
    }
    return true;
}

/**
 * [CCommon::FileExist 判断文件是否存在]
 * @param  file [文件]
 * @return      [存在返回true]
 */
bool CCommon::FileExist(const char *file)
{
    if ((file == NULL) || (strlen(file) == 0)) {
        PRINT_ERR_HEAD
        print_err("para err[%s]", file);
        return false;
    }

    struct stat buf;
    if (stat(file, &buf) < 0) {
        PRINT_INFO_HEAD
        print_info("stat fail[%s][%s]", file, strerror(errno));
        return false;
    }

    if (S_ISREG(buf.st_mode)) {
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("not reg file[%s]", file);
        return false;
    }
}

/**
 * [CCommon::GetStrMd5 计算一个字符串对应的md5，会自动在字符串后加回车符后计算]
 * @param  name    [待计算的字符串]
 * @param  nameout [md5字符串 出参]
 * @param  outlen  [出参缓冲区长度]
 * @return         [成功返回true]
 */
bool CCommon::GetStrMd5(const char *name, char *nameout, int outlen)
{
    bool _ret = false;
    PRINT_DBG_HEAD
    print_dbg("%s", name);

    char chcmd[1024] = {0};
    snprintf(chcmd, sizeof(chcmd), "echo %s|md5sum|cut -d\" \" -f0", name);
    memset(nameout, 0, outlen);

    if (Sysinfo(chcmd, nameout, outlen) == NULL) {
        PRINT_ERR_HEAD
        print_err("chcmd[%s] fail", chcmd);
    } else {
        if (strlen(nameout) == 32) {
            PRINT_INFO_HEAD
            print_info("name[%s] namemd5[%s]", name, nameout);
            _ret = true;
        } else {
            PRINT_ERR_HEAD
            print_err("name[%s] namemd5[%s]", name, nameout);
        }
    }
    return _ret;
}
