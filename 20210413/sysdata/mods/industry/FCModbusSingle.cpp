/*******************************************************************************************
*文件:  FCModbusSingle.cpp
*描述:  MODBUS模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       支持功能码和值域的控制                            ------> 2017-10-01
*******************************************************************************************/
#include <stdlib.h>
#include "FCModbusSingle.h"

#define strempty(s) (strcmp(s, "") == 0)

CMODBUSSINGLE::CMODBUSSINGLE()
{
    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));
}

CMODBUSSINGLE::~CMODBUSSINGLE()
{
}

bool CMODBUSSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        return DoDstMsg(sdata, slen, cherror);
    }
}

const char *CMODBUSSINGLE::GetRFCString(const char* chcodeid)
{
    if (chcodeid == NULL)
    {
        printf("%s[%d]para null\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    switch (atoi(chcodeid))
    {
    case COIL_R:
        strcpy(m_chcmd, "读线圈"); return m_chcmd;
    case BIT_R:
        strcpy(m_chcmd, "读离散量输入"); return m_chcmd;
    case REGHD_R:
        strcpy(m_chcmd, "读保持寄存器"); return m_chcmd;
    case REGIN_R:
        strcpy(m_chcmd, "读输入寄存器"); return m_chcmd;
    case COIL_W:
        strcpy(m_chcmd, "写单个线圈"); return m_chcmd;
    case REG_W:
        strcpy(m_chcmd, "写单个寄存器"); return m_chcmd;
    case COIL_WM:
        strcpy(m_chcmd, "写多个线圈"); return m_chcmd;
    case REG_WM:
        strcpy(m_chcmd, "写多个寄存器"); return m_chcmd;
    case FILE_R:
        strcpy(m_chcmd, "读文件记录"); return m_chcmd;
    case FILE_W:
        strcpy(m_chcmd, "写文件记录"); return m_chcmd;
    case REG_MASK:
        strcpy(m_chcmd, "屏蔽写寄存器"); return m_chcmd;
    case REG_RW:
        strcpy(m_chcmd, "读写多个寄存器"); return m_chcmd;
    case DEV_R:
        strcpy(m_chcmd, "读设备识别码"); return m_chcmd;
    default:
        strcpy(m_chcmd, chcodeid); return m_chcmd;
    }
}

bool CMODBUSSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0)
    {
        return true;
    }

    memset(m_chcmd, 0, sizeof(m_chcmd));
    memset(m_chpara, 0, sizeof(m_chpara));

    //校验长度
    if (datalen <= MODBUSMBAP_LEN + 1)
    {
        sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, datalen);
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return false;
    }

    //协议号检查  应该为0
    if ((sdata[hdlen + 2] != 0x00) || (sdata[hdlen + 3] != 0x00))
    {
        sprintf(cherror, "%s", MODBUS_PROTO_ERROR);
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return false;
    }

    //得到功能码
    char chcodeid[10];
    memset(chcodeid, 0, sizeof(chcodeid));
    sprintf(chcodeid, "%d", sdata[hdlen + MODBUSMBAP_LEN]);

    //功能码是否合法
    if ((sdata[hdlen + MODBUSMBAP_LEN] > 127)
        || (sdata[hdlen + MODBUSMBAP_LEN] < 1))
    {
        sprintf(cherror, "%s[%d]", MODBUS_FUNC_CODE_ERROR, sdata[hdlen + MODBUSMBAP_LEN]);
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
        return false;
    }

    //根据功能码 得到汉语描述
    GetRFCString(chcodeid);

    if (FilterCode(chcodeid, sdata + hdlen, slen - hdlen, cherror))
    {
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, true);
        return true;
    }
    else
    {
        RecordCallLog(sdata, m_chcmd, m_chpara, cherror, false);
        return false;
    }
}

bool CMODBUSSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

/*******************************************************************************************
*功能:  过滤功能码以及值域
*参数:
*       chcodeid   功能码
*       sdata      应用层数据
*       slen       应用层数据长度
*       cherror    出错信息  出参
*注释:
*******************************************************************************************/
bool CMODBUSSINGLE::FilterCode(const char *chcodeid, unsigned char *sdata, int slen, char *cherror)
{
    int para_sec_l = 0;//参数区间左值
    int para_sec_r = 0;//参数区间右值
    int data_sec_l = 0;//数据包区间左值
    int data_sec_r = 0;//数据包区间右值
    int value_sec_l = 0;//值区间左值
    int value_sec_r = 0;//值区间右值

    switch (atoi(chcodeid))
    {
    case COIL_R://1
    case BIT_R://2
    case REGHD_R://3
    case REGIN_R://4
    case COIL_WM://15

        {
            if (slen < MODBUSMBAP_LEN + 5)
            {
                sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, slen);
                return false;
            }

            //取得数据包的地址区间
            GetDataSection(sdata, data_sec_l, data_sec_r);
            sprintf(m_chpara, "地址[%d-%d]", data_sec_l, data_sec_r);

            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    //如果没有写参数 就按匹配所有处理
                    if (strempty(m_service->m_cmd[i]->m_parameter))
                    {
                        if (!m_service->m_cmd[i]->m_action)
                        {
                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                        }
                        return m_service->m_cmd[i]->m_action;
                    }

                    //取得命令的地址区间
                    if (GetParaSection(m_service->m_cmd[i]->m_parameter, para_sec_l, para_sec_r))
                    {
                        if (m_service->m_cmd[i]->m_action)
                        {
                            //允许的命令
                            if ((data_sec_l >= para_sec_l) && (data_sec_r <= para_sec_r))
                            {
                                return true;
                            }
                        }
                        else
                        {
                            //拒绝的命令
                            if (!((data_sec_l > para_sec_r) || (data_sec_r < para_sec_l)))
                            {
                                sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                                return false;
                            }
                        }
                    }//GetParaSection
                }//if
            }//for
            break;
        }
    case COIL_W://5
    case REG_W://6
        {
            if (slen < MODBUSMBAP_LEN + 5)
            {
                sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, slen);
                return false;
            }

            //取得数据包的单个地址
            int addr = sdata[MODBUSMBAP_LEN + 1] * 256 + sdata[MODBUSMBAP_LEN + 2] + 1;

            //取得数据包的输出值
            int outval = sdata[MODBUSMBAP_LEN + 3] * 256 + sdata[MODBUSMBAP_LEN + 4];
            if (atoi(chcodeid) == COIL_W)
            {
                sprintf(m_chpara, "地址[%d]值[%s]", addr, (outval == 0) ? "off":"on");
            }
            else if (atoi(chcodeid) == REG_W)
            {
                sprintf(m_chpara, "地址[%d]值[%d]", addr, outval);
            }

            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    //如果没有写参数 就按匹配所有处理
                    if (strempty(m_service->m_cmd[i]->m_parameter))
                    {
                        if (!m_service->m_cmd[i]->m_action)
                        {
                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                        }
                        return m_service->m_cmd[i]->m_action;
                    }

                    //取得命令的地址区间
                    if (GetParaSection(m_service->m_cmd[i]->m_parameter, para_sec_l, para_sec_r))
                    {
                        //地址匹配
                        if ((addr >= para_sec_l) && (addr <= para_sec_r))
                        {
                            //如果没有值参数 就按匹配所有处理
                            if (strempty(m_service->m_cmd[i]->m_sign))
                            {
                                if (!m_service->m_cmd[i]->m_action)
                                {
                                    sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                                }
                                return m_service->m_cmd[i]->m_action;
                            }

                            //取得配置文件中值的区间
                            if (GetValueSection(m_service->m_cmd[i]->m_cmd,
                                m_service->m_cmd[i]->m_sign, value_sec_l, value_sec_r))
                            {
                                //值匹配
                                if ((outval >= value_sec_l) && (outval <= value_sec_r))
                                {
                                    if (!m_service->m_cmd[i]->m_action)
                                    {
                                        sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                                    }
                                    return m_service->m_cmd[i]->m_action;
                                }
                            }//GetValueSection
                        }//地址匹配
                    }
                }//if 功能码匹配
            }//for
            break;
        }
    case REG_WM://16
        {
            if (slen < MODBUSMBAP_LEN + 5)
            {
                sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, slen);
                return false;
            }

            //取得数据包的地址区间
            GetDataSection(sdata, data_sec_l, data_sec_r);
            sprintf(m_chpara, "地址[%d-%d]", data_sec_l, data_sec_r);

            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    //如果没有写参数 就按匹配所有处理
                    if (strempty(m_service->m_cmd[i]->m_parameter))
                    {
                        if (!m_service->m_cmd[i]->m_action)
                        {
                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                        }
                        return m_service->m_cmd[i]->m_action;
                    }

                    //取得命令的地址区间
                    if (GetParaSection(m_service->m_cmd[i]->m_parameter, para_sec_l, para_sec_r))
                    {
                        if (m_service->m_cmd[i]->m_action)//允许的命令
                        {
                            if ((data_sec_l >= para_sec_l) && (data_sec_r <= para_sec_r))//地址匹配
                            {
                                if (strempty(m_service->m_cmd[i]->m_sign))//没有设置值
                                {
                                    return true;
                                }

                                //取得配置文件中值的区间
                                if (GetValueSection(m_service->m_cmd[i]->m_cmd,
                                    m_service->m_cmd[i]->m_sign, value_sec_l, value_sec_r))
                                {
                                    //地址区间数量
                                    int addrnum = sdata[MODBUSMBAP_LEN + 3] * 256 + sdata[MODBUSMBAP_LEN + 4];
                                    if (slen < (MODBUSMBAP_LEN + 6 + 2 * addrnum))
                                    {
                                        sprintf(cherror, "%s", MODBUS_PROTO_ERROR);
                                        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
                                        return false;
                                    }

                                    bool havenomatch = false;
                                    for (int i = 0; i < addrnum; i++)
                                    {
                                        //取得数据包中的一个值
                                        int tempval = sdata[MODBUSMBAP_LEN + 6 + 2 * i] * 256 +
                                            sdata[MODBUSMBAP_LEN + 6 + 2 * i + 1];
                                        if ((tempval < value_sec_l) || (tempval > value_sec_r))
                                        {
                                            havenomatch = true;
                                            break;
                                        }
                                    }

                                    //有不符合命令规定的值域的 说明没有匹配上该条命令,continue 20171109王君雷修改
                                    if (havenomatch)
                                    {
                                        continue;
                                    }
                                    return true;//所有值都匹配了命令规定，执行允许操作
                                }
                            }
                        }
                        else//拒绝的命令
                        {
                            if (!((data_sec_l > para_sec_r) || (data_sec_r < para_sec_l)))//地址匹配
                            {
                                if (strempty(m_service->m_cmd[i]->m_sign))//没有设置值
                                {
                                    sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                                    return false;
                                }

                                //取得配置文件中值的区间
                                if (GetValueSection(m_service->m_cmd[i]->m_cmd,
                                    m_service->m_cmd[i]->m_sign, value_sec_l, value_sec_r))
                                {
                                    //地址区间数量
                                    int addrnum = sdata[MODBUSMBAP_LEN + 3] * 256 + sdata[MODBUSMBAP_LEN + 4];
                                    if (slen < (MODBUSMBAP_LEN + 6 + 2 * addrnum))
                                    {
                                        sprintf(cherror, "%s", MODBUS_PROTO_ERROR);
                                        printf("%s[%d]%s\n", __FUNCTION__, __LINE__, cherror);
                                        return false;
                                    }

                                    for (int i = 0; i < addrnum; i++)
                                    {
                                        //取得数据包中的一个值
                                        int tempval = sdata[MODBUSMBAP_LEN + 6 + 2 * i] * 256 +
                                            sdata[MODBUSMBAP_LEN + 6 + 2 * i + 1];
                                        if ((tempval >= value_sec_l) && (tempval <= value_sec_r))
                                        {
                                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                                            return false;
                                        }
                                    }
                                }//GetValueSection
                            }//地址匹配
                        }
                    }//GetParaSection
                }//if
            }//for
            break;
        }
    case REG_MASK://22
        {
            if (slen < MODBUSMBAP_LEN + 5)
            {
                sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, slen);
                return false;
            }

            //取得数据包的单个地址
            int addr = sdata[MODBUSMBAP_LEN + 1] * 256 + sdata[MODBUSMBAP_LEN + 2] + 1;
            sprintf(m_chpara, "地址[%d]", addr);

            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    //如果没有写参数 就按匹配所有处理
                    if (strempty(m_service->m_cmd[i]->m_parameter))
                    {
                        if (!m_service->m_cmd[i]->m_action)
                        {
                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                        }
                        return m_service->m_cmd[i]->m_action;
                    }

                    //取得命令的地址区间
                    if (GetParaSection(m_service->m_cmd[i]->m_parameter, para_sec_l, para_sec_r))
                    {
                        if ((addr >= para_sec_l) && (addr <= para_sec_r))
                        {
                            //匹配上了
                            if (!m_service->m_cmd[i]->m_action)
                            {
                                sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                            }
                            return m_service->m_cmd[i]->m_action;
                        }
                    }
                }//if
            }
            break;
        }
    case FILE_R://20
    case FILE_W://21
    case REG_RW://23
        {
            //不用控制参数 忽略参数
            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    if (!m_service->m_cmd[i]->m_action)
                    {
                        sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                    }
                    return m_service->m_cmd[i]->m_action;
                }
            }
            break;
        }
    case DEV_R://43
        {
            if (slen < MODBUSMBAP_LEN + 4)
            {
                sprintf(cherror, "%s[%d]", MODBUS_DATALEN_ERROR, slen);
                return false;
            }

            if (sdata[MODBUSMBAP_LEN + 1] != 0x0E)
            {
                sprintf(cherror, "%s", MODBUS_PROTO_ERROR);
                return false;
            }

            //取得数据包的对象ID
            unsigned char c = sdata[MODBUSMBAP_LEN + 3];
            sprintf(m_chpara, "对象ID[%d]", c);

            for (int i = 0; i < m_service->m_cmdnum; i++)
            {
                //功能码匹配
                if (atoi(chcodeid) == atoi(m_service->m_cmd[i]->m_cmd))
                {
                    //如果没有写参数 就按匹配所有处理
                    if (strempty(m_service->m_cmd[i]->m_parameter))
                    {
                        if (!m_service->m_cmd[i]->m_action)
                        {
                            sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                        }
                        return m_service->m_cmd[i]->m_action;
                    }

                    //取得命令的对象区间
                    if (GetParaSection(m_service->m_cmd[i]->m_parameter, para_sec_l, para_sec_r))
                    {
                        if ((c >= para_sec_l) && (c <= para_sec_r))
                        {
                            //匹配上了
                            if (!m_service->m_cmd[i]->m_action)
                            {
                                sprintf(cherror, "%s", MODBUS_PERM_FORBID);
                            }
                            return m_service->m_cmd[i]->m_action;
                        }
                    }
                }
            }//for
            break;
        }
        default:
        {
            break;
        }
    }//switch

    printf("%s[%d]no defined code:%d\n", __FUNCTION__, __LINE__, atoi(chcodeid));
    //未定义命令

    if (!m_service->m_IfExec)
    {
        sprintf(cherror, "%s", MODBUS_PERM_FORBID);
    }
    return m_service->m_IfExec;
}

/*******************************************************************************************
*功能:  分析通过WEB界面添加的参数  把结果存放到该函数的后两个参数中
*参数:
*       chpara      命令参数
*       leftval     区间左值
*       rightval    区间右值
*注释:
*******************************************************************************************/
bool CMODBUSSINGLE::GetParaSection(const char *chpara, int& leftval, int& rightval)
{
    if (chpara == NULL)
    {
        printf("%s[%d]para null\n", __FUNCTION__, __LINE__);
        return false;
    }

    //查找减号位置
    const char *ptr_sign = strchr(chpara, '-');
    if (ptr_sign == NULL)
    {
        //不是减号连接的
        rightval = leftval = atoi(chpara);
        return (leftval >= 0);
    }
    else
    {
        //是减号连接的
        leftval = atoi(chpara);
        rightval = atoi(ptr_sign + 1);
        if ((leftval >=0) && (rightval >= 0) && (leftval <= rightval))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}

/*******************************************************************************************
*功能:  从数据包中分析出地址区间
*参数:
*       chdata       数据包
*       leftval      区间左值
*       rightval     区间右值
*注释:
*******************************************************************************************/
void CMODBUSSINGLE::GetDataSection(unsigned char *chdata, int& leftval, int& rightval)
{
    leftval = 0;
    rightval = 0;

    unsigned char c1 = chdata[MODBUSMBAP_LEN + 1];
    unsigned char c2 = chdata[MODBUSMBAP_LEN + 2];
    unsigned char c3 = chdata[MODBUSMBAP_LEN + 3];
    unsigned char c4 = chdata[MODBUSMBAP_LEN + 4];

    leftval = c1 * 256 + c2 + 1;
    rightval = c3 * 256 + c4 + leftval - 1;
    return;
}

/*******************************************************************************************
*功能:  从配置信息中解析出值的区间
*参数:
*       chcmd        功能码
*       chvalue      值区间字符串
*       value_sec_l  区间左值
*       value_sec_r  区间右值
*注释:
*******************************************************************************************/
bool CMODBUSSINGLE::GetValueSection(const char* chcmd, const char* chvalue,int &value_sec_l,int &value_sec_r)
{
    if ((chcmd == NULL) || (chvalue == NULL))
    {
        printf("%s[%d]para null!\n", __FUNCTION__, __LINE__);
        return false;
    }

    //如果是读线圈
    if (atoi(chcmd) == COIL_W)
    {
        if (strcasecmp(chvalue, "on") == 0)
        {
            value_sec_l = value_sec_r = 0xFF * 256;
            return true;
        }
        else if (strcasecmp(chvalue, "off") == 0)
        {
            value_sec_l = value_sec_r = 0;
            return true;
        }
        else
        {
            printf("%s[%d]invalid value[%s]\n", __FUNCTION__, __LINE__, chvalue);
            return false;
        }
    }

    return GetParaSection(chvalue, value_sec_l, value_sec_r);
}
