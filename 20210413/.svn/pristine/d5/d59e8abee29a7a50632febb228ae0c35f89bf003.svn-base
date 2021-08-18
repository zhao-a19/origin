/*******************************************************************************************
*文件:  callwd.cpp
*描述:  调用看门狗程序 使用深信服提供的程序修改的
*作者:  王君雷
*日期:  2021/03/10
*修改:
*******************************************************************************************/
#include "define.h" // SUPPORT_WATCHDOG
#include "debugout.h"
#include "common.h"

loghandle glog_p = NULL;

#ifdef SUPPORT_WATCHDOG

#define WATCHDOG_TIMEOUT 5 //5s超时
#define WATCHDOG_FEED    2 //2s喂一次

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/io.h>
#include </usr/include/sys/io.h>
#define SMBUS_BASE      0x800088D0
#define PCI_INDEX       0xCF8
#define PCI_DATA        0xCFC
#define outportb(port,data) outb(data,port)
#define inportb(port)   inb(port)
#define SMBUS_OFFSET 0x00

unsigned int SMBus_Port;

void delay()
{
    int count = 0;
    for (count = 0; count < 500; count++)
        outportb(0xED, 0xFF);
}

void Check_Data()
{
    int i;
    unsigned int c;

    for (i = 0; i < 6; i++) {
        c = inb(SMBus_Port);
        if (c != 0) break;
    }

}

char CT_Chk_SMBus_Ready()
{
    unsigned int c;
    int i;

    for (i = 0; i < 0x800; i++) {
        c = inb(SMBus_Port);        //get status reg0
        Check_Data();
        outb(c, SMBus_Port);    //clear status bit

        if (c & 2) goto Clear_final;
        if ((c & ~0x40) == 0) goto Clear_final;
        if (c & 0x4) goto SMBus_Err;
    }
    // printf("bus = %x\n",SMBus_Port);
SMBus_Err:
    return 0;
Clear_final:
    return 1;
}

void Delay5ms()
{
    usleep(5000);
}

int Get_SMBus_Port()
{
    int B_SMBUS;
    outl(SMBUS_BASE, PCI_INDEX);
    B_SMBUS = inl(PCI_DATA);
    return B_SMBUS; //return the base address
}

void Clear_Sts()
{
    int count = 0;

    for (count = 0; count < 500; count++) {
        outportb(SMBus_Port + 0x00, 0xFF);
        outportb(0xED, 0xFF);     //delay
        if (inportb(SMBus_Port + 0x00) == 0x40)
            break;
    }
}

void Ct_I2CWriteByte(unsigned char ID, unsigned char index, unsigned char cmd, unsigned char *data) //ID= slave addr, index = cmd
{
    //   int Bypass_Reg_Value = 0;
    //  printf("Key-in your register value.\t");
    // scanf("%x",&Bypass_Reg_Value);
    outb(ID, SMBus_Port + 4);       //slave addr reg = base addr + 4 , add 0 = set write bit
    Delay5ms();
    Delay5ms();
    CT_Chk_SMBus_Ready();
    outb(index, SMBus_Port + 3);
    Delay5ms();
    Delay5ms();
    outb(cmd, SMBus_Port + 5);
    Delay5ms();
    Delay5ms();
    outb(0x48, SMBus_Port + 2);
    Delay5ms();
    Delay5ms();
    *data = inb(SMBus_Port + 5);
    //printf("\nBypass setting: address 0x%x is 0x%x\n",index,*data);
    Delay5ms();
    Delay5ms();
    Check_Data();
}

unsigned char Ct_I2CReadByte(unsigned char ID, unsigned char index, unsigned char *data)
{
    unsigned char i, j;
    outb(ID + 1, SMBus_Port + 4);
    Delay5ms();
    Delay5ms();
    CT_Chk_SMBus_Ready();
    outb(index, SMBus_Port + 3);
    Delay5ms();
    Delay5ms();
    outb(0x48, SMBus_Port + 2);
    Delay5ms();
    Delay5ms();
    i = inb(SMBus_Port + 5);
    Delay5ms();
    Delay5ms();
    return i;
}

void Pmbus_Write(unsigned char slave, unsigned char Bypass_Reg, unsigned char Cmd)
{
    unsigned char *CR = (unsigned char *)malloc(sizeof(char));
    //  int Bypass_Reg = 0;
    //   printf("Key-in the register address.\t");
    //  scanf("%x",&Bypass_Reg);
    Ct_I2CWriteByte(slave, Bypass_Reg, Cmd, CR);
    free(CR);
}

unsigned char Pmbus_Read(unsigned char slave, unsigned char Bypass_Reg)
{
    unsigned char k;
    unsigned char *CR = (unsigned char *)malloc(sizeof(char));
    k = Ct_I2CReadByte(slave, Bypass_Reg, CR);
    free(CR);
    return k;
}

void print_usage(char *s)
{
    printf("usage:%s 0 content (write com_logo)\n", s);
    printf("usage:%s 1 content(write dmi)\n", s);
    printf("usage:%s 2 content(write family)\n", s);
    printf("usage:%s 3 content(write serial number)\n", s);
    printf("usage:%s 4 content(write uuid)\n", s);
    printf("usage:%s 5 content(write motherboard vertion)\n", s);
    printf("usage:%s 6 content(write production time)\n", s);
    printf("usage:%s 7 content(write motherboard product time)\n", s);
    printf("usage:%s 8 content(write pcb product time)\n", s);
    printf("usage:%s 9 content(write mb manufaturer)\n", s);
    printf("usage:%s 10 content(write product model)\n", s);
    printf("usage:%s all 0(read all)\n", s);
}

int main(int argc, char **argv)
{
#if 0
    iopl(3);
    int i, j;
    unsigned char data[50];
    char input_rw[5];
    char cmp_logo[50];
    char dmi[50];
    char family[50];
    char se_num[50];
    char uuid[50];
    char mb_ver[50];
    char pro_time[50];
    char mb_time[50];
    char pcb_time[50];
    char mb_facturer[50];
    char pro_model[50];
    char all_item[500];
    memset(input_rw, 0, sizeof(input_rw));
    memset(cmp_logo, 0, sizeof(cmp_logo));
    memset(dmi, 0, sizeof(dmi));
    memset(family, 0, sizeof(family));
    memset(se_num, 0, sizeof(se_num));
    memset(uuid, 0, sizeof(uuid));
    memset(mb_ver, 0, sizeof(mb_ver));
    memset(pro_time, 0, sizeof(pro_time));
    memset(mb_time, 0, sizeof(mb_time));
    memset(pcb_time, 0, sizeof(pcb_time));
    memset(mb_facturer, 0, sizeof(mb_facturer));
    memset(pro_model, 0, sizeof(pro_model));
    memset(all_item, 0, sizeof(all_item));
    SMBus_Port = 0xE000;
    if (argc < 3 || argc > 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "all") != 0) {
        j = atoi(argv[1]);
        switch (j) {
        case 0: {
            for (i = 0; i < 7; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x00 + i, 0);
            }
            strcpy(cmp_logo, argv[2]);
            for (i = 0; i < strlen(cmp_logo); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x00 + i, cmp_logo[i]);
            }
            break;

        }
        case 1: {
            for (i = 0; i < 9; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x07 + i, 0);
            }
            strcpy(dmi, argv[2]);
            for (i = 0; i < strlen(dmi); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x07 + i, dmi[i]);
            }
            break;

        }
        case 2: {
            for (i = 0; i < 38; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x10 + i, 0);
            }
            strcpy(family, argv[2]);
            for (i = 0; i < strlen(family); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x10 + i, family[i]);
            }
            break;

        }
        case 3: {
            for (i = 0; i < 10; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x36 + i, 0);
            }
            strcpy(se_num, argv[2]);
            for (i = 0; i < strlen(se_num); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x36 + i, se_num[i]);
            }
            break;

        }
        case 4: {
            for (i = 0; i < 32; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x40 + i, 0);
            }
            strcpy(uuid, argv[2]);
            printf("Please input the UUID:\n");
            for (i = 0; i < strlen(uuid); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x40 + i, uuid[i]);
            }
            break;

        }
        case 5: {
            for (i = 0; i < 16; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x60 + i, 0);
            }
            strcpy(mb_ver, argv[2]);
            for (i = 0; i < strlen(mb_ver); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x60 + i, mb_ver[i]);
            }
            break;

        }
        case 6: {
            for (i = 0; i < 11; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x70 + i, 0);
            }
            strcpy(pro_time, argv[2]);
            for (i = 0; i < strlen(pro_time); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x70 + i, pro_time[i]);
            }
            break;

        }
        case 7: {
            for (i = 0; i < 11; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x7b + i, 0);
            }
            strcpy(mb_time, argv[2]);
            for (i = 0; i < strlen(mb_time); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x7b + i, mb_time[i]);
            }
            break;

        }
        case 8: {
            for (i = 0; i < 11; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x86 + i, 0);
            }
            strcpy(pcb_time, argv[2]);
            for (i = 0; i < strlen(pcb_time); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x86 + i, pcb_time[i]);
            }
            break;

        }
        case 9: {
            for (i = 0; i < 15; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x91 + i, 0);
            }
            strcpy(mb_facturer, argv[2]);
            for (i = 0; i < strlen(mb_facturer); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0x91 + i, mb_facturer[i]);
            }
            break;

        }
        case 10: {
            for (i = 0; i < 32; i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0xa0 + i, 0);
            }
            strcpy(pro_model, argv[2]);
            for (i = 0; i < strlen(pro_model); i++) {
                //printf("mod_name[%d]=0x%x\n",i,mod_name[i]);
                Pmbus_Write(0xaa, 0xa0 + i, pro_model[i]);
            }
            break;

        }
        default: {
            print_usage(argv[0]);
            break;
        }
        }
    } else if (strcmp(argv[1], "all") == 0) {
        printf("COMPANY LOGO is: ");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 7; i++) {
            data[i] = Pmbus_Read(0xaa, 0x00 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("DMI is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 9; i++) {
            data[i] = Pmbus_Read(0xaa, 0x07 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("FAMILY is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 38; i++) {
            data[i] = Pmbus_Read(0xaa, 0x10 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("SERIAL NUM is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 10; i++) {
            data[i] = Pmbus_Read(0xaa, 0x36 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("UUID is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 32; i++) {
            data[i] = Pmbus_Read(0xaa, 0x40 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("MOTHERBOARD VERTION is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 16; i++) {
            data[i] = Pmbus_Read(0xaa, 0x60 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("PRODUCT TIME is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 11; i++) {
            data[i] = Pmbus_Read(0xaa, 0x70 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("MOTHERBOARD PRODUCT TIME is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 11; i++) {
            data[i] = Pmbus_Read(0xaa, 0x7b + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("PCB PRODUCT TIME is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 11; i++) {
            data[i] = Pmbus_Read(0xaa, 0x86 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("MOTHERBOARD FACTUERER is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 15; i++) {
            data[i] = Pmbus_Read(0xaa, 0x91 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
        printf("PRODUCT MODEL is:");
        memset(data, 0, sizeof(data));
        for (i = 0; i < 32; i++) {
            data[i] = Pmbus_Read(0xaa, 0xa0 + i);
            if (data[i] != 0 && data[i] != 0xff)
                printf("%c", data[i]);
        }
        printf("\n");
    }
#else
    _log_init_(glog_p, callwd);
    iopl(3);
    SMBus_Port = 0xE000;

    char boardver[50] = {0};
    int n = 0;
    unsigned char data[50] = {0};
    char tmpstr[5] = {0};
    char chcmd[1024] = {0};

    memset(data, 0, sizeof(data));
    for (int i = 0; i < 16; i++) {
        data[i] = Pmbus_Read(0xaa, 0x60 + i);
        if (data[i] != 0 && data[i] != 0xff) {
            sprintf(tmpstr, "%c", data[i]);
            boardver[n++] = tmpstr[0];
        }
    }
    //printf("[%s]\n", boardver);
    PRINT_INFO_HEAD
    print_info("boardver[%s]", boardver);

    if ((strcmp(boardver, "sxf_tina_v1.0") == 0)
        || (strcmp(boardver, "sxf_luma_v1.0") == 0)) {
        CCommon common;
        if (common.FileExist(WATCHDOG_TINA)) {
            chmod(WATCHDOG_TINA, 0755);
            sprintf(chcmd, "%s -s %d", WATCHDOG_TINA, WATCHDOG_TIMEOUT);
        } else {
            PRINT_INFO_HEAD
            print_info("file[%s] not exist", WATCHDOG_TINA);
        }
    } else {
        PRINT_INFO_HEAD
        print_info("unknown boardver[%s]", boardver);
    }

    int cmdlen = strlen(chcmd);
    while (cmdlen > 0) {
        sleep(WATCHDOG_FEED);
        system(chcmd);
    }
#endif
    return 0;
}

#else
int main()
{
    _log_init_(glog_p, callwd);
    return 0;
}
#endif
