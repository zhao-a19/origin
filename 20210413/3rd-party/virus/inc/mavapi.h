#ifndef ENGINE_HEAD_H__
#define ENGINE_HEAD_H__

typedef long (*GETMAVUSERNUMPROC)(void);	//回调函数格式声明


#ifdef __cplusplus
extern "C" {
#endif

//限时的时间类型
#define MAV_LIMIT_TIME_NULL				0	//不限时
#define MAV_LIMIT_TIME_ONE_MONTH		1	//限时1个月
#define MAV_LIMIT_TIME_THREE_MONTHS		2	//限时3个月
#define MAV_LIMIT_TIME_ONE_YEAR			3	//限时1年

#define	MAV_MAX_PATH		1024
#define	MAV_MAX_DISP		1024
#define	MAV_MAX_FILTER		256
#define	MAV_MAX_VIRUSNAME	64

//MAVATTACHLIST.dwAction		//查杀毒结果
#define		MAV_RESULT_EXCEPTION					-2		//查毒异常
#define		MAV_RESULT_CANNOT_GET_STRING			-1		//查毒异常
#define		MAV_RESULT_NOT_FOUND					0		//没发现病毒
#define		MAV_RESULT_FOUND						1		//发现病毒
#define		MAV_RESULT_FOUND_AND_KILLED				2//发现病毒并清除
#define		MAV_RESULT_FOUND_BUT_KILL_FAILED		3//发现病毒但清除失败
#define		MAV_RESULT_FOUND_AND_DELETED			4//发现病毒并删除
#define		MAV_RESULT_FOUND_BUT_DELETE_FAILED		5//发现病毒但删除失败
#define		MAV_RESULT_FOUND_BUT_USER_IGNORE		6//发现病毒但用户忽略
#define		MAV_RESULT_FOUND_BUT_NEED_UNPACK		7//发现病毒但需要解压缩
#define		MAV_RESULT_FOUND_AND_RENAMED			8//发现病毒并改名
#define		MAV_RESULT_FOUND_BUT_RENAME_FAILED		9//发现病毒但改名失败
#define		MAV_RESULT_ZIP_ENCRYPT					10//压缩包需要解密


//MAVSCANINFO.dwKillType		杀毒时用户希望如何处理带毒文件
#define		MAV_KILLTYPE_SCAN			0	//只是查毒
#define		MAV_KILLTYPE_KILL			2	//自动清除
#define		MAV_KILLTYPE_DELETE			4	//自动删除

//MAVSCANINFO.dwCompress		查压缩文件
#define		MAV_COMPRESS_NORMAL		2	//只把压缩文件当普通文件查，不解包
#define		MAV_COMPRESS_BOTH		3	//先当普通文件查，再解包
#define		MAV_COMPRESS_MULTI		4	//多层解压

//MAVSCANINFO.dwFilterType		过滤器类型
#define		MAV_FILTERTYPE_NULL		0		//不使用过滤器
#define		MAV_FILTERTYPE_INCLUDE	1		//只查过滤到的文件
#define		MAV_FILTERTYPE_EXCLUDE	2		//不查过滤到的文件

typedef struct tagSerialInfo
{
	long lUserNum;							//允许最大用户数，如果为0则不限制用户数
	long lLimitType;						//试用类型
} SERIALINFO, *PSERIALINFO;

typedef struct tagMAVAttachList {			//病毒链表数据结构
	char szAttachName[MAV_MAX_PATH];		//附件名称
	char szVirusName[MAV_MAX_VIRUSNAME];	//病毒名称
	unsigned long dwAction;					//查杀毒结果
	struct tagMAVAttachList *pNext;				//下一个病毒项
}MAVATTACHLIST, *PMAVATTACHLIST;

typedef struct tagMAVMailInfo {
	unsigned long dwScanCount;						//扫描计数
	unsigned long dwInfectCount;					//被感染文件总数
	unsigned long dwKillCount;						//杀毒数
	unsigned long dwDelCount;						//删除病毒数
	unsigned long dwKillFailCount;					//杀毒失败数
	unsigned long dwDelFailCount;					//删除失败数
	unsigned long dwIgnoreCount;					//忽略病毒数
	PMAVATTACHLIST pAttachList;						//病毒链表
	char szMailName[MAV_MAX_PATH];					//文件名
}MAVMAILINFO, *PMAVMAILINFO;

typedef struct tagMAVSCANINFO
{
	char	szFilePath[MAV_MAX_PATH];		//实际的文件路径
	unsigned long	dwKillType;				//杀毒时用户希望如何处理带毒文件
	unsigned long	dwCompress;				//是否查压缩文件
	unsigned long	dwFilterType;			//过滤器类型
	char	szScanFilter[MAV_MAX_FILTER];	//文件类型 ("*" for all files;)
} MAVSCANINFO, *PMAVSCANINFO;

////////////////////////////////////////////////////////////////////////////////
//用  途：打开引擎，并设置所支持的最大线程数
//功能1：if lMaxInstCount == -1 then 返回当前的最大Instance数
//功能2：if lInstCount == 0     then 将前的最大Instance数设置为lMaxInstCount
//功能3：if lInstCount > 0 && lMaxInstCount > 0 then 初始化lInstCount个Instance
//                                      并设置最大Instance数为lMaxInstCount
//对全局变量的影响：无
//参  数：
//              pszLibName : 病毒库文件名
//              lInstCount : 要初始化的Instance数
//              lMaxInstCount : 系统允许的最大Instance数
//返回值：long
//功能1：<0:Fail ; >=0:Sucess
//功能2：0:Fail ; 1:success
//功能3：0:Fail ; 1:Sucess
////////////////////////////////////////////////////////////////////////////////
long OpenMAVEngine(char *pszLibName,long lInstCount,long lMaxInstCount);

////////////////////////////////////////////////////////////////////////////////
//用  途：设置搜索深度(范围是: 0~5000)
//对全局变量的影响：	若nNewDepth在0~5000,则
//							设置全局变量g_nMaxSearchZipDepth为nNewDepth
//							在本进程空间内有效. 并返回true
//						否则返回false
//参  数：nNewDepth：0表示不限制深度次数, 其他有效值(1~5000)为最大查找深度
//返回值：bool Success: true; Fail: false
////////////////////////////////////////////////////////////////////////////////
//bool SetMaxSearchDepth(int nNewDepth = 100);
int  SetMaxSearchDepth(int nNewDepth );

////////////////////////////////////////////////////////////////////////////////
//用  途：关闭引擎
//对全局变量的影响：无
//参  数：bForce：是否强制关闭引擎
//返回值：long Success:1 Fail:0
////////////////////////////////////////////////////////////////////////////////
long CloseMAVEngine(short bForce);

////////////////////////////////////////////////////////////////////////////////
//用  途：查杀一个文件
//对全局变量的影响：无
//参  数：
//		lpScanInfo : 结构体，每个具体成员的含义在结构体中说明。
//返回值：unsigned long 
//	---------------------------------
//	| 31-24 | 23-16 | 15-8  |  7-0  |
//	---------------------------------
//		A		B		C		D
//
//	A:保留，内部使用
//	B:保留，内部使用
//	C:曾经成功杀毒的结果，具体值定义与dwScanResult相同。
//	D:最后一次杀毒的结果，具体值定义与dwScanResult相同。
//	
////////////////////////////////////////////////////////////////////////////////
unsigned long MailMAVScan(PMAVSCANINFO pMAVScanInfo,PMAVMAILINFO* ppmmi);

//释放用户数据
void  FreeMAVMailInfo(PMAVMAILINFO pmmi);

////////////////////////////////////////////////////////////////////////////////
//用  途：判断MailMAVScan的查毒结果
//对全局变量的影响：无
//参  数：MailMAVScan的返回值
//返回值：有无病毒（0:有；1：无）
//		在dwKillType = MAV_KILLTYPE_SCAN时使用
////////////////////////////////////////////////////////////////////////////////
#define ScanNoVirus(x) (((x&0xff000000) != 0)||((x&0x00ff0000) == 0))

////////////////////////////////////////////////////////////////////////////////
//用  途：判断MailMAVScan的查毒结果
//对全局变量的影响：无
//参  数：MailMAVScan的返回值
//返回值：有无病毒（0:有；1：无）
//		在dwKillType = MAV_KILLTYPE_KILL 或 MAV_KILLTYPE_DELETE时使用
////////////////////////////////////////////////////////////////////////////////
#define KillNoVirus(x) (((x&0xff000000) != 0)||((x&0x0000ffff) == 0))

////////////////////////////////////////////////////////////////////////////////
//用  途：判断MailMAVScan的查毒结果
//对全局变量的影响：无
//参  数：MailMAVScan的返回值
//返回值：杀毒结果（具体值定义与dwScanResult相同）
//		在dwKillType = MAV_KILLTYPE_KILL 或 MAV_KILLTYPE_DELETE时使用
////////////////////////////////////////////////////////////////////////////////
#define KillResult(x)  (x&0xff) 

////////////////////////////////////////////////////////////////////////////////
//函数名：long IsNeedScan( char *pszFileName ) 
//用  途：判断一个文件是否需要查毒
//对全局变量的影响：无
//参  数：
//		pszFileName : 待判断类型的文件名
//返回值：long
//		>=0:需要查毒，且返回的是文件的类型
//		<0:不需要查毒
////////////////////////////////////////////////////////////////////////////////
long IsNeedScan(char *pszFileName);


////////////////////////////////////////////////////////////////////////////////
//函数名：GetEngineVersion(char *pszVersion)
//用  途：获取引擎版本
//对全局变量的影响：无
//参  数：
//		pszVersion : 保存版本字符串。
//返回值：无
////////////////////////////////////////////////////////////////////////////////
void GetEngineVersion(char *pszVersion);

////////////////////////////////////////////////////////////////////////////////
//函数名：GetMAVSerialInfo(PSERIALINFO psi)
//用  途：获取许可协议信息
//对全局变量的影响：无
//参  数：
//		psi : 许可信息结构指针。
//返回值：0==失败；1==成功
////////////////////////////////////////////////////////////////////////////////
short GetMAVSerialInfo(PSERIALINFO psi);

////////////////////////////////////////////////////////////////////////////////
//函数名：SetMAVUserNumCallBack(GETMAVUSERNUMPROC)
//用  途：设置能够得到当前使用杀毒功能的用户数的回调函数的地址
//对全局变量的影响：此函数地址将保存在全局变量：g_UserNumCallBackProc
//参  数：
//		pMAVUserNumProc : GETMAVUSERNUMPROC回调函数地址。
//返回值：无
////////////////////////////////////////////////////////////////////////////////
void SetMAVUserNumCallBack(GETMAVUSERNUMPROC pMAVUserNumProc);

// 扩展查毒接口
// 下面的定义是为了扩展接口定义的
#define MAVDISKFILE 0	//普通磁盘文件
#define MAVMEMFILE	1	//内存文件

//用户邮件查杀参数结构
typedef struct tagMAVSCANINFOEx
{
	char	szFilePath[MAV_MAX_PATH];		//实际的文件路径
	unsigned long	dwKillType;				//杀毒时用户希望如何处理带毒文件
	unsigned long	dwCompress;				//是否查压缩文件
	unsigned long	dwFilterType;			//过滤器类型
	char	szScanFilter[MAV_MAX_FILTER];	//文件类型 ("*" for all files;)
	
	//扩展部分
	int nType; // 数据文件类型，如果nType值未定义，则默认为0
						 // MAVDISKFILE-无毒邮箱磁盘文件
						 // MAVMEMFILE-无毒邮箱内存对象			
	void *pData; //根据nType类型指向不同的指针结构，对于磁盘文件，为NULL
} MAVSCANINFOEX, *PMAVSCANINFOEX;

//无毒邮箱内存对象结构
typedef struct tagNVMBMemData
{
	unsigned char *pData; // 内存文件缓冲区
	unsigned int  nDataSize; // 内存文件大小
	unsigned int nBufSize;		//pData缓冲区大小
}NVMBMEMDATA, *PNVMBMEMDATA;

////////////////////////////////////////////////////////////////////////////////
//用  途：扩展的文件查杀接口
//对全局变量的影响：无
//参  数：
//		lpScanInfo : 结构体，每个具体成员的含义在结构体中说明。
//返回值：unsigned long 
//	---------------------------------
//	| 31-24 | 23-16 | 15-8  |  7-0  |
//	---------------------------------
//		A		B		C		D
//
//	A:保留，内部使用
//	B:保留，内部使用
//	C:曾经成功杀毒的结果，具体值定义与dwScanResult相同。
//	D:最后一次杀毒的结果，具体值定义与dwScanResult相同。
//	
////////////////////////////////////////////////////////////////////////////////
unsigned long MailMAVScanEx(PMAVSCANINFOEX pMAVScanInfo,PMAVMAILINFO* ppmmi);

////////////////////////////////////////////////////////////////
//  函数名： void GetVirusDefVersion(char *pszVersion)
//  用途：  取得病毒库的版本
//  对全局变量的影响：无
//  参数说明 ： pszVersion :返回病毒库版本
//  返回结果 ： 无
/////////////////////////////////////////////////////////////////
void GetVirusDefVersion(char *pszVersion);

#ifdef __cplusplus
}
#endif

#endif	//ENGINE_HEAD_H__
