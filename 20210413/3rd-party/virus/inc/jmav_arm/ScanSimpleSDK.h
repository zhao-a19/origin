#pragma once

#include "TypeDef.h"

#ifdef __GNUC__
#include <stdbool.h>
typedef uint64_t __time64_t;
#endif // 

//
// 发现病毒处理方式
//
#ifndef EHandleMode_DEF
#define EHandleMode_DEF
typedef enum _EHandleMode {
	modeIgnore	= 0,	// 不处理
	modeFind	= 1,	// 查毒
	modeCure	= 2,	// 杀毒, 返回结果为查毒成功/杀毒失败
	modeDelete	= 3,	// 删除


	modeStop	= 4,	// 仅用于备份时返回值
} EHandleMode;
#endif // EHandleMode_DEF

// 扫描标志定义

typedef enum _EFlags {					
	scanUnzip = 0x01,		// 扫描压缩包
	scanUnpack = 0x02,		// 脱壳
	scanStopOnOne = 0x10,		// 处理一个病毒后即停止
								// 仅在查毒方式下有效

	scanProgramOnly = 0x100,	// 只扫描程序

	scanOriginalMd5 = 0x1000,	// 需要返回原始文件的 MD5值
	scanUseFigner = 0x2000,	// 是否使用指纹，建议文件扫描、文件监控使用。网页监控、邮件监控不需要使用
	scanBackup = 0x8000,	// 文件需要前应进行备份

	scanForceUnzip = 0x100000, // 强制按压缩包处理
	scanDeleteOnCureFail = 0x200000, // 清除失败时删除染毒文件
} EFlags;

//
// 查杀病毒扫描选项
//
typedef struct _ScanOptions {
	uint32_t m_dwSize;				// 结构大小


	uint32_t m_dwFlags;				// EFlags 扫描选项标志组合
	EHandleMode m_handeMode;		// 具体处理方式
	uint32_t m_dwMaxFileSize;		// 最大扫描文件大小, 0 为不限制 
	uint32_t m_dwMaxZipFileSize;	// 最大解压文件大小， 0为不限制

	uint32_t m_unUnzipLevel;		// 最大解压层数

	uint64_t m_ulMaxUnzipFileSize;	// 解压出文件的最大大小，0 为不限制
	uint32_t m_unMaxUnzipRatio;		// 解压文件时最大的压缩率，即压缩率大于该值则不再解压

	uint32_t rev[0x10];
} ScanOptions;


//
// 查杀病毒处理结果定义
//
#ifndef  EScanResult_DEF
#define  EScanResult_DEF
typedef enum _EScanResult {
	scanNormal			= 0x0,		// 没有发现病毒
	scanFind			= 0x01,		// 发现病毒，未清除		
	scanCured			= 0x10,		// 发现病毒，成功清除
	scanCureReboot		= 0x11,		// 发现病毒，清除后需要重启替换
	scanCureFailed		= 0x13,		// 发现病毒，清除失败
	scanDelete			= 0x28,		// 发现病毒，已删除
	scanDeleteReboot	= 0x21,		// 发现病毒，需要重启删除
	scanDeleteFailed	= 0x23,		// 发现病毒，删除失败

	scanMaskFind		= 0x01,		// 发现病毒的掩码位
	scanMaskFailed		= 0x02,		// 处理失败的掩码位
	scanMaskNotExisted	= 0x08		// 文件已不再存在的掩码位
} EScanResult;
#endif // EScanResult


#ifndef MAX_PATH
#define MAX_PATH          4096
#endif

#include <PshPack1.h>
/**
 *  IScanSimple 中 对于压缩包中包含多个病毒，返回第一个病毒名及Id
 * 感染多个病毒也是第一个病毒名及Id
 * 而 IScanNotify 中信息为当前路径对应的信息
 * 只对独立文件（脱壳也是原始文件）计算MD5，压缩包不计算
 */
typedef struct _ScanResult {
	uint32_t m_dwSize; // 结构大小
	char	m_szVirusName[MAX_VIRNAME_LEN];// 病毒名称
	uint8_t m_arrMd5[16];				// 病毒原始文件的 MD5 值（未杀毒前的）
	uint8_t m_btFirstNotify;			// 一个文件第一次通知时为 1，以后为 0 
	char	m_szBackupId[MAX_PATH];		// 备份的文件名
	uint32_t	m_dwVirusId;			// 病毒记录Id	// 为兼容暂时保持32位
	EScanResult m_result;				// 具体扫描处理结果
} ScanResult;

#include <PopPack.h>

#ifdef __GNUC__
#define LIB_PUBLIC	__attribute__((visibility ("default")))
#else
#define LIB_PUBLIC	
#endif // __GNUC__


/**
 * @brief 单一文件的扫描接口
 * 主要用于监控类/网关类的模块调用扫描
 */
#ifdef __cplusplus
struct IScanSimple {
protected:
	~IScanSimple() = default;
public:
	//
	// 释放接口
	//
	virtual void AV_CALLTYPE Dispose() PURE;

	// 
	// 设置扫描选项
	//
	// 参数：
	//		pOptions		扫描选项，调用前需要正确设置ScanOptions::m_dwSize
	//
	virtual void AV_CALLTYPE SetOtpions(const ScanOptions* pOptions) PURE;

	//
	// 按路径扫描文件
	//
	// 参数：
	//		szPath			待扫描的完整文件路径
	//		unLastRecNo		保留参数，为 0
	//		pResult			返回扫描结果
	//
	// 返回值
	//		true			成功进行了扫描
	//		false			内部错误，未能扫描
	virtual bool AV_CALLTYPE ScanFile(const TCHAR* szPath, uint32_t unLastRecNo,  ScanResult* pResult) PURE;

	// 按内存进行扫描处理
	// 参数：
	//		pData			需要扫描的内存缓冲区指针
	//		unDataLen		输入：需要扫描的内存缓冲区大小
	//						输出：清除病毒模式下杀毒后的内存，可能会被截断
	//		szExt			文件扩展名，可以为""
	//		unLastRecNo		保留参数，为 0
	//		pResult			返回扫描结果
	//
	// 返回值
	//		true			成功进行了扫描
	//		false			内部错误，未能扫描
	//	说明：
	//		1. 对于清除后变大的情况，将只返回 unDataLen 提供的内存大小，后面会被截断
	//		2. 对于清除后变小的情况，unDataLen返回清除后的大小
	virtual bool AV_CALLTYPE ScanMemoryFile(void* pData, uint32_t& unDataLen, const TCHAR* szExt, uint32_t unLastRecNo,  ScanResult* pResult) PURE;

	//
	// 按IFile接口扫描文件
	//
	// 参数：
	//		pFile			待扫描的完整文件对象
	//		unLastRecNo		保留参数，为 0
	//		pResult			返回扫描结果
	//
	// 返回值
	//		true			成功进行了扫描
	//		false			内部错误，未能扫描
	virtual bool AV_CALLTYPE ScanFile( IFileEx* pFile, uint32_t unLastRecNo, ScanResult* pResult ) PURE;
};
#else

typedef void* IScanSimple;

// 释放接口
LIB_PUBLIC 	void AV_CALLTYPE IScan_Dispose(IScanSimple* pIScanSimple);


// 
// 设置扫描选项
//
// 参数：
//		pOptions		扫描选项，调用前需要正确设置ScanOptions::m_dwSize
//
LIB_PUBLIC 	void AV_CALLTYPE IScan_SetOtpions(IScanSimple* pIScanSimple, const ScanOptions* pOptions);

//
// 按路径扫描文件
//
// 参数：
//		szPath			待扫描的完整文件路径
//		unLastRecNo		保留参数，为 0
//		pResult			返回扫描结果
//
// 返回值
//		true			成功进行了扫描
//		false			内部错误，未能扫描
LIB_PUBLIC 	bool AV_CALLTYPE IScan_ScanFile(IScanSimple* pIScanSimple, const TCHAR* szPath, uint32_t unLastRecNo, ScanResult* pResult);

// 按内存进行扫描处理
// 参数：
//		pData			需要扫描的内存缓冲区指针
//		unDataLen		输入：需要扫描的内存缓冲区大小
//		szExt			文件扩展名，可以为""
//		unLastRecNo		保留参数，为 0
//		pResult			返回扫描结果
//		punDataLen		清除病毒模式下杀毒后的内存，可能会被截断
//
// 返回值
//		true			成功进行了扫描
//		false			内部错误，未能扫描
//	说明：
//		1. 对于清除后变大的情况，punDataLen将只返回 unDataLen 提供的内存大小，后面会被截断
//		2. 对于清除后变小的情况，punDataLen返回清除后的大小
LIB_PUBLIC 	bool AV_CALLTYPE IScan_ScanMemoryFile(IScanSimple* pIScanSimple, void* pData, uint32_t unDataLen, const TCHAR* szExt, uint32_t unLastRecNo, ScanResult* pResult, uint32_t* punDataLen);


#endif // __cplusplus

EXTERN_C_BEGIN

///////////////////////////////////////////////////////////////////////
//
// 设置libavemgr.so完整路径
// libavemgr根据此路径计算病毒库/配置文件路径
//	
// 参数：
//		pszAVEMgrPath		libavemgr.so的绝对路径
//
// 说明：
//		如果主程序与libavemgr.so在同一文件夹，可以不设置
//
LIB_PUBLIC void AV_CALLTYPE ScanSetModPath(const TCHAR* pszAVEMgrPath);

///////////////////////////////////////////////////////////////////////
//
// 创建 IScanSimple 接口，初始化病毒库
//
// 返回值:
//		IScanSimple* 指针
//		失败时为NULL
LIB_PUBLIC 	IScanSimple* AV_CALLTYPE ScanSimpleCreate( );

//
// 获取引擎版本
//
// 返回值:
//		版本字符串
LIB_PUBLIC 	const TCHAR* AV_CALLTYPE ScanGetVersion( );

//
// 获取病毒库日期
//
// 返回值:
//		病毒库时间戳， 单位为秒，从 January 1, 1970, 0:00 UTC 开始计算
// 说明:
//		需要在ScanSimpleCreate成功后调用
LIB_PUBLIC 	__time64_t AV_CALLTYPE ScanGetLibDate();

//
// 获取备份文件夹路径
//
// 返回值:
//		备份文件夹路径
// 说明:
//		需要在ScanSimpleCreate成功后调用
LIB_PUBLIC 	const TCHAR* AV_CALLTYPE ScanGetBackupPath();

//
//  扫描结束，释放接口后清理资源
//
LIB_PUBLIC 	void AV_CALLTYPE ScanClean();

///////////////////////////////////////////////////////////////////////
//
// 备份文件
//
// 参数：
//		szOrgFile	将要备份的文件路径
//		pszVirName	病毒名，不可为空
//		szBackPath	将要创建的备份文件完整路径，含文件名
//
// 返回值：
//		0， 成功
//		其它，失败
LIB_PUBLIC  int32_t AV_CALLTYPE FileBackup(const TCHAR* szOrgFile, const char* pszVirName, const TCHAR* szBackPath);

//
// 还原杀毒时的备份文件
//
// 参数：
//		szBackPath	需要还原的备份文件完整路径，含文件名
//		szRestorePath	将要创建的还原文件路径，含文件名
//
// 返回值：
//		0， 成功
//		其它，失败
LIB_PUBLIC  int32_t AV_CALLTYPE FileRestore(const TCHAR* szBackPath, const TCHAR* szRestorePath);


// 
// 获取授权到期截止时间
//
// 说明：
//	需要在ScanSetModPath或ScanSimpleCreate后调用，否则会因为配置文件路径不正确而失败
//
// 参数：
//	pszEndDate，授权到期时间缓冲区，格式为 "2020-01-02", UTC 时间
//
// 返回值
//	>=0, 成功， 同时填充 pszEndDate 缓冲区
//  <0, 失败， 授权文件不存在或数据错误。
//
LIB_PUBLIC int64_t AV_CALLTYPE Lic_GetVLibEndDate(OUT char pszEndDate[0x40]);


///////////////////////////////////////////////////////////////////////
//
// 动态加载引擎方式
//

// 初始化引擎，动态加载引擎模块方式, 同时可以创建一个 IScanSimple 实例
//
// 参数：
//  pszJMEngPath 为 libavemgr.so 路径
//  ppIScanSimple 保存创建的IScanSimple 实例
//
// 返回值：
//  0, 成功，同时ppIScanSimple 返回创建的IScanSimple 实例
//  其它，失败
//
int  JMAVEng_Init(const char* pszJMEngPath, IScanSimple** ppIScanSimple);

// 卸载模块 - 清理
//
// 参数：
//   pIScanSimple 以前创建的IScanSimple 实例, 如果已经释放，为 NULL
//
//  说明：
//   在此之前需要已经调用 IScan_Dispose 释放所有创建的 IScanSimple 实例
//	 只有所有的 IScanSimple 都释放了，才可以成功清理内存。
//
int  JMAVEng_Clear(IScanSimple* pIScanSimple);



EXTERN_C_END
