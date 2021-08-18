#pragma once

#include "ScanSimpleSDK.h"

// 工作状态枚举
enum EWorkerState {
	stateIdle,
	stateScanning,
	statePausing,
	stateStopping
};

// 扫描通知回调
struct IScanNotify;

//
// 异步扫描接口，用于扫描程序，不适合病毒监控
//
struct IScanWorker {
protected:
	~IScanWorker() = default;

public:
	//
	// 释放接口
	//
	virtual void AV_CALLTYPE Dispose() PURE;

	/**
	 * @brief 设置扫描回调通知接口
	 */
	virtual void AV_CALLTYPE SetNotify(IScanNotify* pNotify) PURE;
	/**
	 * @brief 将扫描选项恢复到默认值
	 *		重置所有设置及扫描目标、忽略目标、忽略路径等
	 *
	 * @retval 如果正在扫描或暂停返回 false ，否则可以重置则进行重置并返回 true
	 */
	virtual bool AV_CALLTYPE Reset() PURE;

	// 设置扫描选项
	virtual void AV_CALLTYPE SetOptions(const ScanOptions* pOptions) PURE;

	// 用于在服务中模拟用户令牌访问文件时
	// 保留，可不用
	//
	// 参数：
	//		unProcessId	根据此进程Id获取用户令牌Token
	virtual void AV_CALLTYPE SetClientProcessId(uint32_t unProcessId) PURE;

	// 设置特定前缀病毒名的处理方式
	// 未用，保留
	virtual void AV_CALLTYPE SetHandleMode(const TCHAR* szVirusPrefix, EHandleMode handleMode) PURE;

	// 增加只扫描扩展名，一次添加一个，带 . 前缀
	virtual void AV_CALLTYPE AddTargetExt(const TCHAR* szExt) PURE;

	// 增加忽略扩展名，带 . 前缀
	// 根据扫描级别控制
	// unLevel 大于 AdjustLevel设置的扫描级别时，扫描时忽略带该扩展名的文件
	virtual void AV_CALLTYPE AddIgnoreExt(const TCHAR* szExt, uint32_t unLevel) PURE;

	/**
	@brief 添加扫描目标

	添加需要扫描的目标，目标可以是文件夹或文件路径，也可以是特定的扫描目标，特定扫描目标以
	\\!!\ 为前缀，后面跟指定的目标名称，已定义的目标有：
	Document
	Computer
	Autorun
	Memory
	Cache&Temp
	SystemFolder
	Desktop
	Program

	// 以下暂未实现
	//AllDisk
	//MailBox
	//AllCDROM
	//AllRemovable
	//MBR %d : 第几块硬盘的主引导区
	//BOOT %c ：逻辑盘 C 的引导区
	//使用时请注意大小写，区分大小写

	@param szUri 扫描目标路径

	@retval 一般返回 S_OK
	*/
	virtual void AV_CALLTYPE AddTarget(const TCHAR* szUri) PURE;

	// 添加忽略文件夹，绝对路径模式
	virtual void AV_CALLTYPE AddIgnoreFolder(const TCHAR* szPath) PURE;

	// 开始扫描, 异步方式
	// 参数：
	//	unWorkerCount,	扫描线程数量
	//	unFromId,		启动扫描来源，未用，保留
	//  unLevel,		扫描级别， 这里的unLevel未用， 如要控制扫描级别，使用 AdjustLevel
	virtual bool AV_CALLTYPE Start(uint32_t unWorkerCount, uint32_t unFromId=0, uint32_t unLevel= UINT32_MAX) PURE;
	virtual bool AV_CALLTYPE Pause() PURE;
	virtual void AV_CALLTYPE Resume() PURE;

	// 停止扫描, 异步方式
	virtual void AV_CALLTYPE Stop() PURE;

	// 设置扫描级别
	//
	// 引擎缺省扫描级别为 UINT32_MAX
	// 
	virtual void AV_CALLTYPE AdjustLevel(uint32_t unLevel) PURE;

	// 查询当前引擎状态（空闲/扫描中/暂停中）
	virtual EWorkerState AV_CALLTYPE QueryState(uint32_t& unFromId) PURE;

	// 未用, 保留
	virtual void AV_CALLTYPE OnSettingChanged() PURE;

	// // 设置扫描时间，speed = 0x80/81/82/.../0x90	// 扫描速度控制 - 全速/最慢
	// 缺省为0x80， 最快
	virtual void AV_CALLTYPE SetSpeed(int speed = 0x80) PURE;

	// 获取当前扫描速度设置
	// 返回 0x80/81/82/.../0x90	// - 全速/最慢
	virtual int  AV_CALLTYPE GetSpeed() PURE;

};

//
// 扫描通知回调
//
struct IScanNotify {
protected:
	~IScanNotify() = default;
public:
	// 下面四个函数在调度线程中运行

	// 通知: 调度线程开始
	virtual void AV_CALLTYPE OnPreStart() PURE;

	// 通知: 开始扫描一个扫描目标
	// 参数：
	//		szUri			当前扫描对象，是一个AddTarget添加的值
	virtual void AV_CALLTYPE OnTargetStart(const TCHAR* szUri) PURE;

	// 通知: 所有目标扫描结束
	// 参数：
	//		bCancel			true = 用户终止扫描
	//		fileTotal		已扫描文件数
	//		virTotal		发现病毒数
	virtual void AV_CALLTYPE OnPostCompleted(bool bCancel, uint64_t fileTotal, uint64_t virTotal) PURE;

	// 通知: 扫描进度
	// 说明: 扫描进度是根据扫描目标、待扫描的文件数计算的一个参考量，并不精确
	// 参数：
	//		ullFull			满分值
	//		ullComplete		当前值
	//		fileTotal		当前已扫描文件数
	virtual void AV_CALLTYPE OnReportProgress(uint64_t ullFull, uint64_t ullComplete, uint64_t fileTotal) PURE;

	// 下面的函数在扫描线程中运行
	/**
	 * 开始扫描一个文件时的回调通知
	 * @param szUri 具体的扫描文件路径, 如果是压缩包中的文件，使用 "->" 分隔压缩包路径和包中的文件路径
	 * @param unZipLevel 解压层数
	 * @param unFileSize 文件大小
	 * @param pLastRecNo 返回最近的扫描记录，如果为 nullptr 则不需要查询指纹 --- 暂未用
	 */
	// 返回值被忽略，可以为modeFind
	virtual EHandleMode AV_CALLTYPE OnPreScanStart(const TCHAR* szUri, uint32_t unZipLevel, uint64_t unFileSize, uint32_t* pLastRecNo) PURE;
	
	/**
	 * 大于 10MB 的文件在备份时通知，可用于界面上提示"正在备份..."
	 */
	virtual void AV_CALLTYPE OnBackupStart( const TCHAR* szPath) PURE;
	virtual void AV_CALLTYPE OnBackupFinish(const TCHAR* szPath) PURE;

	/**
	 * 用于通知界面程序备份失败，通常是磁盘不足
	 */
	// 未使用
	// 返回值可以为modeFind
	virtual EHandleMode AV_CALLTYPE OnBackupFailed(const TCHAR* szPath) PURE;

	// 用于步进工作进度，可不用
	virtual void AV_CALLTYPE OnStep() PURE;

	// 通知发现病毒
	virtual void AV_CALLTYPE OnVirus(const TCHAR* szPath, const ScanResult* pResult) PURE;

	// 通知文件扫描结束，未发现病毒
	virtual void AV_CALLTYPE OnFileIsSafe(const TCHAR* szPath) PURE;
};


EXTERN_C_BEGIN

	//
	// 创建异步扫描接口
	//
	IScanWorker* AV_CALLTYPE ScanWorkerCreate();

	// Linux下 内部接口，显示内存使用信息，用于分析
	// Win下实现为空
	LIB_PUBLIC 	void AV_CALLTYPE ScanTrace(int cmd, const char* pos);


EXTERN_C_END