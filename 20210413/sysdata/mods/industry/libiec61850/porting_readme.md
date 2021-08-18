# libiec61850 0.9.2.1 版本移植说明

|版本|时间|作者|内容|
|---|---|---|---|
|1.0.0|2017-01-04|于明明|首版本|

## 1 移植缘由

默认的libiec61850能够正确解析mms报文，但是asm_printf函数不能正常工作，输出不了整数数据；另外asm_printf不能解析googse和sv报文。
这些问题在libiec61850的1.0版本仍然存在，因此对此源码做了一些移植修改。

## 2 mms移植

### 2.1 iso_presentation.h

添加如下行，导出此函数
```
int
parseNormalModeParameters(IsoPresentation* self, uint8_t* buffer, int totalLength, int bufPos);

```

同时文件iso_presentation.c 380行将函数parseNormalModeParameters的static修饰符去掉。

### 2.2 asn_system.h
包含头文件
```
#include <limits.h>
```
### 2.3 constr_CHOICE.c
810行增加异常处理，避免不能输出choice类型的内容（问题不出在这，防护的意义不大）
```
		if (elm->type->xer_encoder) {
			tmper = elm->type->xer_encoder(elm->type, memb_ptr,
					ilevel + 1, flags, cb, app_key);
			if(tmper.encoded == -1) return tmper;
		}
```

### 2.4 constr_SEQUENCE.c
883行，同上
```
		/* Print the member itself */
		if (elm->type->xer_encoder) {
			tmper = elm->type->xer_encoder(elm->type, memb_ptr,
				ilevel + 1, flags, cb, app_key);
			if(tmper.encoded == -1) return tmper;
		}
```
### 2.5 其余文件

libiec61850 0.9.2.1(以下简称源码)使用的asn文件是通过文件mms-extended.asn生成，但是源码里面并没有提供此文件。源码中如下的7个文件和使用工具 `asn1c + mms-extended.asn` 生成的文件有出入，且这些出入是导致asn_printf函数不能输出整数的原因。

因此替换了源码中的此7个文件，新文件通过asn文件 https://github.com/jiajw0426/easyscada/blob/master/drivers/iec61850/protocol/src/mms/iso_mms/mms-extended.asn 生成。

此asn文件已经保存在目录KAIFA_IAF/sysdata/mms/libiec61850/src/mms/iso_mms/asn1c中。

```
1. INTEGER.c
2. INTEGER.h
3. NativeEnumerated.c
4. NativeInteger.c
5. per_support.c
6. per_support.h
7. Unsigned32.c
```

### 2.6 新增函数 xer_sprint
库提供的函数xer_fprint是将xml格式的asn报文输出到文件的，mms程序需要一个输出到缓冲区的函数。
因此参照xer_fprint新增了函数xer_sprint。

此函数在头文件xer_encoder.h中声明，在文件xer_encoder.c中定义，原型如下
```
uint8_t *
xer_sprint(uint8_t *buf, size_t buf_size, asn_TYPE_descriptor_t *td, void *sptr)
```

#### 2.6.1 参数说明
1. buf：解析后的xml报文输出缓存区
2. buf_size：缓存区大小
3. td：待解析的ASN报文首层类型
4. sptr：待解析的ASN报文内容
5. 函数返回解析后的xml报文正文区(为buf+8的地址，原因在下方说明)。

#### 2.6.2 缓冲区越界防护
函数xer_sprint将会逐层解析ASN报文，并把解析后的字符串数据追加到缓存区。为了避免缓存区溢出，特意将传入的buf空间定义成如下结构体

```
struct stream_buf_t {
	size_t size;
	size_t len;
	void *buf;
};
```

每次在写入的时候，都要判断下是否还有剩余的空间可供使用。

```
static int xer__print2buf(const void *buffer, size_t size, void *app_key) {
	struct stream_buf_t *stream = app_key;

	if (stream->len + size > stream->size)
		return -1;
	
	memcpy(stream->buf, buffer, size);
	stream->len += size;

	return 0;
}
```

## 3 goose移植
### 3.1 生成asn头文件

源码自带goose的asn文件，保存在目录KAIFA_IAF/sysdata/mms/libiec61850/src/goose中。
通过命令 `asn1c iec61850_goose.asn` 生成头文件。
生成的和goose相关的头文件以及C文件，都保存在目录KAIFA_IAF/sysdata/mms/libiec61850/src/goose中。


### 3.2 ethernet_linux.c
goose程序需要控制网卡进入混杂模式，以便监听网络上的数据包。
将此文件中的函数getInterfaceIndex的static修饰符去掉。

### 3.3 示范程序
在目录KAIFA_IAF/sysdata/mms/libiec61850/src/goose中，提供了如何通过链路层协议抓取googse报文以及如何解析的示范程序，源码文件名为goose_des.c，Makefile文件为Goose_Makefile。

## 4 sv移植
### 4.1 生成asn头文件

源码不带sv的asn文件。
从wireshark源码https://github.com/kimgr/asn1ate/blob/master/testdata/public/wireshark.asn下载sv的asn文件，保存在目录KAIFA_IAF/sysdata/mms/libiec61850/src/sampled_values中。

通过命令 `asn1c sv.asn` 生成头文件。
生成的和sv相关的头文件以及C文件，都保存在目录KAIFA_IAF/sysdata/mms/libiec61850/src/sampled_values中。

### 4.2 示范程序
在目录KAIFA_IAF/sysdata/mms/libiec61850/src/sampled_values中，提供了如何通过链路层协议抓取sv报文以及如何解析的示范程序，源码文件名为sv_des.c，Makefile文件为SV_Makefile。


