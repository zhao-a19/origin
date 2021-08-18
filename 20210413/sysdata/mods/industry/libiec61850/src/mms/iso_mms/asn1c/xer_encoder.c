/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/******************************************************************************************* 
*文件:    xer_decoder.c                                                                            
*描述:    将内存数据翻译成xml格式                                                                      
*                                                                                            
*作者:    于明明                                                                             
*日期:    2017-01-03                                                                         
*修改:      增加函数xer_sprint，将xml字符串保存到缓存区      ------>     2017-01-03                       
*                                                                                            
*******************************************************************************************/ 


/*
 * The XER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
xer_encode(asn_TYPE_descriptor_t *td, void *sptr,
	enum xer_encoder_flags_e xer_flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	asn_enc_rval_t er, tmper;
	const char *mname;
	size_t mlen;
	int xcan = (xer_flags & XER_F_CANONICAL) ? 1 : 2;

	if(!td || !sptr) goto cb_failed;

	mname = td->xml_tag;
	mlen = strlen(mname);

	_ASN_CALLBACK3("<", 1, mname, mlen, ">", 1);

	tmper = td->xer_encoder(td, sptr, 1, xer_flags, cb, app_key);
	if(tmper.encoded == -1) return tmper;

	_ASN_CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

	er.encoded = 4 + xcan + (2 * mlen) + tmper.encoded;

	_ASN_ENCODED_OK(er);
cb_failed:
	_ASN_ENCODE_FAILED;
}

/*
 * This is a helper function for xer_fprint, which directs all incoming data
 * into the provided file descriptor.
 */
static int
xer__print2fp(const void *buffer, size_t size, void *app_key) {
	FILE *stream = (FILE *)app_key;

	if(fwrite(buffer, 1, size, stream) != size)
		return -1;

	return 0;
}

int
xer_fprint(FILE *stream, asn_TYPE_descriptor_t *td, void *sptr) {
	asn_enc_rval_t er;

	if(!stream) stream = stdout;
	if(!td || !sptr)
		return -1;
	
	er = xer_encode(td, sptr, XER_F_BASIC, xer__print2fp, stream);
	if(er.encoded == -1)
		return -1;

	return fflush(stream);
}

/***
新增函数 xer_sprint
库提供的函数xer_fprint是将xml格式的asn报文输出到文件的，mms程序需要一个输出到缓冲区的函数。
因此参照xer_fprint新增了函数xer_sprint。

函数xer_sprint将会逐层解析ASN报文，并把解析后的字符串数据追加到缓存区。
为了避免缓存区溢出，特意将传入的buf空间定义成结构体stream_buf_t类型，
在缓存区的起始地址保存了缓存区大小和已使用大小
函数xer__print2buf在每次在写入的时候，都要判断下是否还有剩余的空间可供使用。
***/

struct stream_buf_t {
	size_t size;
	size_t len;
	uint8_t buf[1];
};

static int xer__print2buf(const void *buffer, size_t size, void *app_key) {
	struct stream_buf_t *stream = app_key;

	if (stream->len + size > stream->size) 
		return -1;
	
	memcpy(stream->buf + stream->len, buffer, size);
	stream->len += size;
	
	return 0;
}

uint8_t *
xer_sprint(uint8_t *buf, size_t buf_size, asn_TYPE_descriptor_t *td, void *sptr) {
	asn_enc_rval_t er;
	struct stream_buf_t *stream = (struct stream_buf_t *)buf;
	size_t data_offset = offsetof(struct stream_buf_t, buf);
	size_t align = ((uint32_t)buf + 3)/4*4 - (uint32_t)buf;

	data_offset += align; // buf address may be not align as int.

	if(!td || !sptr || !buf || buf_size < data_offset)
		return NULL;

	stream->size = buf_size - data_offset;
	stream->len = 0;
	
	er = xer_encode(td, sptr, XER_F_CANONICAL, xer__print2buf , buf);
	if(er.encoded == -1)
		return NULL;

	return stream->buf;
}
