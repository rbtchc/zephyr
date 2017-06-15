/*
 * Copyright (c) 2015, Yanzi Networks AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Original Authors:
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

/*
 * Zephyr Contribution by Michael Scott <michael.scott@linaro.org>
 * - Zephyr code style changes / code cleanup
 * - Move to Zephyr APIs where possible
 * - Convert to Zephyr int/uint types
 * - Remove engine dependency (replace with writer context)
 * - Add write int64 function
 */

/*
 * TODO:
 * - Lots of byte-order API clean up
 * - Var / parameter type cleanup
 * - Replace magic #'s with defines
 */

#define SYS_LOG_DOMAIN "lib/lwm2m_oma_tlv"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <string.h>
#include <stdint.h>

#include "lwm2m_rw_oma_tlv.h"

static u8_t get_len_type(const struct oma_tlv *tlv)
{
	if (tlv->length < 8) {
		return 0;
	} else if (tlv->length < 0x100) {
		return 1;
	} else if (tlv->length < 0x10000) {
		return 2;
	}

	return 3;
}

static size_t oma_tlv_write(const struct oma_tlv *tlv, u8_t *buffer, size_t len)
{
	int pos;
	u8_t len_type;

	/* len type is the same as number of bytes required for length */
	len_type = get_len_type(tlv);
	pos = 1 + len_type;
	/* ensure that we do not write too much */
	if (len < tlv->length + pos) {
		SYS_LOG_ERR("OMA-TLV: Could not write the TLV - buffer overflow"
			    " (len:%zd < tlv->length:%d + pos:%d)",
			    len, tlv->length, pos);
		return 0;
	}

	/* first type byte in TLV header */
	buffer[0] = (tlv->type << 6) |
		    (tlv->id > 255 ? (1 << 5) : 0) |
		    (len_type << 3) |
		    (len_type == 0 ? tlv->length : 0);
	pos = 1;

	/* The ID */
	if (tlv->id > 255) {
		buffer[pos++] = (tlv->id >> 8) & 0xff;
	}

	buffer[pos++] = tlv->id & 0xff;

	/* Add length if needed - unrolled loop ? */
	if (len_type > 2) {
		buffer[pos++] = (tlv->length >> 16) & 0xff;
	}

	if (len_type > 1) {
		buffer[pos++] = (tlv->length >> 8) & 0xff;
	}

	if (len_type > 0) {
		buffer[pos++] = tlv->length & 0xff;
	}

	/* finally add the value */
	if (tlv->value != NULL && tlv->length > 0) {
		memcpy(&buffer[pos], tlv->value, tlv->length);
	}

	/* TODO: Add debug print of TLV */
	return pos + tlv->length;
}

static size_t oma_tlv_write_int32(u8_t type, s16_t id, s32_t value,
				  u8_t *buffer, size_t len)
{
	struct oma_tlv tlv;
	size_t tlvlen = 0;
	u8_t buf[4];
	int i;

	SYS_LOG_DBG("Exporting s32 %d %d ", id, value);

	buf[3] = value & 0xff;
	value = value >> 8;
	for (i = 1; value > 0 && i < 4; i++) {
		buf[3 - i] = value & 0xff;
		value = value >> 8;
	}

	tlvlen = i;

	/* export INT as TLV */
	SYS_LOG_DBG("len: %zu", tlvlen);
	tlv.type = type;
	tlv.length = tlvlen;
	tlv.value = &buf[3 - (tlvlen - 1)];
	tlv.id = id;
	return oma_tlv_write(&tlv, buffer, len);
}

static size_t oma_tlv_write_int64(u8_t type, s16_t id, s64_t value,
				  u8_t *buffer, size_t len)
{
	struct oma_tlv tlv;
	size_t tlvlen = 0;
	u8_t buf[8];
	int i;

	SYS_LOG_DBG("Exporting s64 %d %lld ", id, value);

	buf[7] = value & 0xff;
	value = value >> 8;
	for (i = 1; value > 0 && i < 8; i++) {
		buf[7 - i] = value & 0xff;
		value = value >> 8;
	}

	tlvlen = i;

	/* export INT64 as TLV */
	SYS_LOG_DBG("len: %zu", tlvlen);
	tlv.type = type;
	tlv.length = tlvlen;
	tlv.value = &buf[7 - (tlvlen - 1)];
	tlv.id = id;
	return oma_tlv_write(&tlv, buffer, len);
}

/* convert fixpoint 32-bit to a IEEE Float in the byte array*/
static size_t oma_tlv_write_float32(u8_t type, s16_t id, s32_t value, int bits,
				    u8_t *buffer, size_t len)
{
	int e = 0;
	s32_t val = 0;
	s32_t v;
	u8_t b[4];
	struct oma_tlv tlv;

	v = value;
	if (v < 0) {
		v = -v;
	}

	while (v > 1) {
		val = (val >> 1);

		if (v & 1) {
			val = val | (1L << 22);
		}

		v = (v >> 1);
		e++;
	}

	/* convert to the thing we should have */
	e = e - bits + 127;
	if (value == 0) {
		e = 0;
	}

	/* is this the right byte order? */
	b[0] = (value < 0 ? 0x80 : 0) | (e >> 1);
	b[1] = ((e & 1) << 7) | ((val >> 16) & 0x7f);
	b[2] = (val >> 8) & 0xff;
	b[3] = val & 0xff;

	/* construct the TLV */
	tlv.type = type;
	tlv.length = 4;
	tlv.value = b;
	tlv.id = id;
	return oma_tlv_write(&tlv, buffer, len);
}

size_t oma_tlv_read(struct oma_tlv *tlv, const u8_t *buffer, size_t len)
{
	u8_t len_type;
	u8_t len_pos = 1;
	size_t tlv_len;

	tlv->type = (buffer[0] >> 6) & 3;
	len_type = (buffer[0] >> 3) & 3;
	len_pos = 1 + (((buffer[0] & (1 << 5)) != 0) ? 2 : 1);
	tlv->id = buffer[1];

	/* if len_pos > 2 it means that there are more ID to read */
	if (len_pos > 2) {
		tlv->id = (tlv->id << 8) + buffer[2];
	}

	if (len_type == 0) {
		tlv_len = buffer[0] & 7;
	} else {
		/* read the length */
		tlv_len = 0;
		while (len_type > 0) {
			tlv_len = tlv_len << 8 | buffer[len_pos++];
			len_type--;
		}
	}

	/* and read out the data??? */
	tlv->length = tlv_len;
	tlv->value = &buffer[len_pos];
	return len_pos + tlv_len;
}

static s32_t oma_tlv_get_int32(const struct oma_tlv *tlv)
{
	int i;
	s32_t value = 0;

	/* will probably need to handle MSB as a sign bit? */
	for (i = 0; i < tlv->length; i++) {
		value = (value << 8) | tlv->value[i];
	}

	return value;
}

static s64_t oma_tlv_get_int64(const struct oma_tlv *tlv)
{
	int i;
	s64_t value = 0;

	/* will probably need to handle MSB as a sign bit? */
	for (i = 0; i < tlv->length; i++) {
		value = (value << 8) | tlv->value[i];
	}

	return value;
}

/* convert float to fixpoint */
static size_t oma_tlv_float32_to_fix(const struct oma_tlv *tlv,
				     s32_t *value, int bits)
{
	/* TLV needs to be 4 bytes */
	int e;
	s32_t val;
	int sign = (tlv->value[0] & 0x80) != 0;

	e = ((tlv->value[0] << 1) & 0xff) | (tlv->value[1] >> 7);
	val = (((long)tlv->value[1] & 0x7f) << 16) | (tlv->value[2] << 8) |
	      tlv->value[3];
	e = e - 127 + bits;

	/* e corresponds to the number of times we need to roll the number */
	SYS_LOG_DBG("Actual e=%d", e);
	e = e - 23;
	SYS_LOG_DBG("E after sub %d", e);
	val = val | 1L << 23;
	if (e > 0) {
		val = val << e;
	} else {
		val = val >> -e;
	}

	*value = sign ? -val : val;
	return 4;
}

static size_t write_begin_ri(struct lwm2m_output_context *out,
			     struct lwm2m_obj_path *path)
{
	/* set some flags in state */
	struct oma_tlv tlv;
	size_t len;

	out->writer_flags |= WRITER_RESOURCE_INSTANCE;
	tlv.type = OMA_TLV_TYPE_MULTI_RESOURCE;
	tlv.length = 8; /* create an 8-bit TLV */
	tlv.value = NULL;
	tlv.id = path->res_id;
	/* we remove the nonsense payload here (len = 8) */
	len = oma_tlv_write(&tlv, &out->outbuf[out->outlen],
			    out->outsize - out->outlen) - 8;
	/*
	 * store position for deciding where to re-write the TLV when we
	 * know the length - NOTE: either this or memmov of buffer later...
	 */
	out->mark_pos_ri = out->outlen;
	out->outlen += len;
	return len;
}

static size_t write_end_ri(struct lwm2m_output_context *out,
			   struct lwm2m_obj_path *path)
{
	/* clear out state info */
	int pos = 2; /* this is the length pos */
	size_t len;

	out->writer_flags &= ~WRITER_RESOURCE_INSTANCE;
	if (path->res_id > 0xff) {
		pos++;
	}

	len = out->outlen - out->mark_pos_ri;

	/* update the length byte... Assume TLV header is pos + 1 bytes. */
	out->outbuf[pos + out->mark_pos_ri] = len - (pos + 1);
	return 0;
}

static size_t write_int32(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s32_t value)
{
	size_t len;
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;

	len = oma_tlv_write_int32(type, id, value, &out->outbuf[out->outlen],
				  out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t write_int64(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s64_t value)
{
	size_t len;
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;

	len = oma_tlv_write_int64(type, id, value, &out->outbuf[out->outlen],
				  out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t write_string(struct lwm2m_output_context *out,
			   struct lwm2m_obj_path *path,
			   const char *value, size_t strlen)
{
	size_t len;
	struct oma_tlv tlv;

	tlv.type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	tlv.value = (u8_t *)value;
	tlv.length = (u32_t)strlen;
	tlv.id = path->res_id;
	len = oma_tlv_write(&tlv, &out->outbuf[out->outlen],
			    out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t write_float32fix(struct lwm2m_output_context *out,
			       struct lwm2m_obj_path *path,
			       s32_t value, int bits)
{
	size_t len;
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;

	len = oma_tlv_write_float32(type, id, value, bits,
				    &out->outbuf[out->outlen],
				    out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t write_bool(struct lwm2m_output_context *out,
			 struct lwm2m_obj_path *path,
			 int value)
{
	return write_int32(out, path, value != 0 ? 1 : 0);
}

static size_t read_int32(struct lwm2m_input_context *in, s32_t *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_read(&tlv, in->inbuf, in->insize);

	if (size > 0) {
		*value = oma_tlv_get_int32(&tlv);
		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t read_int64(struct lwm2m_input_context *in,
			 s64_t *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_read(&tlv, in->inbuf, in->insize);

	if (size > 0) {
		*value = oma_tlv_get_int64(&tlv);
		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t read_string(struct lwm2m_input_context *in,
			  u8_t *value, size_t strlen)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_read(&tlv, in->inbuf, in->insize);

	if (size > 0) {
		if (strlen <= tlv.length) {
			/*
			 * The outbuffer can not contain the
			 * full string including ending zero
			 */
			return 0;
		}

		memcpy(value, tlv.value, tlv.length);
		value[tlv.length] = '\0';
		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t read_float32fix(struct lwm2m_input_context *in,
			      s32_t *value, int bits)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_read(&tlv, in->inbuf, in->insize);

	if (size > 0) {
		oma_tlv_float32_to_fix(&tlv, value, bits);
		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t read_bool(struct lwm2m_input_context *in,
			int *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_read(&tlv, in->inbuf, in->insize);

	if (size > 0) {
		*value = oma_tlv_get_int32(&tlv) != 0;
		in->last_value_len = tlv.length;
	}

	return size;
}

const struct lwm2m_writer oma_tlv_writer = {
	NULL,
	NULL,
	write_begin_ri,
	write_end_ri,
	write_int32,
	write_int64,
	write_string,
	write_float32fix,
	write_bool
};

const struct lwm2m_reader oma_tlv_reader = {
	read_int32,
	read_int64,
	read_string,
	read_float32fix,
	read_bool
};
