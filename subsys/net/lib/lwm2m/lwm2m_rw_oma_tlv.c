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
#include "lwm2m_engine.h"

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

static size_t oma_tlv_put(const struct oma_tlv *tlv, u8_t *buffer, size_t len)
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

size_t oma_tlv_get(struct oma_tlv *tlv, const u8_t *buffer, size_t len)
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

static size_t put_begin_ri(struct lwm2m_output_context *out,
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
	len = oma_tlv_put(&tlv, &out->outbuf[out->outlen],
			    out->outsize - out->outlen) - 8;
	/*
	 * store position for deciding where to re-write the TLV when we
	 * know the length - NOTE: either this or memmov of buffer later...
	 */
	out->mark_pos_ri = out->outlen;
	out->outlen += len;
	return len;
}

static size_t put_end_ri(struct lwm2m_output_context *out,
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

static size_t put_int32(struct lwm2m_output_context *out,
			struct lwm2m_obj_path *path, s32_t value)
{
	size_t len;
	struct oma_tlv tlv;
	size_t tlvlen = 0;
	u8_t buf[4];
	int i;
	u8_t *buffer = &out->outbuf[out->outlen];
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;

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
	len = oma_tlv_put(&tlv, buffer, out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t put_int64(struct lwm2m_output_context *out,
			struct lwm2m_obj_path *path, s64_t value)
{
	size_t len;
	struct oma_tlv tlv;
	size_t tlvlen = 0;
	u8_t buf[8];
	int i;
	u8_t *buffer = &out->outbuf[out->outlen];
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;


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
	len = oma_tlv_put(&tlv, buffer, out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t put_string(struct lwm2m_output_context *out,
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
	len = oma_tlv_put(&tlv, &out->outbuf[out->outlen],
			    out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t put_float32fix(struct lwm2m_output_context *out,
			     struct lwm2m_obj_path *path,
			     s32_t value, int bits)
{
	size_t len;
	int e = 0;
	s32_t val = 0;
	s32_t v;
	u8_t b[4];
	struct oma_tlv tlv;
	u8_t *buffer = &out->outbuf[out->outlen];
	u8_t type = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				OMA_TLV_TYPE_RESOURCE_INSTANCE :
				OMA_TLV_TYPE_RESOURCE;
	u16_t id = out->writer_flags & WRITER_RESOURCE_INSTANCE ?
				path->res_inst_id :
				path->res_id;

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
	len = oma_tlv_put(&tlv, buffer, out->outsize - out->outlen);
	out->outlen += len;
	return len;
}

static size_t put_bool(struct lwm2m_output_context *out,
		       struct lwm2m_obj_path *path, int value)
{
	return put_int32(out, path, value != 0 ? 1 : 0);
}

static size_t get_int32(struct lwm2m_input_context *in, s32_t *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_get(&tlv, in->inbuf, in->insize);
	int i;

	if (size > 0) {
		/* will probably need to handle MSB as a sign bit? */
		for (i = 0; i < tlv.length; i++) {
			*value = (*value << 8) | tlv.value[i];
		}
		in->last_value_len = tlv.length;
	}

	return size;
}

/* TODO: research to make sure this is correct */
static size_t get_int64(struct lwm2m_input_context *in, s64_t *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_get(&tlv, in->inbuf, in->insize);
	int i;

	*value = 0;
	if (size > 0) {
		/* will probably need to handle MSB as a sign bit? */
		for (i = 0; i < tlv.length; i++) {
			*value = (*value << 8) | tlv.value[i];
		}

		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t get_string(struct lwm2m_input_context *in,
			 u8_t *value, size_t strlen)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_get(&tlv, in->inbuf, in->insize);

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

/* convert float to fixpoint */
static size_t get_float32fix(struct lwm2m_input_context *in,
			     s32_t *value, int bits)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_get(&tlv, in->inbuf, in->insize);
	int e;
	s32_t val;
	int sign = (tlv.value[0] & 0x80) != 0;

	if (size > 0) {
		/* TLV needs to be 4 bytes */
		e = ((tlv.value[0] << 1) & 0xff) | (tlv.value[1] >> 7);
		val = (((long)tlv.value[1] & 0x7f) << 16) | (tlv.value[2] << 8) |
		      tlv.value[3];
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
		in->last_value_len = tlv.length;
	}

	return size;
}

static size_t get_bool(struct lwm2m_input_context *in, int *value)
{
	struct oma_tlv tlv;
	size_t size = oma_tlv_get(&tlv, in->inbuf, in->insize);
	int i;

	if (size > 0) {
		/* will probably need to handle MSB as a sign bit? */
		for (i = 0; i < tlv.length; i++) {
			*value = (*value << 8) | tlv.value[i];
		}
		*value = *value != 0;
		in->last_value_len = tlv.length;
	}

	return size;
}

const struct lwm2m_writer oma_tlv_writer = {
	NULL,
	NULL,
	put_begin_ri,
	put_end_ri,
	put_int32,
	put_int64,
	put_string,
	put_float32fix,
	put_bool
};

const struct lwm2m_reader oma_tlv_reader = {
	get_int32,
	get_int64,
	get_string,
	get_float32fix,
	get_bool
};

static int do_write_op_tlv_item(struct lwm2m_engine_context *context,
				u8_t *data, int len)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	struct lwm2m_engine_res_inst *res = NULL;
	struct lwm2m_engine_obj_field *obj_field = NULL;
	u8_t created = 0;
	int ret, i;

	in->inbuf = data;
	in->inpos = 0;
	in->insize = len;

	ret = get_or_create_engine_obj(context, obj_inst, &created);
	if (ret < 0) {
		return ret;
	}

	obj_field = get_engine_obj_field(obj_inst->obj,
					 context->path->res_id);
	if (!obj_field) {
		return -EINVAL;
	}

	if ((obj_field->permissions & LWM2M_OP_BIT(LWM2M_OP_WRITE)) !=
	    LWM2M_OP_BIT(LWM2M_OP_WRITE)) {
		return -EPERM;
	}

	if (!obj_inst->resources || obj_inst->resource_count == 0) {
		return -EINVAL;
	}

	for (i = 0; i < obj_inst->resource_count; i++) {
		if (obj_inst->resources[i].res_id == context->path->res_id) {
			res = &obj_inst->resources[i];
			break;
		}
	}

	if (!res) {
		return -ENOENT;
	}

	return engine_write_handler(obj_inst, res, obj_field, context);
}

int do_write_op_tlv(struct lwm2m_engine_obj_inst *obj_inst,
		    struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_obj_path *path = context->path;
	size_t len;
	struct oma_tlv tlv;
	int tlvpos = 0, ret;

	while (tlvpos < in->insize) {
		len = oma_tlv_get(&tlv, &in->inbuf[tlvpos],
				   in->insize - tlvpos);

		SYS_LOG_DBG("Got TLV format First is: type:%d id:%d "
			    "len:%d (p:%d len:%d/%d)",
			    tlv.type, tlv.id, (int) tlv.length,
			    (int) tlvpos, (int) len, (int) in->insize);

		if (tlv.type == OMA_TLV_TYPE_OBJECT_INSTANCE) {
			struct oma_tlv tlv2;
			int len2;
			int pos = 0;

			path->obj_inst_id = tlv.id;
			if (tlv.length == 0) {
				/* Create only - no data */
				ret = engine_create_obj_inst(path->obj_id,
							     path->obj_inst_id,
							     obj_inst);
				if (ret < 0) {
					return ret;
				}
			}

			while (pos < tlv.length &&
			       (len2 = oma_tlv_get(&tlv2, &tlv.value[pos],
						    tlv.length - pos))) {
				if (tlv2.type == OMA_TLV_TYPE_RESOURCE) {
					path->res_id = tlv2.id;
					path->level = 3;
					ret = do_write_op_tlv_item(
							context,
							(u8_t *)&tlv.value[pos],
							len2);
					if (ret < 0) {
						return ret;
					}
				}

				pos += len2;
			}
		} else if (tlv.type == OMA_TLV_TYPE_RESOURCE) {
			path->res_id = tlv.id;
			path->level = 3;
			ret = do_write_op_tlv_item(context,
						   &in->inbuf[tlvpos], len);
			if (ret < 0) {
				return ret;
			}

			zoap_header_set_code(context->out->out_zpkt,
					     ZOAP_RESPONSE_CODE_CHANGED);
		}

		tlvpos += len;
	}

	return 0;
}
