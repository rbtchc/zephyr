/*
 * Copyright (c) 2016, Eistec AB.
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
 *         Joakim Nohlgård <joakim.nohlgard@eistec.se>
 *         Joakim Eriksson <joakime@sics.se> added JSON reader parts
 */

/*
 * Zephyr Contribution by Michael Scott <michael.scott@linaro.org>
 * - Zephyr code style changes / code cleanup
 * - Move to Zephyr APIs where possible
 * - Convert to Zephyr int/uint types
 * - Remove engine dependency (replace with writer/reader context)
 * - Add write / read int64 functions
 */

/*
 * TODO:
 * - Debug formatting errors in Leshan
 * - Replace magic #'s with defines
 * - Research using Zephyr JSON lib for json_next_token()
 */

#define SYS_LOG_DOMAIN "lib/lwm2m_json"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "lwm2m_object.h"
#include "lwm2m_rw_json.h"
#include "lwm2m_rw_plain_text.h"

#define T_NONE		0
#define T_STRING_B	1
#define T_STRING	2
#define T_NAME		4
#define T_VNUM		5
#define T_OBJ		6
#define T_VAL		7

#define SEPARATOR(f)	((f & WRITER_OUTPUT_VALUE) ? "," : "")

/* Simlified JSON style reader for reading in values from a LWM2M JSON string */
int json_next_token(struct lwm2m_input_context *in, struct json_data *json)
{
	int pos;
	u8_t type = T_NONE;
	u8_t vpos_start = 0;
	u8_t vpos_end = 0;
	u8_t cont;
	u8_t wscount = 0;
	u8_t c;

	json->name_len = 0;
	json->value_len = 0;
	cont = 1;
	pos = in->inpos;

	/* We will be either at start, or at a specific position */
	while (pos < in->insize && cont) {
		c = in->inbuf[pos++];

		switch (c) {

		case '{':
			type = T_OBJ;
			break;

		case '}':
		case ',':
			if (type == T_VAL || type == T_STRING) {
				json->value = &in->inbuf[vpos_start];
				json->value_len = vpos_end - vpos_start -
						  wscount;
				type = T_NONE;
				cont = 0;
			}

			wscount = 0;
			break;

		case '\\':
			/* stuffing */
			if (pos < in->insize) {
				pos++;
				vpos_end = pos;
			}

			break;

		case '"':
			if (type == T_STRING_B) {
				type = T_STRING;
				vpos_end = pos - 1;
				wscount = 0;
			} else {
				type = T_STRING_B;
				vpos_start = pos;
			}

			break;

		case ':':
			if (type == T_STRING) {
				json->name = &in->inbuf[vpos_start];
				json->name_len = vpos_end - vpos_start;
				vpos_start = vpos_end = pos;
				type = T_VAL;
			} else {
				/* Could be in string or at illegal pos */
				if (type != T_STRING_B) {
					SYS_LOG_ERR("ERROR - illegal ':'");
				}
			}

			break;

		/* ignore whitespace */
		case ' ':
		case '\n':
		case '\t':
			if (type != T_STRING_B) {
				if (vpos_start == pos - 1) {
					vpos_start = pos;
				} else {
					wscount++;
				}
			}

			/* fallthrough */

		default:
			vpos_end = pos;

		}
	}

	if (cont == 0 && pos < in->insize) {
		in->inpos = pos;
	}

	/* OK if cont == 0 othewise we failed */
	return (cont == 0 && pos < in->insize);
}

static size_t write_begin(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path)
{
	int len;

	len = snprintf(&out->outbuf[out->outlen],
		       out->outsize - out->outlen,
		       "{\"bn\":\"/%u/%u/\",\"e\":[",
		       path->obj_id, path->obj_inst_id);
	out->writer_flags = 0; /* set flags to zero */
	if (len < 0 || len >= out->outsize) {
		return 0;
	}

	out->outlen += len;
	return (size_t)len;
}

static size_t write_end(struct lwm2m_output_context *out,
			struct lwm2m_obj_path *path)
{
	int len;

	len = snprintf(&out->outbuf[out->outlen],
		       out->outsize - out->outlen, "]}");
	if (len < 0 || len >= (out->outsize - out->outlen)) {
		return 0;
	}

	out->outlen += len;
	return (size_t)len;
}

static size_t write_begin_ri(struct lwm2m_output_context *out,
			     struct lwm2m_obj_path *path)
{
	out->writer_flags |= WRITER_RESOURCE_INSTANCE;
	return 0;
}

static size_t write_end_ri(struct lwm2m_output_context *out,
			   struct lwm2m_obj_path *path)
{
	out->writer_flags &= ~WRITER_RESOURCE_INSTANCE;
	return 0;
}

static size_t write_int32(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s32_t value)
{
	u8_t *outbuf;
	size_t outlen;
	char *sep;
	int len;

	outbuf = &out->outbuf[out->outlen];
	outlen = out->outsize - out->outlen;
	sep = SEPARATOR(out->writer_flags);
	if (out->writer_flags & WRITER_RESOURCE_INSTANCE) {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u/%u\",\"v\":%d}",
			       sep, path->res_id, path->res_inst_id, value);
	} else {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u\",\"v\":%d}",
			       sep, path->res_id, value);
	}

	if (len < 0 || len >= outlen) {
		return 0;
	}

	SYS_LOG_DBG("JSON: Write int:%s", outbuf);
	out->writer_flags |= WRITER_OUTPUT_VALUE;
	out->outlen += len;
	return (size_t)len;
}

static size_t write_int64(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s64_t value)
{
	u8_t *outbuf;
	size_t outlen;
	char *sep;
	int len;

	outbuf = &out->outbuf[out->outlen];
	outlen = out->outsize - out->outlen;
	sep = SEPARATOR(out->writer_flags);
	if (out->writer_flags & WRITER_RESOURCE_INSTANCE) {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u/%u\",\"v\":%lld}",
			       sep, path->res_id, path->res_inst_id, value);
	} else {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u\",\"v\":%lld}",
			       sep, path->res_id, value);
	}

	if (len < 0 || len >= outlen) {
		return 0;
	}

	SYS_LOG_DBG("JSON: Write int:%s", outbuf);
	out->writer_flags |= WRITER_OUTPUT_VALUE;
	out->outlen += len;
	return (size_t)len;
}

static size_t write_string(struct lwm2m_output_context *out,
			   struct lwm2m_obj_path *path,
			   const char *value, size_t strlen)
{
	u8_t *outbuf;
	size_t outlen;
	char *sep;
	size_t i;
	size_t len = 0;
	int res;

	outbuf = &out->outbuf[out->outlen];
	outlen = out->outsize - out->outlen;
	sep = SEPARATOR(out->writer_flags);
	if (out->writer_flags & WRITER_RESOURCE_INSTANCE) {
		res = snprintf(outbuf, outlen, "%s{\"n\":\"%u/%u\",\"sv\":\"",
			       sep, path->res_id, path->res_inst_id);
	} else {
		res = snprintf(outbuf, outlen, "%s{\"n\":\"%u\",\"sv\":\"",
			       sep, path->res_id);
	}

	if (res < 0 || res >= outlen) {
		return 0;
	}

	len += res;
	for (i = 0; i < strlen && len < outlen; ++i) {
		/* Escape special characters */
		/* TODO: Handle UTF-8 strings */
		if (value[i] < '\x20') {
			res = snprintf(&outbuf[len], outlen - len, "\\x%x",
				       value[i]);

			if (res < 0 || res >= (outlen - len)) {
				return 0;
			}

			len += res;
			continue;
		} else if (value[i] == '"' || value[i] == '\\') {
			outbuf[len] = '\\';
			++len;
			if (len >= outlen) {
				return 0;
			}
		}

		outbuf[len] = value[i];
		++len;
		if (len >= outlen) {
			return 0;
		}
	}

	res = snprintf(&outbuf[len], outlen - len, "\"}");
	if (res < 0 || res >= (outlen - len)) {
		return 0;
	}

	SYS_LOG_DBG("JSON: Write string:%s", outbuf);
	len += res;
	out->writer_flags |= WRITER_OUTPUT_VALUE;
	out->outlen += len;
	return len;
}

static size_t write_float32fix(struct lwm2m_output_context *out,
			       struct lwm2m_obj_path *path,
			       s32_t value, int bits)
{
	u8_t *outbuf;
	size_t outlen;
	char *sep;
	size_t len = 0;
	int res;

	outbuf = &out->outbuf[out->outlen];
	outlen = out->outsize - out->outlen;
	sep = SEPARATOR(out->writer_flags);
	if (out->writer_flags & WRITER_RESOURCE_INSTANCE) {
		res = snprintf(outbuf, outlen, "%s{\"n\":\"%u/%u\",\"v\":",
			       sep, path->res_id, path->res_inst_id);
	} else {
		res = snprintf(outbuf, outlen, "%s{\"n\":\"%u\",\"v\":",
			       sep, path->res_id);
	}

	if (res <= 0 || res >= outlen) {
		return 0;
	}

	len += res;
	outlen -= res;
	res = plain_text_write_float32fix(&outbuf[len], outlen, value, bits);
	if (res <= 0 || res >= outlen) {
		return 0;
	}

	len += res;
	outlen -= res;
	res = snprintf(&outbuf[len], outlen, "}");
	if (res <= 0 || res >= outlen) {
		return 0;
	}

	len += res;
	out->writer_flags |= WRITER_OUTPUT_VALUE;
	out->outlen += len;
	return len;
}

static size_t write_bool(struct lwm2m_output_context *out,
			 struct lwm2m_obj_path *path,
			 int value)
{
	u8_t *outbuf;
	size_t outlen;
	char *sep;
	int len;

	outbuf = &out->outbuf[out->outlen];
	outlen = out->outsize - out->outlen;
	sep = SEPARATOR(out->writer_flags);
	if (out->writer_flags & WRITER_RESOURCE_INSTANCE) {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u/%u\",\"bv\":%s}",
			       sep, path->res_id, path->res_inst_id,
			       value ? "true" : "false");
	} else {
		len = snprintf(outbuf, outlen, "%s{\"n\":\"%u\",\"bv\":%s}",
			       sep, path->res_id, value ? "true" : "false");
	}

	if (len < 0 || len >= outlen) {
		return 0;
	}

	SYS_LOG_DBG("JSON: Write bool:%s", outbuf);
	out->writer_flags |= WRITER_OUTPUT_VALUE;
	out->outlen += len;
	return (size_t)len;
}

const struct lwm2m_writer json_writer = {
	write_begin,
	write_end,
	write_begin_ri,
	write_end_ri,
	write_int32,
	write_int64,
	write_string,
	write_float32fix,
	write_bool
};
