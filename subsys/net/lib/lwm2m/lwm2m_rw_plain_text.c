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
 * - Type cleanups
 * - Cleanup integer parsing
 */

#define SYS_LOG_DOMAIN "lib/lwm2m_plain_text"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwm2m_object.h"
#include "lwm2m_rw_plain_text.h"

size_t plain_text_write_float32fix(u8_t *outbuf, size_t outlen, s32_t value,
				   int bits)
{
	s64_t v;
	unsigned long integer_part;
	unsigned long frac_part;
	int n, o = 0;

	if (outlen == 0) {
		return 0;
	}

	if (value < 0) {
		*outbuf++ = '-';
		outlen--;
		o = 1;
		value = -value;
	}

	integer_part = (unsigned long)(value >> bits);
	v = value - (integer_part << bits);
	v = (v * 100) >> bits;
	frac_part = (unsigned long)v;
	n = snprintf(outbuf, outlen, "%lu.%02lu", integer_part, frac_part);

	if (n < 0 || n >= outlen) {
		return 0;
	}

	return n + o;
}

static size_t plain_text_read_int32(const u8_t *inbuf, size_t len, s32_t *value)
{
	int i, neg = 0;

	*value = 0;

	for (i = 0; i < len; i++) {
		if (inbuf[i] >= '0' && inbuf[i] <= '9') {
			*value = *value * 10 + (inbuf[i] - '0');
		} else if (inbuf[i] == '-' && i == 0) {
			neg = 1;
		} else {
			break;
		}
	}

	if (neg) {
		*value = -*value;
	}

	return i;
}

static size_t plain_text_read_int64(const u8_t *inbuf, size_t len, s64_t *value)
{
	int i, neg = 0;

	*value = 0;

	for (i = 0; i < len; i++) {
		if (inbuf[i] >= '0' && inbuf[i] <= '9') {
			*value = *value * 10 + (inbuf[i] - '0');
		} else if (inbuf[i] == '-' && i == 0) {
			neg = 1;
		} else {
			break;
		}
	}

	if (neg) {
		*value = -*value;
	}

	return i;
}

static size_t plain_text_read_float32fix(const u8_t *inbuf, size_t len,
					 s32_t *value, int bits)
{
	int i, dot = 0, neg = 0;
	s32_t counter = 0, integerpart = 0, frac = 0;

	for (i = 0; i < len; i++) {
		if (inbuf[i] >= '0' && inbuf[i] <= '9') {
			counter = counter * 10 + (inbuf[i] - '0');
			frac = frac * 10;
		} else if (inbuf[i] == '.' && dot == 0) {
			integerpart = counter;
			counter = 0;
			frac = 1;
			dot = 1;
		} else if (inbuf[i] == '-' && i == 0) {
			neg = 1;
		} else {
			break;
		}
	}

	if (dot == 0) {
		integerpart = counter;
		counter = 0;
		frac = 1;
	}

	*value = integerpart << bits;
	if (frac > 1) {
		*value += ((counter << bits) / frac);
	}

	SYS_LOG_DBG("READ FLOATFIX: '%s'(%zd) => int:%d "
		    "cnt:%d frac:%d value=%d",
		    inbuf, len, integerpart, counter, frac, *value);
	if (neg) {
		*value = -*value;
	}

	return i;
}

static size_t write_int32(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s32_t value)
{
	int len;

	len = snprintf(&out->outbuf[out->outlen], out->outsize - out->outlen,
		       "%d", value);
	if (len < 0 || len >= (out->outsize - out->outlen)) {
		return 0;
	}

	out->outlen += len;
	return (size_t)len;
}

static size_t write_int64(struct lwm2m_output_context *out,
			  struct lwm2m_obj_path *path,
			  s64_t value)
{
	int len;

	len = snprintf(&out->outbuf[out->outlen], out->outsize - out->outlen,
		       "%lld", value);
	if (len < 0 || len >= (out->outsize - out->outlen)) {
		return 0;
	}

	out->outlen += len;
	return (size_t)len;
}

static size_t write_float32fix(struct lwm2m_output_context *out,
			       struct lwm2m_obj_path *path,
			       s32_t value, int bits)
{
	size_t len;

	len = plain_text_write_float32fix(&out->outbuf[out->outlen],
					  out->outsize - out->outlen,
					  value, bits);
	out->outlen += len;
	return len;
}

static size_t write_string(struct lwm2m_output_context *out,
			   struct lwm2m_obj_path *path,
			   const char *value, size_t strlen)
{
	if (strlen >= (out->outsize - out->outlen)) {
		return 0;
	}

	memmove(&out->outbuf[out->outlen], value, strlen);
	out->outbuf[strlen] = '\0';
	out->outlen += strlen;
	return strlen;
}

static size_t write_bool(struct lwm2m_output_context *out,
			 struct lwm2m_obj_path *path,
			 int value)
{
	if ((out->outsize - out->outlen) > 0) {
		if (value) {
			out->outbuf[out->outlen] = '1';
		} else {
			out->outbuf[out->outlen] = '0';
		}

		out->outlen += 1;
		return 1;
	}

	return 0;
}

static size_t read_int32(struct lwm2m_input_context *in,
			 s32_t *value)
{
	int size;

	size = plain_text_read_int32(in->inbuf, in->insize, value);
	in->last_value_len = size;
	return size;
}

static size_t read_int64(struct lwm2m_input_context *in,
			 s64_t *value)
{
	int size;

	size = plain_text_read_int64(in->inbuf, in->insize, value);
	in->last_value_len = size;
	return size;
}

static size_t read_string(struct lwm2m_input_context *in,
			  u8_t *value, size_t strlen)
{
	/* The outbuffer can't contain the full string including ending zero */
	if (strlen <= in->insize) {
		return 0;
	}

	memcpy(value, in->inbuf, in->insize);
	value[in->insize] = '\0';
	in->last_value_len = in->insize;
	return in->insize;
}

static size_t read_float32fix(struct lwm2m_input_context *in,
			      s32_t *value, int bits)
{
	size_t size;

	size = plain_text_read_float32fix(in->inbuf, in->insize, value, bits);
	in->last_value_len = size;
	return size;
}

static size_t read_bool(struct lwm2m_input_context *in,
			int *value)
{
	if (in->insize > 0) {
		if (*in->inbuf == '1' || *in->inbuf == '0') {
			*value = (*in->inbuf == '1') ? 1 : 0;
			in->last_value_len = 1;
			return 1;
		}
	}

	return 0;
}

const struct lwm2m_writer plain_text_writer = {
	NULL,
	NULL,
	NULL,
	NULL,
	write_int32,
	write_int64,
	write_string,
	write_float32fix,
	write_bool
};

const struct lwm2m_reader plain_text_reader = {
	read_int32,
	read_int64,
	read_string,
	read_float32fix,
	read_bool
};
