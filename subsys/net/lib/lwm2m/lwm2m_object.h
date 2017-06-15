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

#ifndef LWM2M_OBJECT_H_
#define LWM2M_OBJECT_H_

/* stdint conversions */
#include <zephyr/types.h>
#include <stddef.h>
#include <net/net_ip.h>
#include <net/zoap.h>
#include <net/lwm2m.h>
#include <misc/printk.h>
#include <kernel.h>

/* adjust console logging function */
#define printf(...) printk(__VA_ARGS__)

/* Operation permissions on the resources - read/write/execute */
#define LWM2M_RESOURCE_READ    0x10000
#define LWM2M_RESOURCE_WRITE   0x20000
#define LWM2M_RESOURCE_EXECUTE 0x40000

/* Defines for the resource definition array */
#define RO(x) (x | LWM2M_RESOURCE_READ)
#define WO(x) (x | LWM2M_RESOURCE_WRITE)
#define RW(x) (x | LWM2M_RESOURCE_READ | LWM2M_RESOURCE_WRITE)
#define EX(x) (x | LWM2M_RESOURCE_EXECUTE)


enum lwm2m_operation {
	LWM2M_OP_NONE,
	LWM2M_OP_READ,
	LWM2M_OP_DISCOVER,
	LWM2M_OP_WRITE,
	LWM2M_OP_WRITE_ATTR,
	LWM2M_OP_EXECUTE,
	LWM2M_OP_CREATE,
	LWM2M_OP_DELETE
};

/* LWM2M / CoAP Content-Formats */
enum lwm2m_content_format {
	PLAIN_TEXT		= 0,
	APP_LINK_FORMAT		= 40,
	APP_OCTET_STREAM	= 42,
	APP_EXI			= 47,
	APP_JSON		= 50,
	LWM2M_TEXT_PLAIN	= 1541,
	LWM2M_OLD_TLV		= 1542,
	LWM2M_OLD_JSON		= 1543,
	LWM2M_OLD_OPAQUE	= 1544,
	LWM2M_TLV		= 11542,
	LWM2M_JSON		= 11543
};

/* remember that we have already output a value - can be between two block's */
#define WRITER_OUTPUT_VALUE      1
#define WRITER_RESOURCE_INSTANCE 2

struct lwm2m_engine_obj;
struct lwm2m_engine_context;

/* path representing object instances */
struct lwm2m_obj_path {
	u16_t obj_id;
	u16_t obj_inst_id;
	u16_t res_id;
	u16_t res_inst_id;
	u8_t  level;  /* 0/1/2/3 = 3 = resource */
};

struct lwm2m_output_context {
	struct zoap_packet *out_zpkt;
	u8_t writer_flags;	/* flags for reader/writer */
	u8_t *outbuf;
	u16_t outsize;
	u32_t outlen;
	u8_t mark_pos_ri;	/* mark pos for last resource instance */
	int last_rpos;
	const struct lwm2m_writer *writer;
};

struct lwm2m_input_context {
	struct zoap_packet *in_zpkt;
	u8_t *inbuf;
	u16_t insize;
	s32_t inpos;
	u16_t last_value_len;
	const struct lwm2m_reader *reader;
};

/* LWM2M format writer for the various formats supported */
struct lwm2m_writer {
	size_t (*write_begin)(struct lwm2m_output_context *out,
			      struct lwm2m_obj_path *path);
	size_t (*write_end)(struct lwm2m_output_context *out,
			    struct lwm2m_obj_path *path);
	size_t (*write_begin_ri)(struct lwm2m_output_context *out,
				 struct lwm2m_obj_path *path);
	size_t (*write_end_ri)(struct lwm2m_output_context *out,
			       struct lwm2m_obj_path *path);
	size_t (*write_int32)(struct lwm2m_output_context *out,
			      struct lwm2m_obj_path *path,
			      s32_t value);
	size_t (*write_int64)(struct lwm2m_output_context *out,
			      struct lwm2m_obj_path *path,
			      s64_t value);
	size_t (*write_string)(struct lwm2m_output_context *out,
			       struct lwm2m_obj_path *path,
			       const char *value, size_t strlen);
	size_t (*write_float32fix)(struct lwm2m_output_context *out,
				   struct lwm2m_obj_path *path,
				   s32_t value, int bits);
	size_t (*write_bool)(struct lwm2m_output_context *out,
			     struct lwm2m_obj_path *path,
			     int value);
};

struct lwm2m_reader {
	size_t (*read_int32)(struct lwm2m_input_context *in,
			     s32_t *value);
	size_t (*read_int64)(struct lwm2m_input_context *in,
			     s64_t *value);
	size_t (*read_string)(struct lwm2m_input_context *in,
			     u8_t *value, size_t strlen);
	size_t (*read_float32fix)(struct lwm2m_input_context *in,
				  s32_t *value, int bits);
	size_t (*read_bool)(struct lwm2m_input_context *in,
			    int *value);
};

/* represent an object instance */
struct lwm2m_engine_obj {
	sys_snode_t node;
	u16_t obj_id;
	u16_t obj_inst_id;

	/* an array of resource IDs for discovery, etc */
	const u32_t *rsc_ids;
	u16_t rsc_count;

	/* callback for resource OPs */
	enum lwm2m_status (*op_callback)(struct lwm2m_engine_obj *obj,
					 struct lwm2m_engine_context *ctx);

	/* callback for getting dimension counts per resource */
	int (*rsc_dim_callback)(struct lwm2m_engine_obj *obj, u16_t res_id);
};

/* LWM2M engine context */
struct lwm2m_engine_context {
	struct lwm2m_input_context *in;
	struct lwm2m_output_context *out;
	struct lwm2m_obj_path *path;
	enum lwm2m_operation operation;
};

/* inline multi-format write / read functions */

static inline size_t engine_write_begin(struct lwm2m_output_context *out,
					struct lwm2m_obj_path *path)
{
	if (out->writer->write_begin) {
		return out->writer->write_begin(out, path);
	}

	return 0;
}

static inline size_t engine_write_end(struct lwm2m_output_context *out,
				      struct lwm2m_obj_path *path)
{
	if (out->writer->write_end) {
		return out->writer->write_end(out, path);
	}

	return 0;
}

static inline size_t engine_write_begin_ri(struct lwm2m_output_context *out,
					   struct lwm2m_obj_path *path)
{
	if (out->writer->write_begin_ri) {
		return out->writer->write_begin_ri(out, path);
	}

	return 0;
}

static inline size_t engine_write_end_ri(struct lwm2m_output_context *out,
					 struct lwm2m_obj_path *path)
{
	if (out->writer->write_end_ri) {
		return out->writer->write_end_ri(out, path);
	}

	return 0;
}

static inline size_t engine_write_int32(struct lwm2m_output_context *out,
					struct lwm2m_obj_path *path,
					s32_t value)
{
	return out->writer->write_int32(out, path, value);
}

static inline size_t engine_write_int64(struct lwm2m_output_context *out,
					struct lwm2m_obj_path *path,
					s64_t value)
{
	return out->writer->write_int64(out, path, value);
}

static inline size_t engine_write_string(struct lwm2m_output_context *out,
					 struct lwm2m_obj_path *path,
					 const char *value, size_t strlen)
{
	return out->writer->write_string(out, path, value, strlen);
}

static inline size_t engine_write_float32fix(struct lwm2m_output_context *out,
					     struct lwm2m_obj_path *path,
					     s32_t value, int bits)
{
	return out->writer->write_float32fix(out, path, value, bits);
}

static inline size_t engine_write_bool(struct lwm2m_output_context *out,
				       struct lwm2m_obj_path *path,
				       int value)
{
	return out->writer->write_bool(out, path, value);
}

static inline size_t engine_read_int32(struct lwm2m_input_context *in,
				       s32_t *value)
{
	return in->reader->read_int32(in, value);
}

static inline size_t engine_read_int64(struct lwm2m_input_context *in,
				       s64_t *value)
{
	return in->reader->read_int64(in, value);
}

static inline size_t engine_read_string(struct lwm2m_input_context *in,
					u8_t *value, size_t strlen)
{
	return in->reader->read_string(in, value, strlen);
}

static inline size_t engine_read_float32fix(struct lwm2m_input_context *in,
					    s32_t *value, int bits)
{
	return in->reader->read_float32fix(in, value, bits);
}

static inline size_t engine_read_bool(struct lwm2m_input_context *in,
				      int *value)
{
	return in->reader->read_bool(in, value);
}

#endif /* LWM2M_OBJECT_H_ */
