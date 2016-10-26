/*
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file contains code based on mbed TLS (https://tls.mbed.org)
 */

#include <libkern/crypto/aes.h>
#include <stddef.h>
#include <string.h>

#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
(n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
| ( (uint32_t) (b)[(i) + 1] << 16 )             \
| ( (uint32_t) (b)[(i) + 2] <<  8 )             \
| ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
(b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
(b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

// MARK: -

static int gcm_gen_table( mbedtls_gcm_context *ctx )
{
	int ret, i, j;
	uint64_t hi, lo;
	uint64_t vl, vh;
	unsigned char h[16];

	memset( h, 0, 16 );
	if (ctx->mode == MODE_ENCRYPT) {
		ret = aes_encrypt(h, h, &ctx->enc_ctx);
		if (ret == aes_error) return aes_error;
	} else {
		ret = aes_decrypt(h, h, &ctx->dec_ctx);
		if (ret == aes_error) return aes_error;
	}

	/* pack h as two 64-bits ints, big-endian */
	GET_UINT32_BE( hi, h,  0  );
	GET_UINT32_BE( lo, h,  4  );
	vh = (uint64_t) hi << 32 | lo;

	GET_UINT32_BE( hi, h,  8  );
	GET_UINT32_BE( lo, h,  12 );
	vl = (uint64_t) hi << 32 | lo;

	/* 8 = 1000 corresponds to 1 in GF(2^128) */
	ctx->HL[8] = vl;
	ctx->HH[8] = vh;

	/* 0 corresponds to 0 in GF(2^128) */
	ctx->HH[0] = 0;
	ctx->HL[0] = 0;

	for( i = 4; i > 0; i >>= 1 )
	{
		uint32_t T = ( vl & 1 ) * 0xe1000000U;
		vl  = ( vh << 63 ) | ( vl >> 1 );
		vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);

		ctx->HL[i] = vl;
		ctx->HH[i] = vh;
	}

	for( i = 2; i <= 8; i *= 2 )
	{
		uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
		vh = *HiH;
		vl = *HiL;
		for( j = 1; j < i; j++ )
		{
			HiH[j] = vh ^ ctx->HH[j];
			HiL[j] = vl ^ ctx->HL[j];
		}
	}

	return( 0 );
}

static const uint64_t last4[16] =
{
	0x0000, 0x1c20, 0x3840, 0x2460,
	0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560,
	0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult( mbedtls_gcm_context *ctx, const unsigned char x[16],
					 unsigned char output[16] )
{
	int i = 0;
	unsigned char lo, hi, rem;
	uint64_t zh, zl;

	lo = x[15] & 0xf;

	zh = ctx->HH[lo];
	zl = ctx->HL[lo];

	for( i = 15; i >= 0; i-- )
	{
		lo = x[i] & 0xf;
		hi = x[i] >> 4;

		if( i != 15 )
		{
			rem = (unsigned char) zl & 0xf;
			zl = ( zh << 60 ) | ( zl >> 4 );
			zh = ( zh >> 4 );
			zh ^= (uint64_t) last4[rem] << 48;
			zh ^= ctx->HH[lo];
			zl ^= ctx->HL[lo];

		}

		rem = (unsigned char) zl & 0xf;
		zl = ( zh << 60 ) | ( zl >> 4 );
		zh = ( zh >> 4 );
		zh ^= (uint64_t) last4[rem] << 48;
		zh ^= ctx->HH[hi];
		zl ^= ctx->HL[hi];
	}

	PUT_UINT32_BE( zh >> 32, output, 0 );
	PUT_UINT32_BE( zh, output, 4 );
	PUT_UINT32_BE( zl >> 32, output, 8 );
	PUT_UINT32_BE( zl, output, 12 );
}

// MARK: -

aes_rval aes_encrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx) {
	aes_encrypt_key(key, key_len, &ctx->enc_ctx);
	gcm_gen_table(ctx);
	return 0;
}

aes_rval aes_encrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx) {
	unsigned char work_buf[16];
	unsigned int i;
	const unsigned char *p;
	size_t use_len;

	if (((uint64_t)len) >> 61 != 0) {
		return aes_error;
	}

	memset(ctx->y, 0, sizeof(ctx->y));
	memset(ctx->buf, 0, sizeof(ctx->buf));

	ctx->len = 0;
	ctx->mode = MODE_ENCRYPT;
	ctx->add_len = 0;

	if (len == 12) {
		memcpy(ctx->y, in_iv, len);
		ctx->y[15] = 1;
	} else {
		memset(work_buf, 0, 16);
		PUT_UINT32_BE(len * 8, work_buf, 12);

		p = in_iv;
		while (len > 0) {
			use_len = (len < 16) ? len : 16;
			for (i = 0; i < use_len; i++) ctx->y[i] ^= p[i];
			gcm_mult(ctx, ctx->y, ctx->y);
			len -= use_len;
			p += use_len;
		}


		for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
		gcm_mult( ctx, ctx->y, ctx->y );
	}

	if (aes_encrypt_key(ctx->y, 16, &ctx->enc_ctx) == aes_error) return aes_error;
	return aes_good;
}

aes_rval aes_encrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx) {
	const unsigned char *p;
	unsigned int use_len;

	ctx->add_len = aad_bytes;
	p = aad;

	while (aad_bytes > 0) {
		use_len = (aad_bytes < 16) ? aad_bytes : 16;
		for (int i = 0; i < use_len; i++) ctx->buf[i] ^= p[i];

		gcm_mult(ctx, ctx->buf, ctx->buf);
		aad_bytes -= use_len;
		p += use_len;
	}

	return aes_good;
}

aes_rval aes_encrypt_gcm(const unsigned char *input, unsigned int length, unsigned char *output, ccgcm_ctx *ctx) {
	unsigned char ectr[16];
	unsigned int i;
	const unsigned char *p;
	unsigned char *out_p = output;
	size_t use_len;

	if( output > input && (size_t) ( output - input ) < length )
		return aes_error;

	/* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
	 * Also check for possible overflow */
	if( ctx->len + length < ctx->len ||
	   (uint64_t) ctx->len + length > 0xFFFFFFFE0ull )
	{
		return aes_error;
	}

	ctx->len += length;

	p = input;
	while( length > 0 )
	{
		use_len = ( length < 16 ) ? length : 16;

		for( i = 16; i > 12; i-- )
			if( ++ctx->y[i - 1] != 0 )
				break;

		if (aes_encrypt(ctx->y, ectr, &ctx->enc_ctx) == aes_error)
			return aes_error;

		for( i = 0; i < use_len; i++ )
		{
			out_p[i] = ectr[i] ^ p[i];
			ctx->buf[i] ^= out_p[i];
		}

		gcm_mult( ctx, ctx->buf, ctx->buf );

		length -= use_len;
		p += use_len;
		out_p += use_len;
	}

	return aes_good;
}


aes_rval aes_encrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx) {
	unsigned char work_buf[16];
	size_t i;
	uint64_t orig_len = ctx->len * 8;
	uint64_t orig_add_len = ctx->add_len * 8;

	if( tag_bytes > 16 || tag_bytes < 4 )
		return aes_error;

	if( tag_bytes != 0 )
		memcpy( tag, ctx->base_ectr, tag_bytes );

	if( orig_len || orig_add_len )
	{
		memset( work_buf, 0x00, 16 );

		PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
		PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
		PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
		PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

		for( i = 0; i < 16; i++ )
			ctx->buf[i] ^= work_buf[i];

		gcm_mult( ctx, ctx->buf, ctx->buf );

		for( i = 0; i < tag_bytes; i++ )
			tag[i] ^= ctx->buf[i];
	}

	return aes_good;
}

unsigned aes_encrypt_get_ctx_size_gcm(void) {
	return sizeof(ccgcm_ctx);
}

// MARK: -

aes_rval aes_decrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx) {
	aes_decrypt_key(key, key_len, &ctx->dec_ctx);
	gcm_gen_table(ctx);
	return 0;
}

aes_rval aes_decrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx) {
	unsigned char work_buf[16];
	unsigned int i;
	const unsigned char *p;
	size_t use_len;

	if (((uint64_t)len) >> 61 != 0) {
		return aes_error;
	}

	memset(ctx->y, 0, sizeof(ctx->y));
	memset(ctx->buf, 0, sizeof(ctx->buf));

	ctx->len = 0;
	ctx->mode = MODE_DECRYPT;
	ctx->add_len = 0;

	if (len == 12) {
		memcpy(ctx->y, in_iv, len);
		ctx->y[15] = 1;
	} else {
		memset(work_buf, 0, 16);
		PUT_UINT32_BE(len * 8, work_buf, 12);

		p = in_iv;
		while (len > 0) {
			use_len = (len < 16) ? len : 16;
			for (i = 0; i < use_len; i++) ctx->y[i] ^= p[i];
			gcm_mult(ctx, ctx->y, ctx->y);
			len -= use_len;
			p += use_len;
		}


		for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
		gcm_mult( ctx, ctx->y, ctx->y );
	}

	if (aes_decrypt_key(ctx->y, 16, &ctx->dec_ctx) == aes_error) return aes_error;
	return aes_good;
}

aes_rval aes_decrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx) {
	const unsigned char *p;
	unsigned int use_len;

	ctx->add_len = aad_bytes;
	p = aad;

	while (aad_bytes > 0) {
		use_len = (aad_bytes < 16) ? aad_bytes : 16;
		for (int i = 0; i < use_len; i++) ctx->buf[i] ^= p[i];

		gcm_mult(ctx, ctx->buf, ctx->buf);
		aad_bytes -= use_len;
		p += use_len;
	}

	return aes_good;
}

aes_rval aes_decrypt_gcm(const unsigned char *input, unsigned int length, unsigned char *output, ccgcm_ctx *ctx) {
	unsigned char ectr[16];
	unsigned int i;
	const unsigned char *p;
	unsigned char *out_p = output;
	size_t use_len;

	if( output > input && (size_t) ( output - input ) < length )
		return aes_error;

	/* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
	 * Also check for possible overflow */
	if( ctx->len + length < ctx->len ||
	   (uint64_t) ctx->len + length > 0xFFFFFFFE0ull )
	{
		return aes_error;
	}

	ctx->len += length;

	p = input;
	while( length > 0 )
	{
		use_len = ( length < 16 ) ? length : 16;

		for( i = 16; i > 12; i-- )
			if( ++ctx->y[i - 1] != 0 )
				break;

		if (aes_decrypt(ctx->y, ectr, &ctx->dec_ctx) == aes_error)
			return aes_error;

		for( i = 0; i < use_len; i++ )
		{
			out_p[i] = ectr[i] ^ p[i];
			ctx->buf[i] ^= out_p[i];
		}

		gcm_mult( ctx, ctx->buf, ctx->buf );

		length -= use_len;
		p += use_len;
		out_p += use_len;
	}

	return aes_good;
}

aes_rval aes_decrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx) {
	unsigned char work_buf[16];
	size_t i;
	uint64_t orig_len = ctx->len * 8;
	uint64_t orig_add_len = ctx->add_len * 8;

	if( tag_bytes > 16 || tag_bytes < 4 )
		return aes_error;

	if( tag_bytes != 0 )
		memcpy( tag, ctx->base_ectr, tag_bytes );

	if( orig_len || orig_add_len )
	{
		memset( work_buf, 0x00, 16 );

		PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
		PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
		PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
		PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

		for( i = 0; i < 16; i++ )
			ctx->buf[i] ^= work_buf[i];

		gcm_mult( ctx, ctx->buf, ctx->buf );

		for( i = 0; i < tag_bytes; i++ )
			tag[i] ^= ctx->buf[i];
	}

	return aes_good;
}

unsigned aes_decrypt_get_ctx_size_gcm(void) {
	return sizeof(ccgcm_ctx);
}

