/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/aes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <kern/debug.h>

extern mbedtls_functions_t g_mbedtls;
#define MBEDTLS_AES_ENCRYPT     1
#define MBEDTLS_AES_DECRYPT     0
#define NBBY 8

aes_rval aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
{
	int retval;

	g_mbedtls->aes_init(&cx[0]);
	retval = g_mbedtls->aes_setkey_enc(&cx[0], key, key_len * NBBY);
	if (retval != 0) return aes_error;
	return aes_good;
}

aes_rval aes_encrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
						 unsigned char *out_blk, aes_encrypt_ctx cx[1])
{
	int retval = g_mbedtls->aes_crypt_cbc(&cx[0], MBEDTLS_AES_ENCRYPT, num_blk * 16, in_iv, in_blk, out_blk);
	if (retval != 0) return aes_error;
	return aes_good;
}

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
/* This does one block of ECB, using the CBC implementation - this allow to use the same context for both CBC and ECB */
aes_rval aes_encrypt(const unsigned char *in_blk, unsigned char *out_blk, aes_encrypt_ctx cx[1])
{
	return aes_encrypt_cbc(in_blk, NULL, 1, out_blk, cx);
 }
#endif

aes_rval aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1])
{
	int retval;

	g_mbedtls->aes_init(&cx[0]);
	retval = g_mbedtls->aes_setkey_dec(&cx[0], key, key_len * NBBY);
	if (retval != 0) return aes_error;

	return aes_good;
}

aes_rval aes_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
						 unsigned char *out_blk, aes_decrypt_ctx cx[1])
{
	int retval = g_mbedtls->aes_crypt_cbc(&cx[0], MBEDTLS_AES_DECRYPT, num_blk * 16, in_iv, in_blk, out_blk);
	if (retval != 0) return aes_error;
	return aes_good;
}

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
/* This does one block of ECB, using the CBC implementation - this allow to use the same context for both CBC and ECB */
aes_rval aes_decrypt(const unsigned char *in_blk, unsigned char *out_blk, aes_decrypt_ctx cx[1])
{
	return aes_decrypt_cbc(in_blk, NULL, 1, out_blk, cx);
}
#endif

aes_rval aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1])
{
	return aes_encrypt_key(key, 16, cx);
}

aes_rval aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1])
{
	return aes_decrypt_key(key, 16, cx);
}


aes_rval aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
{
	return aes_encrypt_key(key, 32, cx);
}

aes_rval aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
{
	return aes_decrypt_key(key, 32, cx);
}

aes_rval aes_encrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx)
{
	panic("aes_encrypt_key_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_encrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx)
{
	panic("aes_encrypt_set_iv_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_encrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx)
{
	panic("aes_encrypt_aad_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_encrypt_gcm(const unsigned char *in_blk, unsigned int num_bytes,
						 unsigned char *out_blk, ccgcm_ctx *ctx)
{
	panic("aes_encrypt_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_encrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx)
{
	panic("aes_encrypt_finalize_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_decrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx)
{
	panic("aes_decrypt_key_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_decrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx)
{
	panic("aes_decrypt_set_iv_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_decrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx)
{
	panic("aes_decrypt_aad_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_decrypt_gcm(const unsigned char *in_blk, unsigned int num_bytes,
						 unsigned char *out_blk, ccgcm_ctx *ctx)
{
	panic("aes_decrypt_gcm(): function unimplemented");
	return aes_error;
}

aes_rval aes_decrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx)
{
	panic("aes_decrypt_finalize_gcm(): function unimplemented");
	return aes_error;
}

unsigned aes_encrypt_get_ctx_size_gcm(void)
{
	panic("aes_encrypt_get_ctx_size_gcm(): function unimplemented");
	return aes_error;
}

unsigned aes_decrypt_get_ctx_size_gcm(void)
{
	panic("aes_decrypt_get_ctx_size_gcm(): function unimplemented");
	return aes_error;
}

