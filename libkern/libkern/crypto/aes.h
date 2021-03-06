/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 31/01/2006

 This file contains the definitions required to use AES in C. See aesopt.h
 for optimisation details.
*/
/**
 * \file gcm.h
 *
 * \brief Galois/Counter mode for 128-bit block ciphers
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


#ifndef _AES_H
#define _AES_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif

#define AES_128     /* define if AES with 128 bit keys is needed    */
#define AES_192     /* define if AES with 192 bit keys is needed    */
#define AES_256     /* define if AES with 256 bit keys is needed    */
#define AES_VAR     /* define if a variable key size is needed      */
#define AES_MODES   /* define if support is needed for modes        */

/* The following must also be set in assembler files if being used  */

#define AES_ENCRYPT /* if support for encryption is needed          */
#define AES_DECRYPT /* if support for decryption is needed          */
#define AES_ERR_CHK /* for parameter checks & error return codes    */
#define AES_REV_DKS /* define to reverse decryption key schedule    */

#define AES_BLOCK_SIZE  16  /* the AES block size in bytes          */
#define N_COLS           4  /* the number of columns in the state   */

typedef	unsigned int    uint_32t;
typedef unsigned char   uint_8t;
typedef unsigned short  uint_16t;
typedef unsigned char   aes_08t;
typedef	unsigned int    aes_32t;

#define void_ret  void
#define int_ret   int

/* The key schedule length is 11, 13 or 15 16-byte blocks for 128,  */
/* 192 or 256-bit keys respectively. That is 176, 208 or 240 bytes  */
/* or 44, 52 or 60 32-bit words.                                    */

#if defined( AES_VAR ) || defined( AES_256 )
#define KS_LENGTH       60
#elif defined( AES_192 )
#define KS_LENGTH       52
#else
#define KS_LENGTH       44
#endif


#if 0 // defined (__i386__) || defined (__x86_64__)

/* 
	looks like no other code for (i386/x86_64) is using the following definitions any more.
	I comment this out, so the C code in the directory gen/ can be used to compile for test/development purpose.
	Note : this is not going to change anything in the i386/x86_64 kernel. 
			(source code in i386/, mostly in assembly, does not reference to this header file.) 

	cclee	10-20-2010
*/

/* the character array 'inf' in the following structures is used    */
/* to hold AES context information. This AES code uses cx->inf.b[0] */
/* to hold the number of rounds multiplied by 16. The other three   */
/* elements can be used by code that implements additional modes    */

#if defined( AES_ERR_CHK )
#define aes_rval     int_ret
#else
#define aes_rval     void_ret
#endif

typedef union
{   uint_32t l;
    uint_8t b[4];
} aes_inf;

typedef struct
{   uint_32t ks[KS_LENGTH];
    aes_inf inf;
} aes_encrypt_ctx;

typedef struct
{   uint_32t ks[KS_LENGTH];
    aes_inf inf;
} aes_decrypt_ctx;

#else

#if defined( AES_ERR_CHK )
#define aes_ret     int
#define aes_good    0
#define aes_error  -1
#else
#define aes_ret     void
#endif

#define aes_rval    aes_ret

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_32t rn;
} aes_encrypt_ctx;

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_32t rn;
} aes_decrypt_ctx;

#endif

typedef struct
{   
	aes_decrypt_ctx decrypt;
    aes_encrypt_ctx encrypt;
} aes_ctx;


/* implemented in case of wrong call for fixed tables */

void gen_tabs(void);


/* Key lengths in the range 16 <= key_len <= 32 are given in bytes, */
/* those in the range 128 <= key_len <= 256 are given in bits       */

#if defined( AES_ENCRYPT )

#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1]);
#endif

#if defined (__i386__) || defined (__x86_64__)
aes_rval aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1]);
#endif

aes_rval aes_encrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
					 unsigned char *out_blk, const aes_encrypt_ctx cx[1]);

#endif

#if defined( AES_DECRYPT )

#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1]);
#endif

#if defined (__i386__) || defined (__x86_64__)
aes_rval aes_decrypt(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1]);
#endif

aes_rval aes_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
					 unsigned char *out_blk, const aes_decrypt_ctx cx[1]);


#endif

typedef struct {
	union {
		aes_encrypt_ctx enc_ctx;
		aes_decrypt_ctx dec_ctx;
	};

	uint64_t HL[16];            /*!< Precalculated HTable */
	uint64_t HH[16];            /*!< Precalculated HTable */
	uint64_t len;               /*!< Total data length */
	uint64_t add_len;           /*!< Total add length */
	unsigned char base_ectr[16];/*!< First ECTR for tag */
	unsigned char y[16];        /*!< Y working value */
	unsigned char buf[16];      /*!< buf working value */
	int mode;                   /*!< Encrypt or Decrypt */
}
mbedtls_gcm_context;
typedef mbedtls_gcm_context ccgcm_ctx; // For source compatibility

aes_rval aes_encrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx);
aes_rval aes_encrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx);
aes_rval aes_encrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx);
aes_rval aes_encrypt_gcm(const unsigned char *in_blk, unsigned int num_bytes, unsigned char *out_blk, ccgcm_ctx *ctx);
aes_rval aes_encrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx);
unsigned aes_encrypt_get_ctx_size_gcm(void);

aes_rval aes_decrypt_key_gcm(const unsigned char *key, int key_len, ccgcm_ctx *ctx);
aes_rval aes_decrypt_set_iv_gcm(const unsigned char *in_iv, unsigned int len, ccgcm_ctx *ctx);
aes_rval aes_decrypt_aad_gcm(const unsigned char *aad, unsigned int aad_bytes, ccgcm_ctx *ctx);
aes_rval aes_decrypt_gcm(const unsigned char *in_blk, unsigned int num_bytes, unsigned char *out_blk, ccgcm_ctx *ctx);
aes_rval aes_decrypt_finalize_gcm(unsigned char *tag, unsigned int tag_bytes, ccgcm_ctx *ctx);
unsigned aes_decrypt_get_ctx_size_gcm(void);

#define CCAES_BLOCK_SIZE AES_BLOCK_SIZE // For source compatibility

#if defined(__cplusplus)
}
#endif

#endif
