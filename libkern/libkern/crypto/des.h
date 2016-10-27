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
/**
 * \file des.h
 *
 * \brief DES block cipher
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

#ifndef _CRYPTO_DES_H
#define _CRYPTO_DES_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* must be 32bit quantity */
#define DES_LONG u_int32_t

typedef unsigned char des_cblock[8];


typedef struct{
	uint32_t enc[32];
	uint32_t dec[32];
} des_ecb_key_schedule;

typedef struct{
	uint32_t enc[32];
	uint32_t dec[32];
} des_cbc_key_schedule;

typedef struct{
	uint32_t enc[96];
	uint32_t dec[96];
} des3_ecb_key_schedule;

typedef struct{
	uint32_t enc[96];
	uint32_t dec[96];
} des3_cbc_key_schedule;

/* Only here for backward compatibility with smb kext */
typedef des_ecb_key_schedule des_key_schedule[1];
#define des_set_key des_ecb_key_sched

#define DES_ENCRYPT	1
#define DES_DECRYPT	0


/* Single DES ECB - 1 block */
int des_ecb_key_sched(des_cblock *key, des_ecb_key_schedule *ks);
void des_ecb_encrypt(des_cblock *in, des_cblock *out, des_ecb_key_schedule *ks, int encrypt);

/* Triple DES ECB - 1 block */
int des3_ecb_key_sched(des_cblock *key, des3_ecb_key_schedule *ks);
void des3_ecb_encrypt(des_cblock *block, des_cblock *, des3_ecb_key_schedule *ks, int encrypt);

/* Single DES CBC */
int des_cbc_key_sched(des_cblock *key, des_cbc_key_schedule *ks);
void des_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t len,
					 des_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt);

/* Triple DES CBC */
int des3_cbc_key_sched(des_cblock *key, des3_cbc_key_schedule *ks);
void des3_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t len,
					  des3_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt);

/* Single DES CBC-MAC */
void des_cbc_cksum(des_cblock *in, des_cblock *out, int len, des_cbc_key_schedule *ks);

void des_fixup_key_parity(des_cblock *key);
int des_is_weak_key(des_cblock *key);
// int des_set_key(des_cblock *, des_key_schedule); // Unsupported KPI.

#ifdef  __cplusplus
}
#endif

#endif
