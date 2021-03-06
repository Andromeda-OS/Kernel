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

#include <libkern/crypto/des.h>
#include <kern/debug.h>
#include <string.h>

#define assert(cond) ((cond) ? (void)0 : panic("Assertion failure: %s", #cond))

/*
 * 32-bit integer manipulation macros (big endian)
 */
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

/*
 * Expanded DES S-boxes
 */
static const uint32_t SB1[64] =
{
	0x01010400, 0x00000000, 0x00010000, 0x01010404,
	0x01010004, 0x00010404, 0x00000004, 0x00010000,
	0x00000400, 0x01010400, 0x01010404, 0x00000400,
	0x01000404, 0x01010004, 0x01000000, 0x00000004,
	0x00000404, 0x01000400, 0x01000400, 0x00010400,
	0x00010400, 0x01010000, 0x01010000, 0x01000404,
	0x00010004, 0x01000004, 0x01000004, 0x00010004,
	0x00000000, 0x00000404, 0x00010404, 0x01000000,
	0x00010000, 0x01010404, 0x00000004, 0x01010000,
	0x01010400, 0x01000000, 0x01000000, 0x00000400,
	0x01010004, 0x00010000, 0x00010400, 0x01000004,
	0x00000400, 0x00000004, 0x01000404, 0x00010404,
	0x01010404, 0x00010004, 0x01010000, 0x01000404,
	0x01000004, 0x00000404, 0x00010404, 0x01010400,
	0x00000404, 0x01000400, 0x01000400, 0x00000000,
	0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const uint32_t SB2[64] =
{
	0x80108020, 0x80008000, 0x00008000, 0x00108020,
	0x00100000, 0x00000020, 0x80100020, 0x80008020,
	0x80000020, 0x80108020, 0x80108000, 0x80000000,
	0x80008000, 0x00100000, 0x00000020, 0x80100020,
	0x00108000, 0x00100020, 0x80008020, 0x00000000,
	0x80000000, 0x00008000, 0x00108020, 0x80100000,
	0x00100020, 0x80000020, 0x00000000, 0x00108000,
	0x00008020, 0x80108000, 0x80100000, 0x00008020,
	0x00000000, 0x00108020, 0x80100020, 0x00100000,
	0x80008020, 0x80100000, 0x80108000, 0x00008000,
	0x80100000, 0x80008000, 0x00000020, 0x80108020,
	0x00108020, 0x00000020, 0x00008000, 0x80000000,
	0x00008020, 0x80108000, 0x00100000, 0x80000020,
	0x00100020, 0x80008020, 0x80000020, 0x00100020,
	0x00108000, 0x00000000, 0x80008000, 0x00008020,
	0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const uint32_t SB3[64] =
{
	0x00000208, 0x08020200, 0x00000000, 0x08020008,
	0x08000200, 0x00000000, 0x00020208, 0x08000200,
	0x00020008, 0x08000008, 0x08000008, 0x00020000,
	0x08020208, 0x00020008, 0x08020000, 0x00000208,
	0x08000000, 0x00000008, 0x08020200, 0x00000200,
	0x00020200, 0x08020000, 0x08020008, 0x00020208,
	0x08000208, 0x00020200, 0x00020000, 0x08000208,
	0x00000008, 0x08020208, 0x00000200, 0x08000000,
	0x08020200, 0x08000000, 0x00020008, 0x00000208,
	0x00020000, 0x08020200, 0x08000200, 0x00000000,
	0x00000200, 0x00020008, 0x08020208, 0x08000200,
	0x08000008, 0x00000200, 0x00000000, 0x08020008,
	0x08000208, 0x00020000, 0x08000000, 0x08020208,
	0x00000008, 0x00020208, 0x00020200, 0x08000008,
	0x08020000, 0x08000208, 0x00000208, 0x08020000,
	0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const uint32_t SB4[64] =
{
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802080, 0x00800081, 0x00800001, 0x00002001,
	0x00000000, 0x00802000, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00800080, 0x00800001,
	0x00000001, 0x00002000, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002001, 0x00002080,
	0x00800081, 0x00000001, 0x00002080, 0x00800080,
	0x00002000, 0x00802080, 0x00802081, 0x00000081,
	0x00800080, 0x00800001, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00000000, 0x00802000,
	0x00002080, 0x00800080, 0x00800081, 0x00000001,
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802081, 0x00000081, 0x00000001, 0x00002000,
	0x00800001, 0x00002001, 0x00802080, 0x00800081,
	0x00002001, 0x00002080, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const uint32_t SB5[64] =
{
	0x00000100, 0x02080100, 0x02080000, 0x42000100,
	0x00080000, 0x00000100, 0x40000000, 0x02080000,
	0x40080100, 0x00080000, 0x02000100, 0x40080100,
	0x42000100, 0x42080000, 0x00080100, 0x40000000,
	0x02000000, 0x40080000, 0x40080000, 0x00000000,
	0x40000100, 0x42080100, 0x42080100, 0x02000100,
	0x42080000, 0x40000100, 0x00000000, 0x42000000,
	0x02080100, 0x02000000, 0x42000000, 0x00080100,
	0x00080000, 0x42000100, 0x00000100, 0x02000000,
	0x40000000, 0x02080000, 0x42000100, 0x40080100,
	0x02000100, 0x40000000, 0x42080000, 0x02080100,
	0x40080100, 0x00000100, 0x02000000, 0x42080000,
	0x42080100, 0x00080100, 0x42000000, 0x42080100,
	0x02080000, 0x00000000, 0x40080000, 0x42000000,
	0x00080100, 0x02000100, 0x40000100, 0x00080000,
	0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const uint32_t SB6[64] =
{
	0x20000010, 0x20400000, 0x00004000, 0x20404010,
	0x20400000, 0x00000010, 0x20404010, 0x00400000,
	0x20004000, 0x00404010, 0x00400000, 0x20000010,
	0x00400010, 0x20004000, 0x20000000, 0x00004010,
	0x00000000, 0x00400010, 0x20004010, 0x00004000,
	0x00404000, 0x20004010, 0x00000010, 0x20400010,
	0x20400010, 0x00000000, 0x00404010, 0x20404000,
	0x00004010, 0x00404000, 0x20404000, 0x20000000,
	0x20004000, 0x00000010, 0x20400010, 0x00404000,
	0x20404010, 0x00400000, 0x00004010, 0x20000010,
	0x00400000, 0x20004000, 0x20000000, 0x00004010,
	0x20000010, 0x20404010, 0x00404000, 0x20400000,
	0x00404010, 0x20404000, 0x00000000, 0x20400010,
	0x00000010, 0x00004000, 0x20400000, 0x00404010,
	0x00004000, 0x00400010, 0x20004010, 0x00000000,
	0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const uint32_t SB7[64] =
{
	0x00200000, 0x04200002, 0x04000802, 0x00000000,
	0x00000800, 0x04000802, 0x00200802, 0x04200800,
	0x04200802, 0x00200000, 0x00000000, 0x04000002,
	0x00000002, 0x04000000, 0x04200002, 0x00000802,
	0x04000800, 0x00200802, 0x00200002, 0x04000800,
	0x04000002, 0x04200000, 0x04200800, 0x00200002,
	0x04200000, 0x00000800, 0x00000802, 0x04200802,
	0x00200800, 0x00000002, 0x04000000, 0x00200800,
	0x04000000, 0x00200800, 0x00200000, 0x04000802,
	0x04000802, 0x04200002, 0x04200002, 0x00000002,
	0x00200002, 0x04000000, 0x04000800, 0x00200000,
	0x04200800, 0x00000802, 0x00200802, 0x04200800,
	0x00000802, 0x04000002, 0x04200802, 0x04200000,
	0x00200800, 0x00000000, 0x00000002, 0x04200802,
	0x00000000, 0x00200802, 0x04200000, 0x00000800,
	0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const uint32_t SB8[64] =
{
	0x10001040, 0x00001000, 0x00040000, 0x10041040,
	0x10000000, 0x10001040, 0x00000040, 0x10000000,
	0x00040040, 0x10040000, 0x10041040, 0x00041000,
	0x10041000, 0x00041040, 0x00001000, 0x00000040,
	0x10040000, 0x10000040, 0x10001000, 0x00001040,
	0x00041000, 0x00040040, 0x10040040, 0x10041000,
	0x00001040, 0x00000000, 0x00000000, 0x10040040,
	0x10000040, 0x10001000, 0x00041040, 0x00040000,
	0x00041040, 0x00040000, 0x10041000, 0x00001000,
	0x00000040, 0x10040040, 0x00001000, 0x00041040,
	0x10001000, 0x00000040, 0x10000040, 0x10040000,
	0x10040040, 0x10000000, 0x00040000, 0x10001040,
	0x00000000, 0x10041040, 0x00040040, 0x10000040,
	0x10040000, 0x10001000, 0x10001040, 0x00000000,
	0x10041040, 0x00041000, 0x00041000, 0x00001040,
	0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/*
 * PC1: left and right halves bit-swap
 */
static const uint32_t LHs[16] =
{
	0x00000000, 0x00000001, 0x00000100, 0x00000101,
	0x00010000, 0x00010001, 0x00010100, 0x00010101,
	0x01000000, 0x01000001, 0x01000100, 0x01000101,
	0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static const uint32_t RHs[16] =
{
	0x00000000, 0x01000000, 0x00010000, 0x01010000,
	0x00000100, 0x01000100, 0x00010100, 0x01010100,
	0x00000001, 0x01000001, 0x00010001, 0x01010001,
	0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/*
 * Initial Permutation macro
 */
#define DES_IP(X,Y)                                             \
{                                                               \
T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;                    \
T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;                   \
X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;                    \
}

/*
 * Final Permutation macro
 */
#define DES_FP(X,Y)                                             \
{                                                               \
X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;                    \
T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;                   \
Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;                    \
T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
}

/*
 * DES round macro
 */
#define DES_ROUND(X,Y)                          \
{                                               \
T = *SK++ ^ X;                              \
Y ^= SB8[ (T      ) & 0x3F ] ^              \
SB6[ (T >>  8) & 0x3F ] ^              \
SB4[ (T >> 16) & 0x3F ] ^              \
SB2[ (T >> 24) & 0x3F ];               \
\
T = *SK++ ^ ((X << 28) | (X >> 4));         \
Y ^= SB7[ (T      ) & 0x3F ] ^              \
SB5[ (T >>  8) & 0x3F ] ^              \
SB3[ (T >> 16) & 0x3F ] ^              \
SB1[ (T >> 24) & 0x3F ];               \
}

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }

// MARK: -

#define DES_KEY_LENGTH 8

static const unsigned char odd_parity_table[128] = { 1,  2,  4,  7,  8,
	11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31, 32, 35, 37, 38, 41, 42, 44,
	47, 49, 50, 52, 55, 56, 59, 61, 62, 64, 67, 69, 70, 73, 74, 76, 79, 81,
	82, 84, 87, 88, 91, 93, 94, 97, 98, 100, 103, 104, 107, 109, 110, 112,
	115, 117, 118, 121, 122, 124, 127, 128, 131, 133, 134, 137, 138, 140,
	143, 145, 146, 148, 151, 152, 155, 157, 158, 161, 162, 164, 167, 168,
	171, 173, 174, 176, 179, 181, 182, 185, 186, 188, 191, 193, 194, 196,
	199, 200, 203, 205, 206, 208, 211, 213, 214, 217, 218, 220, 223, 224,
	227, 229, 230, 233, 234, 236, 239, 241, 242, 244, 247, 248, 251, 253,
	254 };

void des_fixup_key_parity(des_cblock *keyptr) {
	unsigned char *key = *keyptr;
	for (int i = 0; i < DES_KEY_LENGTH; i++) {
		key[i] = odd_parity_table[key[i] / 2];
	}
}

#define WEAK_KEY_COUNT 16

static const unsigned char weak_key_table[WEAK_KEY_COUNT][DES_KEY_LENGTH] =
{
	{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
	{ 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
	{ 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E },
	{ 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 },

	{ 0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E },
	{ 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01 },
	{ 0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1 },
	{ 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01 },
	{ 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE },
	{ 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01 },
	{ 0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1 },
	{ 0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E },
	{ 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE },
	{ 0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E },
	{ 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE },
	{ 0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1 }
};

int des_is_weak_key(des_cblock *key) {
	for (int i = 0; i < WEAK_KEY_COUNT; i++) {
		if (memcmp(weak_key_table[i], key, DES_KEY_LENGTH) == 0) return 1;
	}

	return 0;
}

// MARK: -

static void _des_ecb_key_sched(des_cblock *key, uint32_t SK[32]) {
	int i;
	uint32_t X, Y, T;

	GET_UINT32_BE( X, *key, 0 );
	GET_UINT32_BE( Y, *key, 4 );

	/*
	 * Permuted Choice 1
	 */
	T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
	T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

	X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
	| (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
	| (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
	| (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

	Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
	| (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
	| (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
	| (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

	X &= 0x0FFFFFFF;
	Y &= 0x0FFFFFFF;

	/*
	 * calculate subkeys
	 */
	for( i = 0; i < 16; i++ )
	{
		if( i < 2 || i == 8 || i == 15 )
		{
			X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
			Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
		}
		else
		{
			X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
			Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
		}

		*SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
		| ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
		| ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
		| ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
		| ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
		| ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
		| ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
		| ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
		| ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
		| ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
		| ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

		*SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
		| ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
		| ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
		| ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
		| ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
		| ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
		| ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
		| ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
		| ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
		| ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
		| ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
	}
}

int des_ecb_key_sched(des_cblock *key, des_ecb_key_schedule *ks) {
	_des_ecb_key_sched(key, ks->enc);
	_des_ecb_key_sched(key, ks->dec);
	return 0;
}

void des_ecb_encrypt(des_cblock *in, des_cblock *out, des_ecb_key_schedule *ks, int encrypt) {
	int i;
	uint32_t X, Y, T, *SK;

	if (encrypt == DES_ENCRYPT) SK = ks->enc;
	else if (encrypt == DES_DECRYPT) SK = ks->dec;
	else panic("Unexpected des_ecb_encrypt() mode %d", encrypt);

	GET_UINT32_BE( X, *in, 0 );
	GET_UINT32_BE( Y, *in, 4 );

	DES_IP( X, Y );

	for( i = 0; i < 8; i++ )
	{
		DES_ROUND( Y, X );
		DES_ROUND( X, Y );
	}

	DES_FP( Y, X );

	PUT_UINT32_BE( Y, *out, 0 );
	PUT_UINT32_BE( X, *out, 4 );
}

int des_cbc_key_sched(des_cblock *key, des_cbc_key_schedule *ks) {
	_des_ecb_key_sched(key, ks->enc);
	_des_ecb_key_sched(key, ks->dec);
	return 0;
}

void des_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t length, des_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt) {
	int i;
	unsigned char temp[8];
	des_cblock work_iv;
	memcpy(work_iv, *iv, 8);

	assert(length % 8 == 0);
	const unsigned char *input = *in;
	unsigned char *output = *out;

	if( encrypt == DES_ENCRYPT )
	{
		while( length > 0 )
		{
			for( i = 0; i < 8; i++ )
				output[i] = (unsigned char)( input[i] ^ work_iv[i] );

			des_cblock temp_input, temp_output;
			memcpy(temp, input, 8);

			des_ecb_encrypt( &temp_input, &temp_output, (des_ecb_key_schedule *) ks, DES_ENCRYPT );
			memcpy( output, temp_output, 8 );
			memcpy( work_iv, output, 8 );

			input  += 8;
			output += 8;
			length -= 8;
		}
	}
	else if( encrypt == DES_DECRYPT )
	{
		while( length > 0 )
		{
			memcpy( temp, input, 8 );

			des_cblock temp_input, temp_output;
			memcpy(temp_input, input, 8);
			des_ecb_encrypt( &temp_input, &temp_output, (des_ecb_key_schedule *) ks, DES_DECRYPT );
			memcpy(output, temp_output, 8);

			for( i = 0; i < 8; i++ )
				output[i] = (unsigned char)( output[i] ^ work_iv[i] );

			memcpy( work_iv, temp, 8 );

			input  += 8;
			output += 8;
			length -= 8;
		}
	}
	else
	{
		panic("Unexpected des_cbc_encrypt() mode %d", encrypt);
	}

	memcpy(*retiv, work_iv, 8);
}

void des_cbc_cksum(des_cblock *in, des_cblock *out, int len, des_cbc_key_schedule *ks) {
	assert(len % 8 == 0);
	int nblocks = len / 8;

	des_cblock cksum;
	des_cblock null_iv = { 0 };
	while (nblocks-- != 0) {
		des_cbc_encrypt(in++, &cksum, 8, ks, &null_iv, &null_iv, DES_ENCRYPT);
	}

	memcpy(out, cksum, sizeof(des_cblock));
}

// MARK: -

int des3_ecb_key_sched(des_cblock *key, des3_ecb_key_schedule *ks) {
	_des_ecb_key_sched(key, ks->enc);
	_des_ecb_key_sched(key + 1, ks->dec + 32);

	for (int i = 0; i < 32; i += 2) {
		ks->dec[i     ] = ks->enc[30 - i];
		ks->dec[i +  1] = ks->enc[31 - i];

		ks->enc[i + 32] = ks->dec[62 - i];
		ks->enc[i + 33] = ks->dec[63 - i];

		ks->enc[i + 64] = ks->enc[i    ];
		ks->enc[i + 65] = ks->enc[i + 1];

		ks->dec[i + 64] = ks->dec[i    ];
		ks->dec[i + 65] = ks->dec[i + 1];
	}

	return 0;
}

void des3_ecb_encrypt(des_cblock *input, des_cblock *output, des3_ecb_key_schedule *ks, int encrypt) {
	int i;
	uint32_t X, Y, T, *SK;

	if (encrypt == DES_ENCRYPT) {
		SK = ks->enc;
	} else if (encrypt == DES_DECRYPT) {
		SK = ks->dec;
	} else {
		panic("Unepected des3_ecb_encrypt() mode %d", encrypt);
	}

	GET_UINT32_BE( X, *input, 0 );
	GET_UINT32_BE( Y, *input, 4 );

	DES_IP( X, Y );

	for( i = 0; i < 8; i++ )
	{
		DES_ROUND( Y, X );
		DES_ROUND( X, Y );
	}

	for( i = 0; i < 8; i++ )
	{
		DES_ROUND( X, Y );
		DES_ROUND( Y, X );
	}

	for( i = 0; i < 8; i++ )
	{
		DES_ROUND( Y, X );
		DES_ROUND( X, Y );
	}

	DES_FP( Y, X );

	PUT_UINT32_BE( Y, *output, 0 );
	PUT_UINT32_BE( X, *output, 4 );
}

int des3_cbc_key_sched(des_cblock *key, des3_cbc_key_schedule *ks) {
	static int warned;
	if (warned++ == 0) {
		extern void kprintf(const char *, ...);
		kprintf("Unholy HACK: Assuming that des3_cbc_key_sched() is identical to des3_ecb_key_sched()!\n");
	}

	return des3_ecb_key_sched(key, (des3_ecb_key_schedule *)ks);
}

void des3_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t len, des3_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt) {
	int i;

	assert(len % 8 == 0);

	if (encrypt == DES_ENCRYPT) {
		des_cblock work_input, work_output, work_iv;
		memcpy(work_iv, *iv, sizeof(work_iv));

		while (len > 0) {
			memcpy(work_input, *in, sizeof(work_input));
			for (i = 0; i < 8; i++) work_input[i] = (unsigned char)(work_input[i] ^ work_iv[i]);

			des3_ecb_encrypt(&work_input, &work_output, ks, DES_ENCRYPT);
			memcpy(*out, work_output, sizeof(work_output));
			memcpy(work_iv, work_output, sizeof(work_iv));

			in++; out++;
			len -= 8;
		}

		memcpy(*retiv, work_iv, sizeof(work_iv));
	} else if (encrypt == DES_DECRYPT) {
		des_cblock work_input, work_output, work_iv;
		memcpy(work_iv, *iv, sizeof(work_iv));

		while (len > 0) {
			memcpy(work_input, *in, sizeof(work_input));
			des3_ecb_encrypt(&work_input, &work_output, ks, DES_DECRYPT);
			for (i = 0; i < 8; i++) work_output[i] = (unsigned char)(work_output[i] ^ work_iv[i]);

			memcpy(*out, work_output, sizeof(work_output));
			memcpy(work_iv, work_output, sizeof(work_iv));
			in++; out++;
			len -= 8;
		}

		memcpy(*retiv, work_iv, sizeof(work_iv));
	}
}
