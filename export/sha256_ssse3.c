/*
 * Cryptographic API.
 *
 * Glue code for the SHA256 Secure Hash Algorithm assembler
 * implementation using supplemental SSE3 / AVX / AVX2 instructions.
 *
 * This file is based on sha256_generic.c
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Author:
 *     Tim Chen <tim.c.chen@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>
#include <asm/i387.h>
#include <asm/xcr.h>
#include <asm/xsave.h>
#include <linux/string.h>
#include "linuxdefs.h"
#include "exportdefs.h"


asmlinkage void sha256_transform_ssse3_ext(const char *data, u32 *digest,
				     u64 rounds);

static asmlinkage void (*sha256_transform_asm)(const char *, u32 *, u64);


static int sha256_ssse3_init(struct sha256_state *sctx)
{
	sctx->state[0] = SHA256_H0;
	sctx->state[1] = SHA256_H1;
	sctx->state[2] = SHA256_H2;
	sctx->state[3] = SHA256_H3;
	sctx->state[4] = SHA256_H4;
	sctx->state[5] = SHA256_H5;
	sctx->state[6] = SHA256_H6;
	sctx->state[7] = SHA256_H7;
	sctx->count = 0;

	return 0;
}

static int __sha256_ssse3_update(struct sha256_state *sctx, const u8 *data,
			       unsigned int len, unsigned int partial)
{
	unsigned int done = 0;

	sctx->count += len;

	if (partial) {
		done = SHA256_BLOCK_SIZE - partial;
		memcpy(sctx->buf + partial, data, done);
		sha256_transform_asm(sctx->buf, sctx->state, 1);
	}

	if (len - done >= SHA256_BLOCK_SIZE) {
		const unsigned int rounds = (len - done) / SHA256_BLOCK_SIZE;

		sha256_transform_asm(data + done, sctx->state, (u64) rounds);

		done += rounds * SHA256_BLOCK_SIZE;
	}

	memcpy(sctx->buf, data + done, len - done);

	return 0;
}

static int sha256_ssse3_update(struct sha256_state *sctx, const u8 *data,
			     unsigned int len)
{
	unsigned int partial = sctx->count % SHA256_BLOCK_SIZE;
	int res;

	/* Handle the fast case right here */
	if (partial + len < SHA256_BLOCK_SIZE) {
		sctx->count += len;
		memcpy(sctx->buf + partial, data, len);

		return 0;
	}

	res = __sha256_ssse3_update(sctx, data, len, partial);
	return res;
}


/* Add padding and return the message digest. */
static int sha256_ssse3_final(struct sha256_state *sctx, u8 *out)
{
	unsigned int i, index, padlen;
	__be32 *dst = (__be32 *)out;
	__be64 bits;
	static const u8 padding[SHA256_BLOCK_SIZE] = { 0x80, };

	bits = cpu_to_be64(sctx->count << 3);

	/* Pad out to 56 mod 64 and append length */
	index = sctx->count % SHA256_BLOCK_SIZE;
	padlen = (index < 56) ? (56 - index) : ((SHA256_BLOCK_SIZE+56)-index);

	/* We need to fill a whole block for __sha256_ssse3_update() */
	if (padlen <= 56) {
		sctx->count += padlen;
		memcpy(sctx->buf + index, padding, padlen);
	} else {
		__sha256_ssse3_update(sctx, padding, padlen, index);
	}
	__sha256_ssse3_update(sctx, (const u8 *)&bits,
				sizeof(bits), 56);

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = cpu_to_be32(sctx->state[i]);

	/* Wipe context */
	memset(sctx, 0, sizeof(*sctx));

	return 0;
}

void
ssse3_hash_compute(void(*hash_compute_def)(uint8_t *, uint8_t *), uint8_t *buf, uint8_t *hash)
{
	struct sha256_state sctx;

	if (!irq_fpu_usable()) {
		(*hash_compute_def)(buf, hash);
		return;
	}

	sha256_ssse3_init(&sctx);
	kernel_fpu_begin();
	sha256_ssse3_update(&sctx, buf, 4096);
	sha256_ssse3_final(&sctx, hash);
	kernel_fpu_end();
}

static int sha256_ssse3_test(void)
{
	/* test for SSSE3 first */
	if (!boot_cpu_has(X86_FEATURE_SSSE3))
		return -1;

	sha256_transform_asm = sha256_transform_ssse3_ext;
	pr_info("Using SSSE3 optimized SHA-256 implementation\n");
	return 0;
}

void
sha256_ssse3_setup(struct qs_kern_cbs *kcbs)
{
	if (sha256_ssse3_test() != 0)
		return;

	kcbs->hash_compute = ssse3_hash_compute;
}
