/* crypto/sha/sha256.c */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved
 * according to the OpenSSL license [found in ../../LICENSE].
 * ====================================================================
 */
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA256)

#include "coredefs.h"
#include "sha.h"

#define SHA256_ASM	1

void SHA256X_Init (SHA256X_CTX *c)
	{
	bzero (c,sizeof(*c));
	c->h[0]=0x6a09e667UL;	c->h[1]=0xbb67ae85UL;
	c->h[2]=0x3c6ef372UL;	c->h[3]=0xa54ff53aUL;
	c->h[4]=0x510e527fUL;	c->h[5]=0x9b05688cUL;
	c->h[6]=0x1f83d9abUL;	c->h[7]=0x5be0cd19UL;
	return;
	}

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
	{
	SHA256X_CTX c;
	static unsigned char m[SHA256_DIGEST_LENGTH];

	if (md == NULL) md=m;
	SHA256X_Init(&c);
	SHA256X_Update(&c,d,n);
	SHA256X_Final(md,&c);
	return(md);
	}

#define	DATA_ORDER_IS_BIG_ENDIAN

#define	HASH_LONG		SHA_LONG
#define	HASH_CTX		SHA256X_CTX
#define	HASH_CBLOCK		SHA_CBLOCK
/*
 * Note that FIPS180-2 discusses "Truncation of the Hash Function Output."
 * default: case below covers for it. It's not clear however if it's
 * permitted to truncate to amount of bytes not divisible by 4. I bet not,
 * but if it is, then default: case shall be extended. For reference.
 * Idea behind separate cases for pre-defined lenghts is to let the
 * compiler decide if it's appropriate to unroll small loops.
 */
#define	HASH_MAKE_STRING(c,s)	do {	\
	unsigned long ll;		\
	unsigned int  nn;		\
	for (nn=0;nn<SHA256_DIGEST_LENGTH/4;nn++)	\
	{   ll=(c)->h[nn]; HOST_l2c(ll,(s));   }	\
	} while (0)

#define	HASH_UPDATE		SHA256X_Update
#define	HASH_TRANSFORM		SHA256X_Transform
#define	HASH_FINAL		SHA256X_Final
#define	HASH_BLOCK_DATA_ORDER	sha256_block_data_order
#ifndef SHA256_ASM
static
#endif
void sha256_block_data_order (SHA256X_CTX *ctx, const void *in, size_t num);

#include "md32_common.h"

#endif /* OPENSSL_NO_SHA256 */
