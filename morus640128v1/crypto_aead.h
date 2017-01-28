#pragma once


#define rotl(x,n)   (((x) << (n)) | ((x) >> (32-n)))

#define XOR128(x,y,z) {                                                                             \
    ((unsigned long long*)(x))[0] = ((unsigned long long*)(y))[0] ^ ((unsigned long long*)(z))[0];  \
    ((unsigned long long*)(x))[1] = ((unsigned long long*)(y))[1] ^ ((unsigned long long*)(z))[1];  \
}

#define AND128(x,y,z) {                                                                             \
    ((unsigned long long*)(x))[0] = ((unsigned long long*)(y))[0] & ((unsigned long long*)(z))[0];  \
    ((unsigned long long*)(x))[1] = ((unsigned long long*)(y))[1] & ((unsigned long long*)(z))[1];  \
}

int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k,
	int verbose
);

int crypto_aead_decrypt(
	unsigned char *m,unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
);

void morus_stateupdate(unsigned int msgblk[], unsigned int state[][4]);
void morus_initialization(const unsigned char *key, const unsigned char *iv, unsigned int state[][4]);
void morus_tag_generation(unsigned long long msglen, unsigned long long adlen, unsigned char *c, unsigned int state[][4]);
int morus_tag_verification(unsigned long long msglen, unsigned long long adlen, const unsigned char *c, unsigned int state[][4]);
void morus_enc_aut_step(const unsigned char *plaintextblock, unsigned char *ciphertextblock, unsigned int state[][4]);
void morus_dec_aut_step(unsigned char *plaintextblock, const unsigned char *ciphertextblock, unsigned int state[][4]);
