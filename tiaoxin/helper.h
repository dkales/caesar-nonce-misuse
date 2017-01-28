#ifndef HELPER_H
#define HELPER_H

void AESROUND_INV(unsigned char *out, unsigned char *in, unsigned char *rk);
void printBlock(const char* prefix, unsigned char* block);

#define XOR128(x,y,z) {                                                                             \
    ((unsigned long long*)(x))[0] = ((unsigned long long*)(y))[0] ^ ((unsigned long long*)(z))[0];  \
    ((unsigned long long*)(x))[1] = ((unsigned long long*)(y))[1] ^ ((unsigned long long*)(z))[1];  \
}

#endif
