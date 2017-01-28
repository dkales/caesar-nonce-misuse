#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_aead.h"

#define BLOCKSIZE 16

#define ITER 128  //128 iterations makes it pretty stable

// public nonce, fixed during the attack
unsigned char  npub[BLOCKSIZE] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};

// the secret key, unknown to us during the attack 
unsigned char key[BLOCKSIZE]  = {0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f};

void encryption_oracle(unsigned char* plaintext, unsigned long long mlen, unsigned char* npub, unsigned char* ciphertext, unsigned long long* clen, int verbose) {
    // we do not use the AD for this attack 
    unsigned char* ad   = NULL;
    unsigned long long adlen = 0;
    unsigned char* nsec = NULL;
    // the verbose parameter allows us to compare our recovered state to the real one
    crypto_aead_encrypt(ciphertext, clen, plaintext, mlen, ad, adlen, nsec, npub, key, verbose);
}

void calc_sX3(unsigned char* sX3, unsigned char* prefix, unsigned long long offset) {

  unsigned long long NUM_BLOCKS = 4+offset;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  unsigned char attack[BLOCKSIZE];
  FILE* fr = fopen("/dev/urandom", "r");
  if (!fr) {
    perror("urandom");
    exit(EXIT_FAILURE);
  }

  unsigned char diff[ITER][BLOCKSIZE];
  memset(sX3,0,BLOCKSIZE);

  for(int i = 0; i < ITER; i++) {
    fread(attack, sizeof(char), BLOCKSIZE, fr);

    memset(plaintext,0,mlen);
    memcpy(plaintext, prefix, offset*BLOCKSIZE);
    memcpy(plaintext+offset*BLOCKSIZE, attack, BLOCKSIZE);
    memcpy(plaintext+(offset+1)*BLOCKSIZE, attack, BLOCKSIZE);

    encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, (i==0 && offset ==3));

    unsigned char diff1[BLOCKSIZE];
    XOR128(diff1, plaintext+(offset+2)*BLOCKSIZE, ciphertext+(offset+2)*BLOCKSIZE);
    XOR128(diff[i], plaintext+(offset+3)*BLOCKSIZE, ciphertext+(offset+3)*BLOCKSIZE);
    XOR128(diff[i], diff1, diff[i]);
  }

  fclose(fr);

  //check every difference with every other difference
  for(int i = 0; i < ITER; i++) {
    for(int j = i+1; j < ITER; j++) {
      //for all 16 bytes
      for(int k = 0; k < BLOCKSIZE; k++) {
        unsigned char byte_diff = diff[i][k] ^ diff[j][k];
        //for all 8 bits
        for(int b = 0; b < 8; b++) {
          if((byte_diff >> b) & 0x1) {
            //found difference, that means bit @ sX3 is 1
            sX3[k] |= 0x1 << b;
          }

        }
      }
    }
  }
}


void calc_s34(unsigned char* s34, unsigned char* plaintext_prefix,
  unsigned char* s31, unsigned char* s32, unsigned char* s33) {

  unsigned long long NUM_BLOCKS = 4;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  memset(plaintext,0,mlen);
  memcpy(plaintext, plaintext_prefix, 2*BLOCKSIZE);

  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, 0);

  AND128(s34,s32,s33);
  XOR128(s34,s31,s34);

  unsigned char diff1[BLOCKSIZE];
  XOR128(diff1, plaintext+3*BLOCKSIZE, ciphertext+3*BLOCKSIZE);
  XOR128(s34,s34,diff1);
}

void printBlock(const char* prefix, unsigned char* block) {
  unsigned long long* block_ull = (unsigned long long*) block;
  printf("%s: %016llX%016llX\n", prefix, block_ull[0], block_ull[1]);
}

int main() {

  unsigned char s33[BLOCKSIZE];
  unsigned char s43[BLOCKSIZE];
  unsigned char s53[BLOCKSIZE];
  unsigned char s63[BLOCKSIZE];

  unsigned char s32[BLOCKSIZE];
  unsigned char s42[BLOCKSIZE];
  unsigned char s52[BLOCKSIZE];

  unsigned char s31[BLOCKSIZE];
  unsigned char s41[BLOCKSIZE];

  unsigned char s34[BLOCKSIZE];
  unsigned char s30[BLOCKSIZE];

  unsigned char wanted_plaintext_prefix[BLOCKSIZE*3];
  memset(wanted_plaintext_prefix, 0, BLOCKSIZE);
  memset(wanted_plaintext_prefix+BLOCKSIZE, 1, BLOCKSIZE);
  memset(wanted_plaintext_prefix+2*BLOCKSIZE, 2, BLOCKSIZE);

  printf("Real State:\n");
  calc_sX3(s33, NULL, 0);
  calc_sX3(s43, wanted_plaintext_prefix, 1);
  calc_sX3(s53, wanted_plaintext_prefix, 2);
  calc_sX3(s63, wanted_plaintext_prefix, 3);

  AESROUND_INV(s32, s43, s33);
  AESROUND_INV(s42, s53, s43);
  AESROUND_INV(s52, s63, s53);

  AESROUND_INV(s31, s42, s32);
  AESROUND_INV(s41, s52, s42);

  AESROUND_INV(s30, s41, s31);

  calc_s34(s34, wanted_plaintext_prefix, s31, s32, s33);

  printf("Recovered State:\n");
  printBlock("s30", s30);
  printBlock("s31", s31);
  printBlock("s32", s32);
  printBlock("s33", s33);
  printBlock("s34", s34);


  return 0;
}
