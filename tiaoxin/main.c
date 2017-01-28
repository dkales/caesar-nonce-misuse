#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tiaoxin-optimized.h"
#include "helper.h"

#define ITER 128

#define BLOCKSIZE 16
#define MSG_BLOCKSIZE 2*BLOCKSIZE


// the constant used in the cipher
unsigned char Z0[16] = {0x42,0x8a,0x2f,0x98,0xd7,0x28,0xae,0x22,0x71,0x37,0x44,0x91,0x23,0xef,0x65,0xcd};
unsigned char ZERO[16] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};


// public nonce, fixed during the attack
unsigned char  npub[BLOCKSIZE] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};

// the secret key, unknown to us during the attack 
unsigned char key[BLOCKSIZE]  = {0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f};

void encryption_oracle(unsigned char* plaintext, unsigned long long mlen, unsigned char* npub, unsigned char* ciphertext, unsigned long long* clen) {
    // we do not use the AD for this attack 
    unsigned char* ad   = NULL;
    unsigned long long adlen = 0;
    unsigned char* nsec = NULL;
    tiaoxin_optimized_encrypt( ad , adlen, plaintext, mlen, nsec, npub, key, ciphertext, clen );
}

void calc_T65(int offset, unsigned char* T65) {
  unsigned long long mlen = (3+offset)*MSG_BLOCKSIZE;
  unsigned long long clen = mlen + BLOCKSIZE;
  unsigned char plaintext[mlen];
  unsigned char ciphertext[clen];
  unsigned char attack[BLOCKSIZE];

  FILE* fr = fopen("/dev/urandom", "r");
  if (!fr) {
    perror("urandom");
    exit(EXIT_FAILURE);
  }

  unsigned char diff[ITER][BLOCKSIZE];
  memset(T65, 0, BLOCKSIZE);

  for(int i = 0; i < ITER; i++) {
    fread(attack, sizeof(unsigned char), BLOCKSIZE, fr);
    memset(plaintext,0,mlen);
    memcpy(plaintext+(MSG_BLOCKSIZE*offset), attack, BLOCKSIZE);
    memcpy(plaintext+(MSG_BLOCKSIZE*(offset+1)), attack, BLOCKSIZE);

    encryption_oracle(plaintext, mlen, npub, ciphertext, &clen);

    memcpy(diff[i], ciphertext+MSG_BLOCKSIZE*(2+offset)+BLOCKSIZE, BLOCKSIZE);
  }

  //check every difference with every other difference
  for(int i = 0; i < ITER; i++) {
    for(int j = i+1; j < ITER; j++) {
      //for all 16 bytes
      for(int k = 0; k < BLOCKSIZE; k++) {
        unsigned char byte_diff = diff[i][k] ^ diff[j][k];
        //for all 8 bits
        for(int b = 0; b < 8; b++) {
          if((byte_diff >> b) & 0x1) {
            //found difference, that means bit @ T65 is 1
            T65[k] |= 0x1 << b;
          }

        }
      }
    }
  }

  fclose(fr);
}

void inverse_update_T6(unsigned char T6[][BLOCKSIZE], unsigned char* M2) {
  unsigned char T6_old[6][BLOCKSIZE];
  //4 straight copies
  memcpy(T6_old[4], T6[5], BLOCKSIZE);
  memcpy(T6_old[3], T6[4], BLOCKSIZE);
  memcpy(T6_old[2], T6[3], BLOCKSIZE);
  memcpy(T6_old[1], T6[2], BLOCKSIZE);
  //one inverse AES operation with key Z0
  AESROUND_INV(T6_old[0], T6[1], Z0);

  //last one is AESROUND_INV(T6[0] xor T6_old[0] xor M2) with key zero
  XOR128(T6_old[5], T6[0], T6_old[0]);
  XOR128(T6_old[5], T6_old[5], M2);
  AESROUND_INV(T6_old[5], T6_old[5], ZERO);

  for(int i = 0; i < 6; i++) {
    memcpy(T6[i], T6_old[i], BLOCKSIZE);
  }
}

int main() {

  unsigned char T6[6][BLOCKSIZE];

  calc_T65(0, T6[5]);
  calc_T65(1, T6[4]);
  calc_T65(2, T6[3]);
  calc_T65(3, T6[2]);
  calc_T65(4, T6[1]);
  calc_T65(5, T6[0]);

  //block T65 needs an inverse AES transformation with subkey Z_0
  AESROUND_INV(T6[0], T6[0], Z0);

  /*printf("State T6 after 3 iterations:\n");
  printBlock("T6[0]", T6[0]);
  printBlock("T6[1]", T6[1]);
  printBlock("T6[2]", T6[2]);
  printBlock("T6[3]", T6[3]);
  printBlock("T6[4]", T6[4]);
  printBlock("T6[5]", T6[5]);*/

  //we now have T6, after 3 Updates with 0, so we reverse these
  for(int i = 0; i < 3; i++) {
    inverse_update_T6(T6, ZERO);
  }

  //then reverse initialization: 15 times with Z0
  for(int i = 0; i < 15; i++) {
    inverse_update_T6(T6, Z0);
  }

  //key is in T6[0] at the beginning:
  printBlock("real key     ", key);
  printBlock("recovered key", T6[0]);

  return 0;
}
