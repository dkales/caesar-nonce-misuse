#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_aead.h"

#define BLOCKSIZE 16

// public nonce, fixed during the attack
unsigned char  npub[BLOCKSIZE] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};

// the secret key, unknown to us during the attack 
unsigned char key[BLOCKSIZE]  = {0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f};

void encryption_oracle(unsigned char* plaintext, unsigned long long mlen, unsigned char* npub, unsigned char* ciphertext, unsigned long long* clen, int verbose) {
    // we do not use the AD for this attack 
    unsigned char* ad   = NULL;
    unsigned long long adlen = 0;
    unsigned char* nsec = NULL;
    // the verbose parameter prints the internal state, allowing us to compare the real state to our recovered one
    crypto_aead_encrypt(ciphertext, clen, plaintext, mlen, ad, adlen, nsec, npub, key, verbose);
}

void calc_s3(unsigned char* s3, int offset, unsigned char* prefix) {

  unsigned long long NUM_BLOCKS = 2 + offset;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  unsigned char  plaintext2[mlen];
  unsigned char  ciphertext2[mlen+BLOCKSIZE];

  memset(plaintext,0,mlen);
  memcpy(plaintext, prefix, BLOCKSIZE*offset);

  memset(plaintext2, 0, mlen);
  memcpy(plaintext2, prefix, BLOCKSIZE*offset);
  memset(plaintext2+BLOCKSIZE*offset, 0xFF, BLOCKSIZE);

  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, (offset==0));
  encryption_oracle(plaintext2, mlen, npub, ciphertext2, &clen, 0);

  unsigned char diff1[BLOCKSIZE];
  unsigned char diff2[BLOCKSIZE];

  XOR128(diff1, plaintext+(offset+1)*BLOCKSIZE, ciphertext+(offset+1)*BLOCKSIZE);
  XOR128(diff2, plaintext2+(offset+1)*BLOCKSIZE, ciphertext2+(offset+1)*BLOCKSIZE);
  //xor with rotated plaintext2, rotation not needed in our easy case
  XOR128(diff2, diff2, plaintext2+(offset*BLOCKSIZE));

  for(int k = 0; k < BLOCKSIZE; k++) {
    unsigned char byte_diff = diff1[k] ^ diff2[k];
    //for all 8 bits
    for(int b = 0; b < 8; b++) {
      if((byte_diff >> b) & 0x1) {
        //found difference, that means bit @ s3 is 1
        s3[k] |= 0x1 << b;
      }
    }
  }

}

void calc_s2(unsigned char* s2, int offset, unsigned char* prefix) {

  unsigned long long NUM_BLOCKS = 2 + offset;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  unsigned char  plaintext2[mlen];
  unsigned char  plaintext2_inv_block[BLOCKSIZE];
  unsigned char  plaintext2_rot[mlen];
  unsigned char  plaintext2_rot_inv_block[BLOCKSIZE];
  unsigned char  ciphertext2[mlen+BLOCKSIZE];
  unsigned char  ciphertext2_rot[mlen+BLOCKSIZE];

  memset(plaintext,0,mlen);
  memcpy(plaintext, prefix, BLOCKSIZE*offset);


  memset(plaintext2, 0, mlen);
  memcpy(plaintext2, prefix, BLOCKSIZE*offset);
  memset(plaintext2+offset*BLOCKSIZE, 0xAA, BLOCKSIZE/4);
  memset(plaintext2+offset*BLOCKSIZE+BLOCKSIZE/2, 0xAA, BLOCKSIZE/4);

  memset(plaintext2_rot, 0, mlen);
  memcpy(plaintext2_rot, prefix, BLOCKSIZE*offset);
  memset(plaintext2_rot+offset*BLOCKSIZE+BLOCKSIZE/4, 0xAA, BLOCKSIZE/4);
  memset(plaintext2_rot+offset*BLOCKSIZE+BLOCKSIZE*3/4, 0xAA, BLOCKSIZE/4);

  //plaintext block with internal rotation by 31, and whole rotation by 64 and 96
  memset(plaintext2_inv_block, 0, BLOCKSIZE);
  memset(plaintext2_inv_block+BLOCKSIZE/4, 0x55, BLOCKSIZE/4);
  memset(plaintext2_inv_block+BLOCKSIZE*3/4, 0x55, BLOCKSIZE/4);

  memset(plaintext2_rot_inv_block, 0, BLOCKSIZE);
  memset(plaintext2_rot_inv_block, 0x55, BLOCKSIZE/4);
  memset(plaintext2_rot_inv_block+BLOCKSIZE/2, 0x55, BLOCKSIZE/4);

  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, 0);
  encryption_oracle(plaintext2, mlen, npub, ciphertext2, &clen, 0);
  encryption_oracle(plaintext2_rot, mlen, npub, ciphertext2_rot, &clen, 0);

  unsigned char diff1[BLOCKSIZE];
  unsigned char diff2[BLOCKSIZE];
  unsigned char diff3[BLOCKSIZE];

  XOR128(diff1, plaintext+(offset+1)*BLOCKSIZE, ciphertext+(offset+1)*BLOCKSIZE);
  XOR128(diff2, plaintext2+(offset+1)*BLOCKSIZE, ciphertext2+(offset+1)*BLOCKSIZE);
  //xor with rotated plaintext2
  XOR128(diff2, diff2, /*rot64&rot96*/ plaintext2_inv_block);

  XOR128(diff3, plaintext2_rot+(offset+1)*BLOCKSIZE, ciphertext2_rot+(offset+1)*BLOCKSIZE);
  //xor with rotated plaintext2
  XOR128(diff3, diff3, /*rot64&rot96*/ plaintext2_rot_inv_block);

  for(int k = 0; k < BLOCKSIZE; k++) {
    unsigned char byte_diff;
    //select difference based on index
    if((k / (BLOCKSIZE/4)) % 2 == 0) {
      byte_diff = diff1[k] ^ diff2[k];
    }
    else {
      byte_diff = diff1[k] ^ diff3[k];
    }
    //for all 8 bits
    for(int b = 0; b < 8; b++) {
      if((byte_diff >> b) & 0x1) {
        //found difference, that means bit @ s2 is 1
        s2[k] |= 0x1 << b;
      }
    }
  }

}


void calc_part_s1(unsigned char* message, unsigned char* s2_old, unsigned char* s3_old, int word_selector) {

  unsigned long long NUM_BLOCKS = 2+1;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  unsigned int s2_rot[4];
  unsigned int s3_new[4];
  unsigned int temp1[4];
  unsigned char s2_2[BLOCKSIZE] = {0,};
  unsigned char s2_3[BLOCKSIZE] = {0,};
  unsigned char ones[BLOCKSIZE] = {0,};

  unsigned int* s2_old_ptr = (unsigned int*) s2_old;
  unsigned int* s3_old_ptr = (unsigned int*) s3_old;
  s2_rot[0] = rotl(s2_old_ptr[1], 25); //32-7
  s2_rot[1] = rotl(s2_old_ptr[2], 25);
  s2_rot[2] = rotl(s2_old_ptr[3], 25);
  s2_rot[3] = rotl(s2_old_ptr[0], 25);

  if(word_selector){
    memset(ones+(word_selector-1)*BLOCKSIZE/4, 0xFF, BLOCKSIZE/4);
    XOR128(s2_rot, s2_rot, ones);
  }

  temp1[0] = rotl(s2_rot[0], 31);
  temp1[1] = rotl(s2_rot[1], 31);
  temp1[2] = rotl(s2_rot[2], 31);
  temp1[3] = rotl(s2_rot[3], 31);
  XOR128(temp1, temp1, s2_rot);
  temp1[0] = rotl(temp1[0], 22);
  temp1[1] = rotl(temp1[1], 22);
  temp1[2] = rotl(temp1[2], 22);
  temp1[3] = rotl(temp1[3], 22);
  XOR128(s3_new, s3_old_ptr, temp1)

  //printBlock("s3_new", s3_new);

  memset(plaintext,0,mlen);
  memcpy(plaintext, s2_rot, BLOCKSIZE);

  calc_s2(s2_2, 1, (unsigned char*) s2_rot);
  calc_s3(s2_3, 1, (unsigned char*) s2_rot);

  //printBlock("S2_2", s2_2);
  //printBlock("S2_3", s2_3);
  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, 0);

  unsigned char diff[BLOCKSIZE];

  XOR128(diff, plaintext+2*BLOCKSIZE, ciphertext+2*BLOCKSIZE);
  AND128(temp1, s2_2, s2_3);
  XOR128(diff, diff, temp1)

  memcpy(message, diff, BLOCKSIZE);
}

void calc_s1(unsigned char* s1, unsigned char* s2_old, unsigned char* s3_old) {
  unsigned char diff1[BLOCKSIZE];
  unsigned char diff2[BLOCKSIZE];
  unsigned int temp[BLOCKSIZE/4];

  unsigned int* s1_ptr = (unsigned int*) s1;


  calc_part_s1(diff1, s2_old, s3_old, 0);
  calc_part_s1(diff2, s2_old, s3_old, 1);
  XOR128(temp, diff1, diff2);
  s1_ptr[1] = rotl(temp[0],27);

  calc_part_s1(diff2, s2_old, s3_old, 2);
  XOR128(temp, diff1, diff2);
  s1_ptr[2] = rotl(temp[1],27);

  calc_part_s1(diff2, s2_old, s3_old, 3);
  XOR128(temp, diff1, diff2);
  s1_ptr[3] = rotl(temp[2],27);

  calc_part_s1(diff2, s2_old, s3_old, 4);
  XOR128(temp, diff1, diff2);
  s1_ptr[0] = rotl(temp[3],27);

  unsigned int s2_rot[4];

  unsigned int* s2_old_ptr = (unsigned int*) s2_old;
  s2_rot[0] = rotl(s2_old_ptr[1], 25); //32-7
  s2_rot[1] = rotl(s2_old_ptr[2], 25);
  s2_rot[2] = rotl(s2_old_ptr[3], 25);
  s2_rot[3] = rotl(s2_old_ptr[0], 25);
  unsigned int temp2;
  temp2 = s2_rot[0];
  s2_rot[0] = s2_rot[2];
  s2_rot[2] = temp2;
  temp2 = s2_rot[1];
  s2_rot[1] = s2_rot[3];
  s2_rot[3] = temp2;
  s2_rot[0] = rotl(s2_rot[0], 31); //b1=31
  s2_rot[1] = rotl(s2_rot[1], 31);
  s2_rot[2] = rotl(s2_rot[2], 31);
  s2_rot[3] = rotl(s2_rot[3], 31);

  XOR128(s1,s1,s2_rot);
}

void calc_s0(unsigned char* s0, unsigned char* s1, unsigned char* s2, unsigned char* s3) {
  unsigned long long NUM_BLOCKS = 2;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  memset(plaintext,0,mlen);

  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, 0);

  unsigned char diff1[BLOCKSIZE];
  unsigned char temp[BLOCKSIZE];

  XOR128(diff1, plaintext+(1)*BLOCKSIZE, ciphertext+(1)*BLOCKSIZE);
  //xor with rotated plaintext2, rotation not needed in our easy case
  AND128(temp, s2, s3);
  XOR128(diff1, diff1, temp);
  unsigned int* temp_ptr = (unsigned int*)temp;
  unsigned int* s1_ptr = (unsigned int*)s1;
  temp_ptr[0] = s1_ptr[1];
  temp_ptr[1] = s1_ptr[2];
  temp_ptr[2] = s1_ptr[3];
  temp_ptr[3] = s1_ptr[0];
  XOR128(s0, diff1, temp);
}


void calc_s4(unsigned char* s4, unsigned char* s0, unsigned char* s1, unsigned char* s2, unsigned char* s3) {
  unsigned char next_s2[BLOCKSIZE] = {0,};
  unsigned char next_s3[BLOCKSIZE] = {0,};
  unsigned char zero[BLOCKSIZE] = {0,};
  unsigned int next_s0[BLOCKSIZE/4];
  AND128(next_s0, s1, s2);
  XOR128(next_s0, next_s0, s0);
  XOR128(next_s0, next_s0, s3);

  next_s0[0] = rotl(next_s0[0], 5);
  next_s0[1] = rotl(next_s0[1], 5);
  next_s0[2] = rotl(next_s0[2], 5);
  next_s0[3] = rotl(next_s0[3], 5);

  unsigned int temp = next_s0[0];
  next_s0[0] = next_s0[1];
  next_s0[1] = next_s0[2];
  next_s0[2] = next_s0[3];
  next_s0[3] = temp;

  calc_s2(next_s2, 1, zero);
  calc_s3(next_s3, 1, zero);

  unsigned long long NUM_BLOCKS = 3;
  unsigned long long mlen= NUM_BLOCKS*BLOCKSIZE;
  unsigned long long clen;

  unsigned char  plaintext[mlen];
  unsigned char  ciphertext[mlen+BLOCKSIZE];

  memset(plaintext,0,mlen);

  encryption_oracle(plaintext, mlen, npub, ciphertext, &clen, 0);

  unsigned int next_s1[BLOCKSIZE/4];
  unsigned int temp2[BLOCKSIZE/4];

  XOR128(next_s1, plaintext+(2)*BLOCKSIZE, ciphertext+(2)*BLOCKSIZE);
  AND128(temp2, next_s2, next_s3);
  XOR128(next_s1, next_s1, temp2);
  XOR128(next_s1, next_s1, next_s0);

  temp = next_s1[0];
  next_s1[0] = next_s1[3];
  next_s1[3] = next_s1[2];
  next_s1[2] = next_s1[1];
  next_s1[1] = temp;

  //printBlock("s2_1", next_s1);

  temp = next_s1[0];
  next_s1[0] = next_s1[2];
  next_s1[2] = temp;
  temp = next_s1[1];
  next_s1[1] = next_s1[3];
  next_s1[3] = temp;


  next_s1[0] = rotl(next_s1[0], 1);
  next_s1[1] = rotl(next_s1[1], 1);
  next_s1[2] = rotl(next_s1[2], 1);
  next_s1[3] = rotl(next_s1[3], 1);

  unsigned int* s3_ptr = (unsigned int*) s3;
  temp2[0] = s3_ptr[3];
  temp2[1] = s3_ptr[0];
  temp2[2] = s3_ptr[1];
  temp2[3] = s3_ptr[2];

  AND128(temp2, s2, temp2);
  XOR128(s4, s1, next_s1);
  XOR128(s4, s4, temp2);
}


#define n1_inv 27
#define n2_inv 1
#define n3_inv 25
#define n4_inv 10
#define n5_inv 19
void inverse_morus_stateupdate(unsigned int msgblk[], unsigned int state[][4]) {
  unsigned int temp;

  temp = state[2][0];    state[2][0] = state[2][1];  state[2][1] = state[2][2];  state[2][2] = state[2][3];  state[2][3] = temp;
  state[4][0] = rotl(state[4][0],n5_inv);  state[4][1] = rotl(state[4][1],n5_inv);       state[4][2] = rotl(state[4][2],n5_inv);       state[4][3] = rotl(state[4][3],n5_inv);
  state[4][0] ^= state[0][0] & state[1][0]; state[4][1] ^= state[0][1] & state[1][1]; state[4][2] ^= state[0][2] & state[1][2]; state[4][3] ^= state[0][3] & state[1][3];
  state[4][0] ^= state[2][0]; state[4][1] ^= state[2][1]; state[4][2] ^= state[2][2]; state[4][3] ^= state[2][3];
  state[4][0] ^= msgblk[0];   state[4][1] ^= msgblk[1];   state[4][2] ^= msgblk[2];   state[4][3] ^= msgblk[3];

  temp = state[1][2];    state[1][2] = state[1][0];  state[1][0] = temp;
  temp = state[1][3];    state[1][3] = state[1][1];  state[1][1] = temp;
  state[3][0] = rotl(state[3][0],n4_inv);  state[3][1] = rotl(state[3][1],n4_inv);       state[3][2] = rotl(state[3][2],n4_inv);       state[3][3] = rotl(state[3][3],n4_inv);
  state[3][0] ^= state[4][0] & state[0][0]; state[3][1] ^= state[4][1] & state[0][1]; state[3][2] ^= state[4][2] & state[0][2]; state[3][3] ^= state[4][3] & state[0][3];
  state[3][0] ^= state[1][0]; state[3][1] ^= state[1][1]; state[3][2] ^= state[1][2]; state[3][3] ^= state[1][3];
  state[3][0] ^= msgblk[0];   state[3][1] ^= msgblk[1];   state[3][2] ^= msgblk[2];   state[3][3] ^= msgblk[3];

  temp = state[0][3];    state[0][3] = state[0][2];  state[0][2] = state[0][1];  state[0][1] = state[0][0];  state[0][0] = temp;
  state[2][0] = rotl(state[2][0],n3_inv);  state[2][1] = rotl(state[2][1],n3_inv);       state[2][2] = rotl(state[2][2],n3_inv);       state[2][3] = rotl(state[2][3],n3_inv);
  state[2][0] ^= state[3][0] & state[4][0]; state[2][1] ^= state[3][1] & state[4][1]; state[2][2] ^= state[3][2] & state[4][2]; state[2][3] ^= state[3][3] & state[4][3];
  state[2][0] ^= state[0][0]; state[2][1] ^= state[0][1]; state[2][2] ^= state[0][2]; state[2][3] ^= state[0][3];
  state[2][0] ^= msgblk[0];   state[2][1] ^= msgblk[1];   state[2][2] ^= msgblk[2];   state[2][3] ^= msgblk[3];

  temp = state[4][3];    state[4][3] = state[4][1];  state[4][1] = temp;
  temp = state[4][2];    state[4][2] = state[4][0];  state[4][0] = temp;
  state[1][0] = rotl(state[1][0],n2_inv);  state[1][1] = rotl(state[1][1],n2_inv);       state[1][2] = rotl(state[1][2],n2_inv);       state[1][3] = rotl(state[1][3],n2_inv);
  state[1][0] ^= (state[2][0] & state[3][0]); state[1][1] ^= (state[2][1] & state[3][1]); state[1][2] ^= (state[2][2] & state[3][2]); state[1][3] ^= (state[2][3] & state[3][3]);
  state[1][0] ^= state[4][0]; state[1][1] ^= state[4][1]; state[1][2] ^= state[4][2]; state[1][3] ^= state[4][3];
  state[1][0] ^= msgblk[0];   state[1][1] ^= msgblk[1];   state[1][2] ^= msgblk[2];   state[1][3] ^= msgblk[3];

  temp = state[3][0];    state[3][0] = state[3][1];  state[3][1] = state[3][2];  state[3][2] = state[3][3];  state[3][3] = temp;
  state[0][0] = rotl(state[0][0],n1_inv);  state[0][1] = rotl(state[0][1],n1_inv);       state[0][2] = rotl(state[0][2],n1_inv);       state[0][3] = rotl(state[0][3],n1_inv);
  state[0][0] ^= state[1][0] & state[2][0]; state[0][1] ^= state[1][1] & state[2][1]; state[0][2] ^= state[1][2] & state[2][2]; state[0][3] ^= state[1][3] & state[2][3];
  state[0][0] ^= state[3][0]; state[0][1] ^= state[3][1]; state[0][2] ^= state[3][2]; state[0][3] ^= state[3][3];

}

void printBlock(const char* prefix, unsigned char* block) {
  printf("%s: ", prefix);
  for(int i = 0; i < BLOCKSIZE; i++) {
      printf("%02X", block[i]);
  }
  printf("\n");
}

int main() {

  unsigned char s1_0[BLOCKSIZE] = {0,};
  unsigned char s1_1[BLOCKSIZE] = {0,};
  unsigned char s1_2[BLOCKSIZE] = {0,};
  unsigned char s1_3[BLOCKSIZE] = {0,};
  unsigned char s1_4[BLOCKSIZE] = {0,};
  unsigned int zero[BLOCKSIZE] = {0,};

  printf("Real State:\n");
  calc_s2(s1_2, 0, NULL);

  calc_s3(s1_3, 0, NULL);

  calc_s1(s1_1, s1_2, s1_3);

  calc_s0(s1_0, s1_1, s1_2, s1_3);

  calc_s4(s1_4, s1_0, s1_1, s1_2, s1_3);

  printf("Recovered State:\n");
  printBlock("S1_0", s1_0);
  printBlock("S1_1", s1_1);
  printBlock("S1_2", s1_2);
  printBlock("S1_3", s1_3);
  printBlock("S1_4", s1_4);
  //printBlock("S2_2", s2_2);
  //printBlock("S2_3", s2_3);

  unsigned int morus_state[5][4];
  memcpy(morus_state[0], s1_0, BLOCKSIZE);
  memcpy(morus_state[1], s1_1, BLOCKSIZE);
  memcpy(morus_state[2], s1_2, BLOCKSIZE);
  memcpy(morus_state[3], s1_3, BLOCKSIZE);
  memcpy(morus_state[4], s1_4, BLOCKSIZE);

  //get to S0
  inverse_morus_stateupdate(zero, morus_state);


  return 0;
}
