#include "helper.h"
#include <immintrin.h>
#include <wmmintrin.h>

#include <stdio.h>

void printBlock(const char* prefix, unsigned char* block) {
  printf("%s: ", prefix);
  for(int i = 0; i < 16; i++) {
      printf("%02X", block[i]);
  }
  printf("\n");
}

void AESROUND_INV(unsigned char *out, unsigned char *in, unsigned char *rk)
{
      __m128i ct = _mm_load_si128((__m128i*)in);
      __m128i key = _mm_load_si128((__m128i*)rk);
      ct = _mm_xor_si128(ct, key);
      __m128i zero = _mm_setzero_si128();
      ct = _mm_aesenclast_si128(ct,zero);
      __m128i pt = _mm_aesdec_si128(ct,zero);
      pt = _mm_aesdeclast_si128(pt,zero);
      _mm_store_si128((__m128i*)out,pt);
}
