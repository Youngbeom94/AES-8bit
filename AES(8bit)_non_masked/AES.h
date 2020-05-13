//* 암호 최적화 및 암호응용 연구실 20175204 김영범
#ifndef __PLUS__
#define __PLUS__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <memory.h>

#define _CRT_SECURE_NO_WARNINGS
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define Nb 4 //Number of colmns
#define Nk 4 //Number of 32-bit words comprising the Cipher Key

#if Nk == 4
#define AES_MAXNR 10 //10 round
#define AES_KEY_BIT 128 // 128 bit
#elif Nk == 6
#define AES_MAXNR 12 // 12 round
#define AES_KEY_BIT 192 // 192 bit
#else Nk == 8
#define AES_MAXNR 14 // 14 round
#define AES_KEY_BIT 256 // 256bit
#endif

typedef struct aes_key_st
{
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void SubByte(unsigned char *state);
void ShiftRow(unsigned char *state);
void MixColumns(unsigned char *state);
void AddRoundKey(unsigned char *state, const AES_KEY *key, int *round);

int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void Swap(unsigned int *src1, unsigned int *src2); //int자료형 두개의 위치 Swap 해주는 함수.
void InvSubByte(unsigned char *state);
void InvShiftRow(unsigned char *state);
void InvMixColumns(unsigned char *state);

int64_t cpucycles(void); // RDTSC

#endif