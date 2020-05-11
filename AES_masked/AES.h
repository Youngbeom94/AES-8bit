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

void MakeMakedValue(unsigned char *masked_sbox,unsigned char *M);
void Masked_M(unsigned char*state, unsigned char *M);
void Masked_M_2nd(unsigned char*state, unsigned char *M);
void Masked_M1_M4(unsigned char*state, unsigned char *M);
void Masked_M1_M4_2nd(unsigned char*state, unsigned char *M);
void AES_encrypt(const unsigned char *in, unsigned char *out, unsigned char* roundkey,unsigned char* M,unsigned char *masked_sbox);
void AES_encrypt_Random(const unsigned char *in, unsigned char *out, unsigned char* roundkey,unsigned char* M,unsigned char *masked_sbox);
void KeySchedule(unsigned char *key, unsigned char *roundkey,unsigned char *M,unsigned char *masked_sbox);
void SubByte(unsigned char *state, unsigned char *masked_sbox);
void ShiftRow(unsigned char *state);
void InvShiftRow(unsigned char *state);
void MixColumns(unsigned char *state);
void MixColumns_Origin(unsigned char *state);
void AddRoundKey(unsigned char *state, unsigned char * roundkey, int *round);

#endif