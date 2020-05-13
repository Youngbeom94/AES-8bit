/*
    부채널 분석 및 응용 
    20175204 김영범
    2020년 05월 13일
*/
#ifndef __PLUS__
#define __PLUS__

//! header file
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <memory.h>

//! define
#define _CRT_SECURE_NO_WARNINGS
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define Nb 4 //Number of colmns
#define Nk 4 //Number of 32-bit words comprising the Cipher Key

//! checking AES security level. in this code we fix AES-128
#if Nk == 4
#define AES_MAXNR 10 //10 round
#define AES_KEY_BIT 128 // 128 bit
#elif Nk == 6
#define AES_MAXNR 12 // 12 round ;do not use
#define AES_KEY_BIT 192 // 192 bit ;do not use
#else Nk == 8
#define AES_MAXNR 14 // 14 round ;do not use
#define AES_KEY_BIT 256 // 256bit;do not use
#endif

void MakeMakedValue(unsigned char *masked_sbox,unsigned char *M); //마스킹값 랜덤으로 6개생성
void KeySchedule(unsigned char *key, unsigned char *roundkey,unsigned char *M,unsigned char *masked_sbox);//AES-128기준으로 각각의 라운드에서 쓰일 키생성하기
void SubByte_Masked(unsigned char *state, unsigned char *masked_sbox,unsigned char * M); //masked_Subbyte와 M',M1',M2',M3',M4' masking
void SubByte_Masked_dot(unsigned char *state, unsigned char *masked_sbox,unsigned char * M);//masked_Subbyte와 M' masking ,Using last Round
void AddRoundKey_Masked(unsigned char *state, unsigned char *roundkey, int *round, unsigned char* M);//AddroundKey와 M1',M2',M3',M4' masking
void FinalKeyAdd(unsigned char *state, unsigned char * roundkey,unsigned char* M);//10Round의 2nd AddroundKey with Masking M'. roundkey에 InvShiftRows 적용시켜서 state값에 반영
void ShiftRow(unsigned char *state);//Origin ShiftRow(just left Shift)
void MixColumns_Masked(unsigned char *state,unsigned char* M);//MixColumns연산, ShiftRow가 포함되어있음. shifRow는 memory 직접할당으로 구현,아울러 마지막에 M1',M2',M3',M4' masking
void AES_encrypt_Randomized(const unsigned char *in, unsigned char *out, unsigned char* roundkey,unsigned char* M,unsigned char *masked_sbox);//본 논문에서 제시하고 있는 Randomization 구현

#endif