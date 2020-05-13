#include "AES(128)_masked.h"
/*
    부채널 분석 및 응용 
    20175204 김영범
    2020년 05월 13일

*/
const unsigned char in[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x7, 0x34};//Plain txt
unsigned char userkey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};//User Key
unsigned char out[16] = {0x00};//Cipher
static unsigned char masked_sbox[256] = {0x00};//Masked Sbox
unsigned char roundkey[176] = {0x00};//Masked RoundKey in AES-128
unsigned char M[10] = {0x00,};//Mask Value

#if 1
int main()
{
    srand(time(NULL));//Setting Seed with Time(NULL)
    int cnt_i = 0x00;
    const unsigned char *plaintxt;//Plain txt
    const unsigned char *UserKey;//Usr key

    MakeMakedValue(masked_sbox,M); //Set masked_Sbox and Masking VALUE M,M',M1,M2,M3,M4,M1',M2',M3',M4'

    printf("\nMask value  : ");//print Mask value
    for(cnt_i = 0 ; cnt_i <10 ; cnt_i ++)
        printf("%02x ", M[cnt_i]);

    printf("\nPlain Txt   : ");//print plain txt
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
        printf("%02x ", in[cnt_i]);
    
    printf("\nKEY         : ");//print Key
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
        printf("%02x ", userkey[cnt_i]);
    
    //! Encrypt
    KeySchedule(userkey,roundkey,M,masked_sbox);//we need to generate key using AES Round. 
    AES_encrypt_Randomized(in, out, roundkey,M,masked_sbox);// Encryption

    printf("\nEncrypt txt : ");//print Cipher txt
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
        printf("%02x ", out[cnt_i]);
}
#endif
