#include "AES.h"


const unsigned char in[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x7, 0x34};
// const unsigned char in[16] = {0x00};
unsigned char userkey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
// unsigned char userkey[16] = {0x00};
unsigned char out[16] = {0x00};
const unsigned char *plaintxt;
const unsigned char *UserKey;
static unsigned char masked_sbox[256] = {0x00};
unsigned char roundkey[176] = {0x00};

#if 1
int main()
{
    int cnt_i;
    srand(time(NULL));

    unsigned char M[10] = {0x10,0x20,0x30,0x40,0x50,0x60};
    MakeMakedValue(masked_sbox,M);

    for(cnt_i = 0 ; cnt_i <10 ; cnt_i ++)
    {
        printf("%02x ", M[cnt_i]);
    }

    printf("\nPlain Txt   : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", in[cnt_i]);
    }
    
    printf("\nKEY         : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", userkey[cnt_i]);
    }

    //! Encrypt
    KeySchedule(userkey,roundkey,M,masked_sbox);
    AES_encrypt(in, out, roundkey,M,masked_sbox);
    // AES_encrypt_Random(in, out, roundkey,M,masked_sbox);

    // printf("\n");
    // for(cnt_i = 0 ; cnt_i <176 ; cnt_i ++)
    // {
    //     if(cnt_i%16 == 0 )
    //         printf("\n");
    //     printf("%02x ",roundkey[cnt_i]);
    // }

    printf("\nEncrypt txt : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", out[cnt_i]);
    }
 
}
#endif
