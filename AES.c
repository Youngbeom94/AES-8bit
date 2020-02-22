#include "AES.h"

static const unsigned char Rcon[13] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab};
static const unsigned char sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const unsigned char rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


void SubByte(unsigned char *state)
{
    int cnt_i;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        *(state + cnt_i) = sbox[state[cnt_i]]; //sbox를 이용해 치환하기
    }
}
void ShiftRow(unsigned char *state)
{
    int temp, temp2;
    temp = state[13]; //2번째 행 1칸 Leftshift
    state[13] = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = temp;

    temp = state[10]; //3번째 행 2칸 Leftshift
    temp2 = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2] = temp;
    state[6] = temp2;

    temp = state[7]; // 4번째 행 3칸 Leftshift
    state[7] = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = temp;
}
void MixColumns(unsigned char *state)
{
    unsigned char *temp;
    temp = (unsigned char *)calloc(2, sizeof(unsigned char)); // 행렬곱셈에 이용할 값들 저장시키는 변수
    unsigned char *src;
    src = (unsigned char *)calloc(4, sizeof(unsigned char)); // 4개의 state 배열의 최종상태 저장시키는 변수
    for (int cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        //? 02 03 01 01
        temp[0] = state[4 * cnt_i] ^ state[4 * cnt_i + 1]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[0] = temp[0] ^ temp[1];                                                   // 최종 src
        //? 01 02 03 01
        temp[0] = state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[1] = temp[0] ^ temp[1];                                               // 최종 src
        //? 01 01 02 03
        temp[0] = state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[2] = temp[0] ^ temp[1];                                               // 최종 src
        //? 03 01 01 03
        temp[0] = state[4 * cnt_i] ^ state[4 * cnt_i + 3]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2];
        src[3] = temp[0] ^ temp[1]; // 최종 src

        for (int cnt_j = 0; cnt_j < 4; cnt_j++) // 각각의 src값을 state에 대입해주기
        {
            state[4 * cnt_i + cnt_j] = src[cnt_j];
        }
    }
    free(temp);
    free(src);
}
void RotWord(int *Word) // int 기준으로 값을 받고 1byte left Rotation
{
    int temp;
    temp = *Word << 8;
    *Word = *Word >> 24;
    *Word &= 0x000000ff;
    *Word ^= temp;
}
void SubWord(int *Word) // int 기준으로 값을 받고 int를 4개의 byte로 쪼개서 byte를 sbox의 값으로 치환
{
    int cnt_i = 0;
    unsigned char temp[4] = {0x00};
    int temp2;
    for (cnt_i = 0; cnt_i < 4; cnt_i++) // 값 쪼개서 sbox로 치환해서 temp배열에 저장
    {
        temp2 = (*Word >> (24 - (8 * cnt_i)));
        temp2 &= 0x000000ff;
        temp[cnt_i] = sbox[temp2];
    }
    *Word = 0;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        *Word += (temp[cnt_i] << (24 - (8 * cnt_i))); // 다시 쪼개고 치환한 값들을 다시 합쳐주기
    }
}

void Byte_Int_Set(const unsigned char *userKey, AES_KEY *key, int start) // byte 16개 배열을 int함수에 저장시키는 함수
{
    int temp = 0;
    for (int cnt_i = 0; cnt_i < 4; cnt_i++) // 저장할 공간을 먼저 초기화 시키기
    {
        key->rd_key[start + cnt_i] = 0;
    }

    for (int cnt_i = 0; cnt_i < 4; cnt_i++) // byte 16개를 int 4개 배열에 저장시키기
    {
        for (int cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            temp = userKey[cnt_j + (cnt_i * 4)] << ((3 - cnt_j) * 8);
            key->rd_key[start + cnt_i] += temp;
            temp = 0;
        }
    }
}
int AES_set_encrypt_key(const unsigned char *userkey, const int bits, AES_KEY *key) //키생성 함수
{

    int cnt_i;
    int temp;
    Byte_Int_Set(userkey, key, 0); //처음 Masterkey(userkey)를 처음 4개의 배열에 저장시키기

    for (cnt_i = 4; cnt_i < Nb * (AES_MAXNR + 1); cnt_i++) // Round 10번에 관한 Key 생성
    {
        temp = key->rd_key[cnt_i - 1];
        if (cnt_i % Nk == 0)
        {
            RotWord(&temp);
            SubWord(&temp);
            temp ^= Rcon[(cnt_i / Nk) - 1] << 24;
        }
        else if ((Nk > 6) && (cnt_i % Nk == 4)) // 192bit 이상일때
        {
            SubWord(&temp);
        }
        key->rd_key[cnt_i] = key->rd_key[cnt_i - Nk] ^ temp;
        // printf("%d %08x \n",cnt_i,key->rd_key[cnt_i]);
    }
    if (bits == 128) // 반환값은 bits에 따라 라운드 값을 반환하기.
        return 10;
    if (bits == 192)
        return 12;
    if (bits == 256)
        return 14;
    printf("\nERROR\n");
    return -1;
}

void AddRoundKey(unsigned char *state, const AES_KEY *key, int *round)
{
    int cnt_i, cnt_j = 0;
    int temp;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    { // 키는 int 배열 4개이고 state는 byte배열 16개 이므로 XoR시 쪼개고 합치는 과정이 필요
        for (cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            temp = (key->rd_key[(*round * 4) + cnt_i]);
            temp = temp >> (24 - (8 * cnt_j));
            temp &= 0x000000ff;
            state[cnt_j + (cnt_i * 4)] ^= temp;
        }
    }

    *round += 1;
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    unsigned char state[4 * Nb];
    int cnt_i,cnt_j;
    int round = 0;

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        state[cnt_i] = in[cnt_i];
    }

    AddRoundKey(state, key, &round);

    for (cnt_i = 1; cnt_i < AES_MAXNR; cnt_i++)
    {
        SubByte(state);
        ShiftRow(state);
        MixColumns(state);
        AddRoundKey(state, key, &round);
    printf("\n");
    for(cnt_j=  0; cnt_j < 16; cnt_j ++)
    {
        printf("%02x ",state[cnt_j]);
    }
    }
    
    SubByte(state);
    printf("\n");
    for(cnt_i=  0; cnt_i < 16; cnt_i ++)
    {
        printf("%02x ",state[cnt_i]);
    }
    ShiftRow(state);
    AddRoundKey(state, key, &round);

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}

//! Inverse
void InvShiftRow(unsigned char *state)
{
    int temp, temp2;
    temp = state[13]; //2번째 행 1칸 Rightshift
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[10]; //2번째 행 2칸 Rightshift
    temp2 = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2] = temp;
    state[6] = temp2;

    temp = state[3]; //2번째 행 3칸 Rightshift
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}
void InvSubByte(unsigned char *state)
{
    int cnt_i;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        *(state + cnt_i) = rsbox[state[cnt_i]]; //inVSubyte이므로 rsbox값으로 치환
    }
}
void InvMixColumns(unsigned char *state)
{

    unsigned char *temp;
    temp = (unsigned char *)calloc(2, sizeof(unsigned char));
    unsigned char *src;
    src = (unsigned char *)calloc(4, sizeof(unsigned char));
    for (int cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        //? 0e 0b 0d 09
        temp[0] = state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3];
        temp[0] = xtime(temp[0]);
        temp[1] = temp[0];
        temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 2];
        temp[1] = xtime(temp[1]);
        temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 1]; 
        temp[1] = xtime(temp[1]);
        src[0] = temp[1] ^= state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3];

        //? 09 0e 0b 0d
        temp[1] = temp[0];
        temp[1] ^= state[4 * cnt_i + 1] ^ state[4 * cnt_i + 3];
        temp[1] = xtime(temp[1]);
        temp[1] ^= state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2]; 
        temp[1] = xtime(temp[1]);
        src[1] = temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3];

        //? 0d 09 0e 0b
        temp[1] = temp[0];
        temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 2];
        temp[1] = xtime(temp[1]);
        temp[1] ^= state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; 
        temp[1] = xtime(temp[1]);
        src[2] = temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 3];

        //? 0b 0d 09 0e
        temp[1] = temp[0];
        temp[1] ^= state[4 * cnt_i + 1] ^ state[4 * cnt_i + 3];
        temp[1] = xtime(temp[1]);
        temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 3]; 
        temp[1] = xtime(temp[1]);
        src[3] = temp[1] ^= state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2];

        for (int cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            state[4 * cnt_i + cnt_j] = src[cnt_j];
        }
    }
    free(temp);
    free(src);
}
void Swap(unsigned int *src1, unsigned int *src2)
{ // AES_set_decrypt_key를 위한 Swap 함수
    int temp;
    temp = *src1;
    *src1 = *src2;
    *src2 = temp;
}
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{ //AES_encrypt_key 함수에서 생성하는 keyschedule과 반대로 값을 대입해주면 된다.
    int cnt_i;
    for (cnt_i = 0; cnt_i < (Nb * (AES_MAXNR + 1)) / 8; cnt_i++)
    { //한쌍씩 Swap 해주고 한쌍당 4개의 배열이므로 (Nb * (AES_MAXNR + 1)) / 8 번 해주면 된다.
        Swap(&(key->rd_key[4 * cnt_i]), &(key->rd_key[(Nb * (AES_MAXNR + 1)) - (4 * (cnt_i + 1))]));
        Swap(&(key->rd_key[4 * cnt_i + 1]), &(key->rd_key[(Nb * (AES_MAXNR + 1)) - (4 * (cnt_i + 1)) + 1]));
        Swap(&(key->rd_key[4 * cnt_i + 2]), &(key->rd_key[(Nb * (AES_MAXNR + 1)) - (4 * (cnt_i + 1)) + 2]));
        Swap(&(key->rd_key[4 * cnt_i + 3]), &(key->rd_key[(Nb * (AES_MAXNR + 1)) - (4 * (cnt_i + 1)) + 3]));
    }

    if (bits == 128) // bit 수에 따라서 각 Round 횟수  반환
        return 10;
    if (bits == 192)
        return 12;
    if (bits == 256)
        key->rounds = 14;
        return 14;
    printf("\nERROR\n");
    return -1;
}
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    unsigned char state[4 * Nb];
    int cnt_i;
    int round = 0;

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        state[cnt_i] = in[cnt_i];
    }
    AddRoundKey(state, key, &round);
    for (cnt_i = 1; cnt_i < AES_MAXNR; cnt_i++)
    {
        InvShiftRow(state);
        InvSubByte(state);
        AddRoundKey(state, key, &round);
        InvMixColumns(state);
    }
    InvShiftRow(state);
    InvSubByte(state);
    AddRoundKey(state, key, &round);

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}

int64_t cpucycles(void)
{
    return __rdtsc();
}

