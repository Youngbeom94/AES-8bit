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

void MakeMakedValue(unsigned char *masked_sbox, unsigned char *M)
{
    int cnt_i = 0;
    unsigned char temp[2] = {0x00}; // 행렬곱셈에 이용할 값들 저장시키는 변수
    unsigned char src[4] = {0x00};  // 4개의 state 배열의 최종상태 저장시키는 변수
    for (cnt_i = 0; cnt_i < 256; cnt_i++)
    {
        masked_sbox[(cnt_i ^ M[0])] = (sbox[cnt_i] ^ M[1]);
    }
    //? 02 03 01 01
    temp[0] = M[2] ^ M[3]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = M[3] ^ M[4] ^ M[5]; // 1 에 해당하는 plaintxt
    src[0] = temp[0] ^ temp[1];   // 최종 src
    //? 01 02 03 01
    temp[0] = M[3] ^ M[4]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = M[2] ^ M[4] ^ M[5]; // 1 에 해당하는 plaintxt
    src[1] = temp[0] ^ temp[1];   // 최종 src
    //? 01 01 02 03
    temp[0] = M[4] ^ M[5]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = M[2] ^ M[3] ^ M[5]; // 1 에 해당하는 plaintxt
    src[2] = temp[0] ^ temp[1];   // 최종 src
    //? 03 01 01 02
    temp[0] = M[2] ^ M[5]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = M[2] ^ M[3] ^ M[4];
    src[3] = temp[0] ^ temp[1]; // 최종 src

    M[6] = src[0];
    M[7] = src[1];
    M[8] = src[2];
    M[9] = src[3];
}

void SubByte(unsigned char *state, unsigned char *masked_sbox)
{
    int cnt_i;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] = masked_sbox[state[cnt_i]]; //sbox를 이용해 치환하기
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
void MixColumns_Origin(unsigned char *state)
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
void MixColumns(unsigned char *state)
{
    unsigned char temp[2] = {0x00}; // 행렬곱셈에 이용할 값들 저장시키는 변수
    unsigned char src[16] = {0x00}; // 4개의 state 배열의 최종상태 저장시키는 변수
    //! 1열
    //? 02 03 01 01
    temp[0] = state[0] ^ state[5]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[5] ^ state[10] ^ state[15]; // 1 에 해당하는 plaintxt
    src[0] = temp[0] ^ temp[1];                 // 최종 src
    //? 01 02 03 01
    temp[0] = state[5] ^ state[10]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[0] ^ state[10] ^ state[15]; // 1 에 해당하는 plaintxt
    src[1] = temp[0] ^ temp[1];                 // 최종 src
    //? 01 01 02 03
    temp[0] = state[10] ^ state[15]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[0] ^ state[5] ^ state[15]; // 1 에 해당하는 plaintxt
    src[2] = temp[0] ^ temp[1];                // 최종 src
    //? 03 01 01 02
    temp[0] = state[0] ^ state[15]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[0] ^ state[5] ^ state[10];
    src[3] = temp[0] ^ temp[1]; // 최종 src

    //! 2열
    //? 02 03 01 01
    temp[0] = state[4] ^ state[9]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[9] ^ state[14] ^ state[3]; // 1 에 해당하는 plaintxt
    src[4] = temp[0] ^ temp[1];                // 최종 src
    //? 01 02 03 01
    temp[0] = state[9] ^ state[14]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[14] ^ state[3]; // 1 에 해당하는 plaintxt
    src[5] = temp[0] ^ temp[1];                // 최종 src
    //? 01 01 02 03
    temp[0] = state[14] ^ state[3]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[9] ^ state[3]; // 1 에 해당하는 plaintxt
    src[6] = temp[0] ^ temp[1];               // 최종 src
    //? 03 01 01 02
    temp[0] = state[4] ^ state[3]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[9] ^ state[14];
    src[7] = temp[0] ^ temp[1]; // 최종 src

    //! 3열
    //? 02 03 01 01
    temp[0] = state[8] ^ state[13]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[13] ^ state[2] ^ state[7]; // 1 에 해당하는 plaintxt
    src[8] = temp[0] ^ temp[1];                // 최종 src
    //? 01 02 03 01
    temp[0] = state[13] ^ state[2]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[2] ^ state[7]; // 1 에 해당하는 plaintxt
    src[9] = temp[0] ^ temp[1];               // 최종 src
    //? 01 01 02 03
    temp[0] = state[2] ^ state[7]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[13] ^ state[7]; // 1 에 해당하는 plaintxt
    src[10] = temp[0] ^ temp[1];               // 최종 src
    //? 03 01 01 02
    temp[0] = state[8] ^ state[7]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[13] ^ state[2];
    src[11] = temp[0] ^ temp[1]; // 최종 src

    //! 4열
    //? 02 03 01 01
    temp[0] = state[12] ^ state[1]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[1] ^ state[6] ^ state[11]; // 1 에 해당하는 plaintxt
    src[12] = temp[0] ^ temp[1];               // 최종 src
    //? 01 02 03 01
    temp[0] = state[1] ^ state[6]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[6] ^ state[11]; // 1 에 해당하는 plaintxt
    src[13] = temp[0] ^ temp[1];                // 최종 src
    //? 01 01 02 03
    temp[0] = state[6] ^ state[11]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[1] ^ state[11]; // 1 에 해당하는 plaintxt
    src[14] = temp[0] ^ temp[1];                // 최종 src
    //? 03 01 01 02
    temp[0] = state[12] ^ state[11]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[1] ^ state[6];
    src[15] = temp[0] ^ temp[1]; // 최종 src

    for (int cnt_j = 0; cnt_j < 16; cnt_j++) // 각각의 src값을 state에 대입해주기
    {
        state[cnt_j] = src[cnt_j];
    }
}

void KeySchedule(unsigned char *key, unsigned char *roundkey, unsigned char *M, unsigned char *masked_sbox)
{
    unsigned char temp[4] = {
        0x00,
    };
    int cnt_i, cnt_j, cnt_k = 0x00;

    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        roundkey[cnt_i * 4] = key[cnt_i * 4] ^ M[6] ^ M[0];
        roundkey[cnt_i * 4 + 1] = key[cnt_i * 4 + 1] ^ M[7] ^ M[0];
        roundkey[cnt_i * 4 + 2] = key[cnt_i * 4 + 2] ^ M[8] ^ M[0];
        roundkey[cnt_i * 4 + 3] = key[cnt_i * 4 + 3] ^ M[9] ^ M[0];
    }

    for (cnt_j = 0; cnt_j < 9; cnt_j++)
    {
        temp[0] = masked_sbox[roundkey[13 + (cnt_j * 16)] ^ M[7]] ^ Rcon[cnt_j] ^ M[1];
        temp[1] = masked_sbox[roundkey[14 + (cnt_j * 16)] ^ M[8]] ^ M[1];
        temp[2] = masked_sbox[roundkey[15 + (cnt_j * 16)] ^ M[9]] ^ M[1];
        temp[3] = masked_sbox[roundkey[12 + (cnt_j * 16)] ^ M[6]] ^ M[1];

        roundkey[16 + (cnt_j * 16)] = temp[0] ^ roundkey[0 + (cnt_j * 16)];
        roundkey[17 + (cnt_j * 16)] = temp[1] ^ roundkey[1 + (cnt_j * 16)];
        roundkey[18 + (cnt_j * 16)] = temp[2] ^ roundkey[2 + (cnt_j * 16)];
        roundkey[19 + (cnt_j * 16)] = temp[3] ^ roundkey[3 + (cnt_j * 16)];

        roundkey[20 + (cnt_j * 16)] = roundkey[16 + (cnt_j * 16)] ^ M[6] ^ M[0] ^ roundkey[20 + (cnt_j - 1) * 16];
        roundkey[21 + (cnt_j * 16)] = roundkey[17 + (cnt_j * 16)] ^ M[7] ^ M[0] ^ roundkey[21 + (cnt_j - 1) * 16];
        roundkey[22 + (cnt_j * 16)] = roundkey[18 + (cnt_j * 16)] ^ M[8] ^ M[0] ^ roundkey[22 + (cnt_j - 1) * 16];
        roundkey[23 + (cnt_j * 16)] = roundkey[19 + (cnt_j * 16)] ^ M[9] ^ M[0] ^ roundkey[23 + (cnt_j - 1) * 16];

        roundkey[24 + (cnt_j * 16)] = roundkey[20 + (cnt_j * 16)] ^ M[6] ^ M[0] ^ roundkey[24 + (cnt_j - 1) * 16];
        roundkey[25 + (cnt_j * 16)] = roundkey[21 + (cnt_j * 16)] ^ M[7] ^ M[0] ^ roundkey[25 + (cnt_j - 1) * 16];
        roundkey[26 + (cnt_j * 16)] = roundkey[22 + (cnt_j * 16)] ^ M[8] ^ M[0] ^ roundkey[26 + (cnt_j - 1) * 16];
        roundkey[27 + (cnt_j * 16)] = roundkey[23 + (cnt_j * 16)] ^ M[9] ^ M[0] ^ roundkey[27 + (cnt_j - 1) * 16];

        roundkey[28 + (cnt_j * 16)] = roundkey[24 + (cnt_j * 16)] ^ M[0] ^ roundkey[12 + (cnt_j * 16)] ^ M[6];
        roundkey[29 + (cnt_j * 16)] = roundkey[25 + (cnt_j * 16)] ^ M[0] ^ roundkey[13 + (cnt_j * 16)] ^ M[7];
        roundkey[30 + (cnt_j * 16)] = roundkey[26 + (cnt_j * 16)] ^ M[0] ^ roundkey[14 + (cnt_j * 16)] ^ M[8];
        roundkey[31 + (cnt_j * 16)] = roundkey[27 + (cnt_j * 16)] ^ M[0] ^ roundkey[15 + (cnt_j * 16)] ^ M[9];
    }

    temp[0] = masked_sbox[roundkey[13 + (cnt_j * 16)] ^ M[7]] ^ Rcon[cnt_j];
    temp[1] = masked_sbox[roundkey[14 + (cnt_j * 16)] ^ M[8]];
    temp[2] = masked_sbox[roundkey[15 + (cnt_j * 16)] ^ M[9]];
    temp[3] = masked_sbox[roundkey[12 + (cnt_j * 16)] ^ M[6]];

    roundkey[16 + (cnt_j * 16)] = temp[0] ^ roundkey[0 + (cnt_j * 16)];
    roundkey[17 + (cnt_j * 16)] = temp[1] ^ roundkey[1 + (cnt_j * 16)];
    roundkey[18 + (cnt_j * 16)] = temp[2] ^ roundkey[2 + (cnt_j * 16)];
    roundkey[19 + (cnt_j * 16)] = temp[3] ^ roundkey[3 + (cnt_j * 16)];

    roundkey[20 + (cnt_j * 16)] = roundkey[16 + (cnt_j * 16)] ^ roundkey[20 + (cnt_j - 1) * 16];
    roundkey[21 + (cnt_j * 16)] = roundkey[17 + (cnt_j * 16)] ^ roundkey[21 + (cnt_j - 1) * 16];
    roundkey[22 + (cnt_j * 16)] = roundkey[18 + (cnt_j * 16)] ^ roundkey[22 + (cnt_j - 1) * 16];
    roundkey[23 + (cnt_j * 16)] = roundkey[19 + (cnt_j * 16)] ^ roundkey[23 + (cnt_j - 1) * 16];

    roundkey[24 + (cnt_j * 16)] = roundkey[20 + (cnt_j * 16)] ^ roundkey[24 + (cnt_j - 1) * 16] ^ M[6];
    roundkey[25 + (cnt_j * 16)] = roundkey[21 + (cnt_j * 16)] ^ roundkey[25 + (cnt_j - 1) * 16] ^ M[7];
    roundkey[26 + (cnt_j * 16)] = roundkey[22 + (cnt_j * 16)] ^ roundkey[26 + (cnt_j - 1) * 16] ^ M[8];
    roundkey[27 + (cnt_j * 16)] = roundkey[23 + (cnt_j * 16)] ^ roundkey[27 + (cnt_j - 1) * 16] ^ M[9];

    roundkey[28 + (cnt_j * 16)] = roundkey[24 + (cnt_j * 16)] ^ roundkey[12 + (cnt_j * 16)] ^ M[6];
    roundkey[29 + (cnt_j * 16)] = roundkey[25 + (cnt_j * 16)] ^ roundkey[13 + (cnt_j * 16)] ^ M[7];
    roundkey[30 + (cnt_j * 16)] = roundkey[26 + (cnt_j * 16)] ^ roundkey[14 + (cnt_j * 16)] ^ M[8];
    roundkey[31 + (cnt_j * 16)] = roundkey[27 + (cnt_j * 16)] ^ roundkey[15 + (cnt_j * 16)] ^ M[9];

    roundkey[16 + (cnt_j * 16)] ^= M[0] ^ M[6];
    roundkey[17 + (cnt_j * 16)] ^= M[0] ^ M[7];
    roundkey[18 + (cnt_j * 16)] ^= M[0] ^ M[8];
    roundkey[19 + (cnt_j * 16)] ^= M[0] ^ M[9];
    roundkey[24 + (cnt_j * 16)] ^= M[0];
    roundkey[25 + (cnt_j * 16)] ^= M[0];
    roundkey[26 + (cnt_j * 16)] ^= M[0];
    roundkey[27 + (cnt_j * 16)] ^= M[0];
}

void AddRoundKey(unsigned char *state, unsigned char *roundkey, int *round)
{
    int cnt_i, cnt_j = 0;
    int temp;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] ^= roundkey[((*round) * 16) + cnt_i];
    }

    *round += 1;
}

void AES_encrypt(const unsigned char *in, unsigned char *out, unsigned char *roundkey, unsigned char *M, unsigned char *masked_sbox)
{
    unsigned char state[4 * Nb];
    unsigned char masked[4 * Nb];
    int cnt_i, cnt_j;
    int round = 0;

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        state[cnt_i] = in[cnt_i];
    }

    Masked_M1_M4_2nd(state, M);
    AddRoundKey(state, roundkey, &round);


    for (cnt_i = 1; cnt_i < AES_MAXNR; cnt_i++)
    {
        SubByte(state, masked_sbox);
        ShiftRow(state);

        Masked_M1_M4(state, M);
        Masked_M_2nd(state, M);
        MixColumns_Origin(state);
        AddRoundKey(state, roundkey, &round);
    }
    SubByte(state, masked_sbox);
    ShiftRow(state);
    AddRoundKey(state, roundkey, &round);

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}

void AES_encrypt_Random(const unsigned char *in, unsigned char *out, unsigned char *roundkey, unsigned char *M, unsigned char *masked_sbox)
{
    unsigned char state[4 * Nb];
    unsigned char masked[4 * Nb];
    int cnt_i, cnt_j;
    int round = 0;

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        state[cnt_i] = in[cnt_i];
    }

    //! 1라운드
    Masked_M1_M4_2nd(state, M);
    AddRoundKey(state, roundkey, &round);
    Masked_M(state, M);
    SubByte(state, masked_sbox);
    Masked_M_2nd(state, M);
    Masked_M1_M4(state, M);
    MixColumns(state);
    Masked_M1_M4_2nd(state, M);
    ShiftRow(state);

    for (cnt_i = 1; cnt_i < 8; cnt_i++)
    {
        AddRoundKey(state, roundkey, &round);
        Masked_M(state, M);
        SubByte(state, masked_sbox);
        Masked_M_2nd(state, M);

        Masked_M1_M4(state, M);
        MixColumns_Origin(state);
        Masked_M1_M4_2nd(state, M);

        ShiftRow(state);
    }
    //!9라운드
    AddRoundKey(state, roundkey, &round);
    Masked_M(state, M);
    SubByte(state, masked_sbox);
    Masked_M_2nd(state, M);

    ShiftRow(state);
    Masked_M1_M4(state, M);
    MixColumns(state);
    Masked_M1_M4_2nd(state, M);

    //!10라운드
    AddRoundKey(state, roundkey, &round);
    Masked_M(state, M);
    SubByte(state, masked_sbox);
    Masked_M_2nd(state, M);
    AddRoundKey(state, roundkey, &round);
    InvShiftRow(state);


    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}
void Masked_M(unsigned char *state, unsigned char *M)
{
    int cnt_i = 0;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] ^= M[0];
    }
}
void Masked_M_2nd(unsigned char *state, unsigned char *M)
{
    int cnt_i = 0;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state[cnt_i] ^= M[1];
    }
}
void Masked_M1_M4(unsigned char *state, unsigned char *M)
{
    int cnt_i = 0;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        state[4 * cnt_i] ^= M[2];
        state[4 * cnt_i + 1] ^= M[3];
        state[4 * cnt_i + 2] ^= M[4];
        state[4 * cnt_i + 3] ^= M[5];
    }
}
void Masked_M1_M4_2nd(unsigned char *state, unsigned char *M)
{
    int cnt_i = 0;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        state[4 * cnt_i] ^= M[6];
        state[4 * cnt_i + 1] ^= M[7];
        state[4 * cnt_i + 2] ^= M[8];
        state[4 * cnt_i + 3] ^= M[9];
    }
}

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