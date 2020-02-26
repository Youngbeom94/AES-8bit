#include "AES.h"

AES_KEY KEY;
AES_KEY *key = &KEY;
// const unsigned char in[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x7, 0x34};
const unsigned char in[16] = {0x00};
const unsigned char userkey[16] = {0x00};
// const unsigned char userkey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
unsigned char out[16] = {0x00};
unsigned char deout[16] = {0x00};
const unsigned char *plaintxt;
const unsigned char *UserKey;

#if 1
int main()
{
    int cnt_i;
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
    key->rounds = AES_set_encrypt_key(userkey, AES_KEY_BIT, key);
    unsigned long long cycles1, cycles2;
    cycles1 = cpucycles();
    AES_encrypt(in, out, key);
    cycles2 = cpucycles();
    printf("\ncycle is %10lld\n",cycles2-cycles1);

    printf("\nEncrypt txt : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", out[cnt_i]);
    }
    //! Decrypt
    key->rounds = AES_set_decrypt_key(userkey, AES_KEY_BIT, key);
    AES_decrypt(out, deout, key);

    printf("\ndecrypt txt : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", deout[cnt_i]);
    }
    return 0;
}
#endif

//! 파일 입출력
#if 0
int main()
{
    int cnt_i, cnt_j = 0;
    FILE *ifp, *ofp;
    ifp = fopen("AES128(ECB)KAT.req", "r"); // Read할 파일 개방
    ofp = fopen("AES128(ECB)KAT_김영범.rsp", "w"); //Write할 파일 개방
    if (ifp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    if (ofp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    
    for (cnt_j = 0; cnt_j < 276 ; cnt_j++)
    {
        char c = 0x00; //fgetc함수를 받아주는 char 변수
        unsigned char testkey[16] = {0x00}; // userkey 값을 받아줄 배열
        unsigned char testpt[16] = {0x00};  // plaintxt 값을 받아줄 배열
        for (cnt_i = 0; cnt_i < 6; cnt_i++)
        {
            c = fgetc(ifp); // req 문서의 맨처음 KEY = 을 받아주는 함수
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        { //실질적 key들의 문자들을 숫자들로 바꾸어 주고 key배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z') //ASCII 값에 따라 저장
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testkey[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testkey[cnt_i / 2] += c;
        }
        c = fgetc(ifp); // 개행문자 \n 삭제

        for (cnt_i = 0; cnt_i < 6; cnt_i++)// PT = 을 받아주는 함수
        {
            c = fgetc(ifp);
        }

        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {// 실질적 PT의 문자들을 숫자들로 바꾸어 주고 pt배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z')
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testpt[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testpt[cnt_i / 2] += c;
        }
        c = fgetc(ifp);//개행문자 삭제
        c = fgetc(ifp);
        c = fgetc(ifp);
        c = fgetc(ifp);
    
        fprintf(ofp, "KEY = ");// 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testkey[cnt_i]);
        }
        fprintf(ofp, "\nPT = ");// 출력시킬 파일에 Write 해주는 함수 PT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testpt[cnt_i]);
        }

        // !Encrypt
        plaintxt = testpt;
        UserKey = testkey;
        key->rounds = AES_set_encrypt_key(UserKey, AES_KEY_BIT, key); 
        AES_encrypt(plaintxt, out, key);

        fprintf(ofp, "\nCT = ");// 출력시킬 파일에 Write 해주는 함수 CT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", out[cnt_i]);
        }
        fprintf(ofp, "\n\n");
    }
    fclose(ifp); //개방한 파일들 닫아주기
    fclose(ofp);
    return 0;
}
#endif

//! 성능 테스트
#if 0
int main()
{
    //? AES 암호화에 걸리는 시간 측정함수 
    clock_t start, end;
    double cpu_time_used;
    int cnt_i = 1; //* 암호화 횟수

    start = clock(); //* 시간 측정시작.
    while (cnt_i)
    {
        //! Encrypt
        key->rounds = AES_set_encrypt_key(userkey, AES_KEY_BIT, key);
        AES_encrypt(in, out, key);
        //! Decrypt
        // key->rounds = AES_set_decrypt_key(userkey, AES_KEY_BIT, key);
        // AES_decrypt(out, deout, key);

        cnt_i--;
    }
    end = clock(); //* 시간 측정완료.

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\nElapsed time with AES_Encrypt: %lf\n", cpu_time_used);

    //? AES 암호화 측정 with RDTSC
    unsigned long long cycles1, cycles2;
    cycles1 = cpucycles();
    key->rounds = AES_set_encrypt_key(userkey, AES_KEY_BIT, key);
    AES_encrypt(in, out, key);
    cycles2 = cpucycles();

    printf("\nElapsed time with AES_Encrypt by RDTSC: %010lld\n", cycles2 - cycles1);

    return 0;
}
#endif