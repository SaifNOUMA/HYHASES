#include <iostream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <time.h>

#define CRYPTO_RSA_KEY_LEN_4096 4096
#define CRYPTO_RSA_KEY_LEN_2048 2048
#define CRYPTO_RSA_KEY_LEN_1024 1024
#define CRYPTO_RSA_KEY_EXP      65535


int main ()
{
  



    uint8_t     ptext[1000], ctext[1000];
    RSA         *rsa_key;
    int         plen;
    int         clen;
    int         num, status;
    clock_t     t0, t1;
    double      sgntime;
    uint8_t     ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";


    if (NULL == (rsa_key = RSA_new()))                                                  { return 1; }

    rsa_key = RSA_generate_key(2048, CRYPTO_RSA_KEY_EXP, NULL, NULL);
    if (RSA_check_key(rsa_key) != 1){
      return 1;
    }

    plen = sizeof(ptext) - 1;

    sgntime =
    for (int i = 0 ; i < 1000 ; i++) {
      t0 = clock();
      num = RSA_public_encrypt(RSA_size(rsa_key), ptext_ex, ctext, rsa_key, RSA_PKCS1_PADDING);
      t1 = clock();
      sgntime += t1-t0;
    }

    printf("DEBUG: avg sgn time = %2.f us\n", sgntime / (1000));
    std::cout << "DEBUG: " << plen << "  " << num << std::endl;

    for (int i = 0 ; i < 1000 ; i++) {
      t0 = clock();
      num = RSA_private_decrypt(RSA_size(rsa_key), ctext, ptext, rsa_key, RSA_PKCS1_PADDING);
      t1 = clock();
      sgntime += t1-t0;
    }

    printf("DEBUG: avg ver time = %2.f us\n", sgntime / (1000));
    std::cout << "DEBUG: " << plen << "  " << num << std::endl;


    printf("INFO: program terminated with success.\n");

    return 0;
}
