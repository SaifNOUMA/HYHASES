
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>

#define J 10000


int main(int argc, char *argv[])
{
    size_t          ret = 0, siglen;
    size_t          mlen = atoi(argv[1]);
    unsigned long long smlen;
    uint8_t         m[mlen], sm[10000], sk[32];
    clock_t         t0, t1;
    double          sign_time = 0, ver_time = 0;

    for (int i = 0 ; i < mlen ; i++) {
        m[i] = i;
    }
    for (int i = 0 ; i < 32 ; i++) {
        sk[i] = i;
    }

    for (int i = 0 ; i < J ; i++) {
        t0 = clock();
        if (crypto_sign(sm, &smlen, (const unsigned char*) m, mlen, sk) != 0) {
            printf("crypto_sign() failure\n");
        }
        t1 = clock();

        sign_time += t1-t0;

    }

    printf("[smlen=%lu]\n", smlen);

    printf("DEBUG: avg sig-gen  = %.2f us\n", sign_time / J);


    return 0;
}
