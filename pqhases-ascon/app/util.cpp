#include "util.h"
#include "asconhashav12/hash.c"

int sha256_i(uint8_t* msg, size_t msglen,
             uint8_t* hash, int counter)
{
    uint8_t ex_hash[msglen + sizeof(counter)];

    memcpy(ex_hash, msg, msglen);
    memcpy(ex_hash + msglen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(ex_hash, sizeof(ex_hash), hash))                                   { return 0; }

    return 1;
}


int asconhashav12_i(uint8_t* msg, size_t msglen,
                    uint8_t* hash, int counter)
{
    uint8_t prior_hash[msglen + sizeof(counter)];

    memcpy(prior_hash, msg, msglen);
    memcpy(prior_hash + msglen, (uint8_t*) &counter, sizeof(counter));

    if (0 != crypto_hash(hash, prior_hash, sizeof(prior_hash)))                           { return 0; }

    return 1;
}


unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

unsigned long long average(unsigned long *t, size_t tlen)
{
    unsigned long long acc=0;
    unsigned long long i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

void print_results(unsigned long *t, size_t tlen)
{
  printf("\taverage       : %llu cycles\n", average(t, tlen));
  printf("\n");
}
