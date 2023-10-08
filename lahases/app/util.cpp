#include "util.h"


int encodeBN(BIGNUM* bn, uint8_t** p, size_t* plen)
{
    *plen = BN_num_bytes(bn);
    *p = new uint8_t[*plen];

    BN_bn2bin(bn, *p);

    return 1;
}

int sha256_i(uint8_t* msg, size_t msglen,
             uint8_t* hash, int counter)
{
    uint8_t ex_hash[msglen + sizeof(counter)];

    memcpy(ex_hash, msg, msglen);
    memcpy(ex_hash + msglen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(ex_hash, sizeof(ex_hash), hash))                                 { return 0; }

    return 1;
}

int concat_str_int(uint8_t* msg, size_t msglen,
                   size_t integer,
                   uint8_t* res, size_t *reslen)
{
    *reslen = msglen + sizeof(integer);
    memcpy(res, msg, msglen);
    memcpy(res + msglen, (uint8_t*) &integer, sizeof(integer));

    return 1;
}

int concat_str_str(uint8_t* msg1, size_t msglen1,
                   uint8_t* msg2, size_t msglen2,
                   uint8_t* res, size_t *reslen)
{
    *reslen = msglen1 + msglen2;
    memcpy(res, msg1, msglen1);
    memcpy(res + msglen1, msg2, msglen2);

    return 1;
}

unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

void print_results(unsigned long long *t, size_t tlen)
{
  printf("\taverage       : %llu cycles\n", average(t, tlen));
  printf("\n");
}
