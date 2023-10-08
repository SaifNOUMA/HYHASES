#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include "asconhashav12/crypto_hash.h"

int encodeBN(BIGNUM* bn, uint8_t** p, size_t* plen);

int sha256_i(uint8_t* msg, size_t msglen,
             uint8_t* hash, int counter);

int asconhashav12_i(uint8_t* msg, size_t msglen,
                    uint8_t* hash, int counter);

int concat_str_int(uint8_t* msg, size_t msglen,
                   size_t integer,
                   uint8_t* res, size_t *reslen);

int concat_str_str(uint8_t* msg1, size_t msglen1,
                   uint8_t* msg2, size_t msglen2,
                   uint8_t* res, size_t *reslen);

unsigned long long cpucycles(void);

unsigned long long average(unsigned long long *t, size_t tlen);

void print_results(unsigned long long *t, size_t tlen);
