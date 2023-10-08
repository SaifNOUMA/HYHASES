#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <bitset>
#include <iostream>
#include <openssl/sha.h>


int sha256_i(uint8_t* message, size_t messagelen, uint8_t* hash, int counter);

unsigned long long cpucycles(void);

unsigned long long average(unsigned long *t, size_t tlen);

void print_results(unsigned long *t, size_t tlen);
