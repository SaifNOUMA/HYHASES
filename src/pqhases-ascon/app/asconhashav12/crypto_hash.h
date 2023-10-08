#ifndef CRYPTO_HASH
#define CRYPTO_HASH

#include "api.h"
#include "ascon.h"
#include "crypto_hash.h"
#include "permutations.h"
#include "printstate.h"

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);

#endif
