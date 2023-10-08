/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <math.h>
#include "Enclave.h"
#include "Enclave_t.h"
#include "tSgxSSL_api.h"
#include "asconhashav12/hash.c"


int sha256_i(uint8_t* msg, size_t msglen,
             uint8_t* hash, int counter)
{
    uint8_t ex_hash[msglen + sizeof(counter)];

    memcpy(ex_hash, msg, msglen);
    memcpy(ex_hash + msglen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(ex_hash, sizeof(ex_hash), hash))                                                     { return 0; }

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


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_uprint(buf);
}



/**
 * Function Name: send_msk
 *
 * Description:
 * Send authority master key
 * @param key: the master key
 * @param keylen: length of master key
 *
 * @return NULL
 */
void send_msk(unsigned char* key, size_t keylen, int signer_id)
{
    uint8_t sk[HASH_SIZE], prior_hash[1000];
    size_t  prior_hash_len = 0, current_counter = 0;

    memcpy(msk, key, keylen);
    msklen = keylen;

    memcpy(prior_hash, msk, msklen);
    memcpy(prior_hash + msklen, (uint8_t*) &signer_id, sizeof(signer_id));
    if (NULL == asconhashav12_i(prior_hash, msklen + sizeof(signer_id), precomputed_seeds, 0))              { return; }
    
}


/**
 * Function Name: request_keys
 *
 * Description:
 * Get the public key from the enclave
 * @param pk: public key
 * @param pk_len: public key length
 * @param signer_id: signer identity
 * @param counter: the current counter
 *
 * @return NULL
 */
void request_keys(uint8_t pk[T * HASH_SIZE], size_t* pk_len,
                  int signer_id, int counter)
{
    uint8_t sk_j[HASH_SIZE], ex_hash[msklen + sizeof(signer_id)];
    uint8_t seed[HASH_SIZE], seed_tmp[HASH_SIZE];
    *pk_len = T * HASH_SIZE;

    memcpy(seed, precomputed_seeds, HASH_SIZE);
    for (int i = 0 ;  i < counter; i++) {
        sha256_i(seed, HASH_SIZE, seed, 2);
    }
    for (int i = counter ;  i < J; i++) {                                                                                     /* sk_j = H^j (sk_0) */
        sha256_i(seed_tmp, HASH_SIZE, seed_tmp, 2);
    }

    // Compute pk_i^j
    memcpy(ex_hash, seed, HASH_SIZE);
    for (int i = 0 ; i < T ; i++) {
        memcpy(ex_hash + HASH_SIZE, (uint8_t*) &i, sizeof(i));
        if (NULL == asconhashav12_i(ex_hash, HASH_SIZE + sizeof(i), sk_j, 1))                               { return; }
        if (NULL == sha256_i(sk_j, HASH_SIZE, pk + i * HASH_SIZE, 0))                                       { return; }
    }
}
