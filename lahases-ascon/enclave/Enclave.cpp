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
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "Enclave.h"
#include "Enclave_t.h"
#include "tSgxSSL_api.h"
#include "asconhashav12/hash.c"
#include "asconprfav12/prf.c"

#define ADD_ENTROPY_SIZE	32


int sha256_i(uint8_t* message, size_t messagelen,
             uint8_t* hash, int counter)
{
    uint8_t prior_hash[messagelen + sizeof(counter)];

    memcpy(prior_hash, message, messagelen);
    memcpy(prior_hash + messagelen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(prior_hash, sizeof(prior_hash), hash))                                   { return 0; }

    return 1;
}

int asconhashav12_i(uint8_t* message, size_t messagelen,
                    uint8_t* hash, int counter)
{
    uint8_t prior_hash[messagelen + sizeof(counter)];

    memcpy(prior_hash, message, messagelen);
    memcpy(prior_hash + messagelen, (uint8_t*) &counter, sizeof(counter));

    if (0 != crypto_hash(hash, prior_hash, sizeof(prior_hash)))                                 { return 0; }

    return 1;
}

int concat_str_int(uint8_t* message, size_t messagelen,
                   size_t integer,
                   uint8_t* res, size_t *reslen)
{
    *reslen = messagelen + sizeof(integer);

    memcpy(res, message, messagelen);
    memcpy(res + messagelen, (uint8_t*) &integer, sizeof(integer));

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


int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
	char buf[BUFSIZ] = {'\0'};

	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
	if (res >=0) {
		sgx_status_t sgx_ret = ocall_uprint((const char *) buf);
		TEST_CHECK(sgx_ret);
	}
	return res;
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

    memcpy(msk, key, keylen);
    msklen = keylen;

    // compute signer private key
    if (NULL == asconhashav12_i(msk, msklen, y, signer_id))                                         { return; }
}


/**
 * Function Name: send_dp
 *
 * Description:
 * Send the EC domain parameters
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void send_dp(uint8_t* p, size_t plen,
             uint8_t* a, size_t alen,
             uint8_t* b, size_t blen,
             uint8_t* gx, size_t gxlen,
             uint8_t* gy, size_t gylen,
             uint8_t* order, size_t orderlen,
             uint8_t* cofactor, size_t cofactorlen)
{
    BIGNUM      *p_nb, *a_nb, *b_nb, *cofactor_bn, *gx_bn, *gy_bn;
    EC_POINT    *generator;

    p_nb            = BN_bin2bn(p, plen, NULL);
    a_nb            = BN_bin2bn(a, alen, NULL);
    b_nb            = BN_bin2bn(b, blen, NULL);
    gx_bn           = BN_bin2bn(gx, gxlen, NULL);
    gy_bn           = BN_bin2bn(gy, gylen, NULL);
    order_bn        = BN_bin2bn(order, orderlen, NULL);
    cofactor_bn     = BN_bin2bn(cofactor, cofactorlen, NULL);

    if (p_nb == NULL || a_nb == NULL || b_nb == NULL || cofactor_bn == NULL)                        { return; }
    
    ec_group = EC_GROUP_new_curve_GFp(p_nb, a_nb, b_nb, NULL);
    if (ec_group == NULL)                                                                           { return; }

    generator = EC_POINT_new(ec_group);
    if (generator == NULL)                                                                          { return; }
    if (0 == EC_POINT_set_affine_coordinates(ec_group, generator, gx_bn, gy_bn, NULL))              { return; }
    if (0 == EC_GROUP_set_generator(ec_group, generator, order_bn, cofactor_bn))                    { return; }

}


/**
 * Function Name: request_keys
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_keys(uint8_t R[256], size_t* Rlen,
                  uint8_t x[256], size_t* xlen,
                  size_t counter)
{
    uint8_t     prior_x[64], r[32], *R_tmp;
    size_t      prior_x_len;
    BIGNUM      *r_bn; 
    EC_POINT    *R_point;

    r_bn    = BN_new();
    R_point = EC_POINT_new(ec_group);

    if (NULL == concat_str_int(y, sizeof(y), counter, prior_x, &prior_x_len))                       { return; }
    if (NULL == sha256_i(prior_x, prior_x_len, x, 0))                                               { return; }
    if (NULL == sha256_i(prior_x, prior_x_len, r, 1))                                               { return; }
    if (NULL == (r_bn = BN_bin2bn(r, HASH_SIZE, 0)))                                                { return; }

    if (0 == EC_POINT_mul(ec_group, R_point, r_bn, NULL, NULL, NULL))                               { return; }
    *Rlen = EC_POINT_point2buf(ec_group, R_point, POINT_CONVERSION_UNCOMPRESSED, &R_tmp, NULL);
    if (Rlen == 0)                                                                                  { return; }
    memcpy(R, R_tmp, *Rlen);
    *xlen = HASH_SIZE;
}


/**
 * Function Name: request_keys_batch
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_keys_batch(uint8_t R[256], size_t* Rlen,
                        uint8_t x[256], size_t* xlen,
                        size_t counter, size_t num_msg)
{
    BN_CTX      *bn_ctx;
    EC_POINT    *R_point;
    BIGNUM      *r_bn, *rl_bn; 
    uint8_t     ex_x[64], r[32], *R_tmp, rj[HASH_SIZE];
    size_t      ex_x_len;


    r_bn    = BN_new();
    rl_bn   = BN_new();
    bn_ctx  = BN_CTX_new();
    R_point = EC_POINT_new(ec_group);
    if (NULL == concat_str_int(y, sizeof(y), counter, ex_x, &ex_x_len))                       { return; }       
    if (NULL == asconhashav12_i(ex_x, ex_x_len, x, 0))                                        { return; }       /* x = H(y || j || 0) */
    if (NULL == asconhashav12_i(ex_x, ex_x_len, r, 1))                                        { return; }       /* r = H(y || j || 1) */

    for (int i = 0 ; i < (int) num_msg ; i++) {
        if (NULL == asconhashav12_i(r, HASH_SIZE, rj, i))                                     { return; }       /* x = H(y || 0) */
        if (i == 0) {
            r_bn = BN_bin2bn(rj, HASH_SIZE, 0);
        } else {
            rl_bn = BN_bin2bn(rj, HASH_SIZE, 0);
            if (rl_bn == NULL)                                                                { return; }
            if (0 == BN_mod_add(r_bn, r_bn, rl_bn, order_bn, bn_ctx))                         { return; }       /* r = r + r' mod q */
        }
    }
            
    if (0 == EC_POINT_mul(ec_group, R_point, r_bn, NULL, NULL, NULL))                         { return; }       /* R = r . G */
    *Rlen = EC_POINT_point2buf(ec_group, R_point, POINT_CONVERSION_UNCOMPRESSED, &R_tmp, NULL);
    if (Rlen == 0)                                                                            { return; }
    memcpy(R, R_tmp, *Rlen);
    *xlen = HASH_SIZE;


    free(R_tmp);
    BN_free(r_bn);
    BN_free(rl_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(R_point);
}
