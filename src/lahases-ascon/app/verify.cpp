#include "util.h"
#include "conf.h"
#include "App.h"
#include "Enclave_u.h"
#include <ctime>


int ver_sig(size_t enclave_id,
            uint8_t* sig, size_t siglen,
            uint8_t* msg, size_t msglen,
            EC_GROUP* ec_group, EC_POINT* Y,
            size_t counter, int* result)
{
    uint8_t       R_ptr[256], x[256];
    size_t        Rlen, xlen, ex_hash_len;
    uint8_t       ex_hash[100000], e_ptr[HASH_SIZE];
    BN_CTX        *bn_ctx;
    BIGNUM        *e, *s;
    EC_POINT      *R_pt, *R;
    *result = -1;

    if (0 != request_keys(enclave_id,
                          R_ptr, &Rlen,
                          x, &xlen,
                          counter))                                                            { return 0; }
    bn_ctx        = BN_CTX_new();
    e             = BN_new();
    s             = BN_new();
    R_pt          = EC_POINT_new(ec_group);
    R             = EC_POINT_new(ec_group);
    if (bn_ctx == NULL || e == NULL || R_ptr == NULL)                                          { return 0; }

    if (0 == concat_str_str(msg, msglen, x, xlen, ex_hash, &ex_hash_len))                      { return 0; }
    if (0 == sha256_i(ex_hash, ex_hash_len, e_ptr, counter))                                   { return 0; }    /* e = H(msg || x || j) */
    e = BN_bin2bn(e_ptr, HASH_SIZE, 0);
    s = BN_bin2bn(sig, siglen, 0);

    if (0 == EC_POINT_mul(ec_group, R_pt, s, Y, e, bn_ctx))                                    { return 0; }    /* R' = s . G + e . Y */
    if (0 == EC_POINT_oct2point(ec_group, R, R_ptr, Rlen, NULL))                               { return 0; }    /* bin2point(R) */
    *result = EC_POINT_cmp(ec_group, R, R_pt, bn_ctx);                                                          /* res = cmp(R, R) */


    return 1;
}


int ver_batch_msg(size_t enclave_id,
                  uint8_t* sig, size_t siglen,
                  uint8_t* msg[], size_t msglen, size_t num_msg,
                  EC_GROUP* ec_group, EC_POINT* Y,
                  size_t counter, int* res, double *req_t)
{
    uint8_t       R_ptr[256], x[256], xj[HASH_SIZE];
    uint8_t       prior_hash[100000], e_ptr[HASH_SIZE];
    size_t        Rlen, xlen, prior_hash_len;
    BN_CTX        *bn_ctx;
    BIGNUM        *e, *el, *s, *order;
    EC_POINT      *R_pt, *R;
    clock_t       t0, t1;
    *res = -1;


    t0 = clock();
    if (0 != request_keys_batch(enclave_id,
                                R_ptr, &Rlen,
                                x, &xlen,
                                counter, num_msg))                                             { return 0; }
    t1 = clock();
    *req_t = t1 - t0;

    bn_ctx        = BN_CTX_new();
    el            = BN_new();
    e             = BN_new();
    s             = BN_new();
    R             = EC_POINT_new(ec_group);
    R_pt          = EC_POINT_new(ec_group);
    order         = (BIGNUM*) EC_GROUP_get0_order(ec_group);
    if (bn_ctx == NULL || e == NULL || order == NULL || R_ptr == NULL)                         { return 0; }

    for (int i = 0 ; i < (int) num_msg ; i++) {
        if (0 == asconhashav12_i(x, xlen, xj, i))                                              { return 0; }    /* xj = H(x || j) */
        if (0 == concat_str_str(msg[i], msglen, xj, HASH_SIZE, 
                                   prior_hash, &prior_hash_len))                               { return 0; }
        if (0 == sha256_i(prior_hash, prior_hash_len, e_ptr, counter))                         { return 0; }    /* ej = H(msg || x || j) */

        if (i == 0) {
            e = BN_bin2bn(e_ptr, HASH_SIZE, 0);
            if (0 == BN_mod(e, e, order, bn_ctx))                                              { return 0; }    /* e = ej mod q */
        } else {
            el = BN_bin2bn(e_ptr, HASH_SIZE, 0);
            if (0 == BN_mod_add(e, e, el, order, bn_ctx))                                      { return 0; }    /* e = e + ej mod q */
        }
    }
    s = BN_bin2bn(sig, siglen, 0);
    if (0 == EC_POINT_mul(ec_group, R_pt, s, Y, e, bn_ctx))                                    { return 0; }    /* R' = s . G + e . Y */
    if (0 == EC_POINT_oct2point(ec_group, R, R_ptr, Rlen, NULL))                               { return 0; }    /* bin2point(R) */
    *res = EC_POINT_cmp(ec_group, R, R_pt, bn_ctx);                                                             /* res = cmp(R, R) */


    BN_free(e);
    BN_free(el);
    BN_free(s);
    EC_POINT_free(R);
    EC_POINT_free(R_pt);

    return 1;
}
