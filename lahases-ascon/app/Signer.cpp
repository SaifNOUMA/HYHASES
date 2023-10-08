
#include "Signer.h"


Signer::Signer(int id)
{
    this->ID        = id;
    this->y         = BN_new();
    this->counter   = 0;
}

Signer::~Signer()
{
}


/**
 * Function Name: setSignerKeys
 *
 * Description:
 * Set the signer's private/public keys
 * @param ec_group: EC group that hold EC domain parameters
 * @param ec_key: The private/public EC keys for the signer.
 *
 * @return 1 on success, 0 on failure
 */
int Signer::setSignerKeys(EC_GROUP* ec_group, EC_KEY* y_key)
{
    this->ec_group  = ec_group;

    this->y         = (BIGNUM*) EC_KEY_get0_private_key(y_key);

    this->Y         = EC_POINT_new(this->ec_group);
    this->Y         = (EC_POINT*) EC_KEY_get0_public_key(y_key);
    this->counter   = 0;

    return 1;
}

/**
 * Function Name: sign_message
 *
 * Description:
 * Sign the given message using ETA scheme
 * @param message: message to sign
 * @param messagelen: length of the message
 *
 * @return 1 on success, 0 on failure
 */
int Signer::sign_message(uint8_t* message, size_t messagelen,
                         uint8_t** sig, size_t* siglen,
                         size_t* counter)
{   
    uint8_t         *y_ptr, r_ptr[HASH_SIZE], x_ptr[HASH_SIZE], 
                    prior_x[64], prior_hash[100000], e_ptr[HASH_SIZE];
    size_t          ylen, prior_x_len, prior_hash_len;
    BIGNUM          *order, *x_bn, *e_bn, *s_bn, *r_bn;
    BN_CTX*         ctx;

    ctx     = BN_CTX_new();
    x_bn    = BN_new();
    e_bn    = BN_new();
    r_bn    = BN_new();
    s_bn    = BN_new();
    order   = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);

    if (0 == encodeBN(this->y, &y_ptr, &ylen))                                                  { return 0; }
    if (0 == concat_str_int(y_ptr, ylen, this->counter, prior_x, &prior_x_len))                 { return 0; }
    if (0 == asconhashav12_i(prior_x, prior_x_len, x_ptr, 0))                                   { return 0; }   /* x = H(y || j || 0) */
    if (0 == asconhashav12_i(prior_x, prior_x_len, r_ptr, 1))                                   { return 0; }   /* x = H(y || j || 1) */
    if (0 == concat_str_str(message, messagelen,
                            x_ptr, sizeof(x_ptr),
                            prior_hash, &prior_hash_len))                                       { return 0; }
    if (0 == sha256_i(prior_hash, prior_hash_len, e_ptr, this->counter))                        { return 0; }   /* e = H(msg || x || j) */
    
    if (NULL == (e_bn = BN_bin2bn(e_ptr, HASH_SIZE, 0)))                                        { return 0; }
    if (NULL == (r_bn = BN_bin2bn(r_ptr, HASH_SIZE, 0)))                                        { return 0; }

    if (0 == BN_mul(x_bn, e_bn, this->y, ctx))                                                  { return 0; }   /* s' = e . y */
    if (0 == BN_mod_sub(s_bn, r_bn, x_bn, order, ctx))                                          { return 0; }   /* s = r - e * y */
    if (0 == encodeBN(s_bn, sig, siglen))                                                       { return 0; }
    *counter = this->counter;
    this->counter ++;


    return 1;
}


/**
 * Function Name: sign_batch_messages
 *
 * Description:
 * Sign the given batch of messages using HYHASE signature scheme
 * @param message: message to sign
 * @param messagelen: message length
 *
 * @return 1 on success, 0 on failure
 */
int Signer::sign_batch_msg(uint8_t* msg[], size_t msglen, size_t msgnum,
                           uint8_t** sig, size_t* siglen,
                           size_t* counter)
{   
    uint8_t         *y_ptr, r_ptr[HASH_SIZE], x_ptr[HASH_SIZE], xj_ptr[HASH_SIZE], rj_ptr[HASH_SIZE],
                    prior_x[64], ex_hash[100000], e_ptr[HASH_SIZE];
    size_t          ylen, prior_x_len, ex_hash_len;
    BIGNUM          *order, *x_bn, *e_bn, *s_bn, *sl_bn, *r_bn;
    BN_CTX*         bn_ctx;

    bn_ctx      = BN_CTX_new();
    x_bn        = BN_new();
    e_bn        = BN_new();
    r_bn        = BN_new();
    s_bn        = BN_new();
    sl_bn       = BN_new();
    order       = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);

    if (0 == encodeBN(this->y, &y_ptr, &ylen))                                                  { return 0; }   /* y_ptr = bn2bin(y) */
    if (0 == concat_str_int(y_ptr, ylen, this->counter, prior_x, &prior_x_len))                 { return 0; }
    if (0 == asconhashav12_i(prior_x, prior_x_len, x_ptr, 0))                                   { return 0; }   /* x = H(y || 0) */
    if (0 == asconhashav12_i(prior_x, prior_x_len, r_ptr, 1))                                   { return 0; }   /* r = H(y || 1) */

    for (int i = 0 ; i < (int) msgnum ; i++) {
        if (0 == asconhashav12_i(x_ptr, HASH_SIZE, xj_ptr, i))                                  { return 0; }   /* xj = H(x || i) */
        if (0 == asconhashav12_i(r_ptr, HASH_SIZE, rj_ptr, i))                                  { return 0; }   /* rj = H(r || i) */
        if (0 == concat_str_str(msg[i], msglen,
                                xj_ptr, HASH_SIZE,
                                ex_hash, &ex_hash_len))                                         { return 0; }
        
        if (0 == sha256_i(ex_hash, ex_hash_len, e_ptr, this->counter))                          { return 0; }   /* e = H(msg || x) */

        e_bn = BN_bin2bn(e_ptr, HASH_SIZE, 0);
        r_bn = BN_bin2bn(rj_ptr, HASH_SIZE, 0);
        if (e_bn == NULL || r_bn == NULL)                                                       { return 0; }
        /* s1 = e * y */
        if (0 == BN_mul(x_bn, e_bn, this->y, bn_ctx))                                           { return 0; }   /* s' = e . y */

        if (i == 0) {
            if (0 == BN_mod_sub(s_bn, r_bn, x_bn, order, bn_ctx))                               { return 0; }   /* s = s' mod q */
        } else {
            if (0 == BN_mod_sub(sl_bn, r_bn, x_bn, order, bn_ctx))                              { return 0; }   /* s' = r - e . y mod q */
            if (0 == BN_mod_add(s_bn, s_bn, sl_bn, order, bn_ctx))                              { return 0; }   /* s = s + s' mod q */
        }
    }
    if (0 == encodeBN(s_bn, sig, siglen))                                                       { return 0; }
    *counter = this->counter;
    this->counter ++;


    BN_free(x_bn);
    BN_free(e_bn);
    BN_free(r_bn);
    BN_free(s_bn);
    BN_free(sl_bn);

    return 1;
}


/**
 * Function Name: send_signature
 *
 * Description:
 * Send the signature to the verifier (SGX enclave)
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::send_signature(unsigned char* sig, size_t siglen)
{

    return 1;
}
