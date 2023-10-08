
#include "Authority.h"
#include "Enclave_u.h"
#include "util.h"
#include "App.h"
#include <iostream>

Authority::Authority()
{
}

Authority::~Authority()
{
}


/**
 * Function Name: init
 *
 * Description:
 * Initialize Authority keys
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init()
{
    this->signer_id = 0;
    this->msk = new unsigned char[EC_POINT_SIZE];

    if (0 == RAND_bytes(this->msk, EC_POINT_SIZE))                                          { return 0; }

    this->ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (this->ec_group == NULL)                                                             { return 0; }

    return 1;
}


/**
 * Function Name: init_parties
 *
 * Description:
 * Initialize ETA process
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_parties(sgx_enclave_id_t* verifier_id, Signer** signer)
{
    int ret;
    this->signer_id ++;

    ret = this->init_enclave(verifier_id);
    if (ret == 0)                                                                              { return 0; }

    ret = this->sendMSK(*verifier_id);
    if (ret == 0)                                                                              { return 0; }

    ret = this->sendDP(*verifier_id);
    if (ret == 0)                                                                              { return 0; }

    this->init_signer(signer);

    return 1;
}


/**
 * Function Name: init_signer
 *
 * Description:
 * Initialize the signer
 * 
 * @param signer     Signer instance
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_signer(Signer** signer)
{
    unsigned char          y[HASH_SIZE];
    BIGNUM                 *y_bn;
    EC_KEY                 *y_key;
    EC_POINT*               y_pub;
    Signer*                signer_tmp;


    if (0 == sha256_i(this->msk, HASH_SIZE, y, this->signer_id))                                { return 0; }

    y_bn    = BN_bin2bn((uint8_t*) y, sizeof(y), NULL);
    y_pub   = EC_POINT_new(this->ec_group);
    if (0 == EC_POINT_mul(this->ec_group, y_pub, y_bn, NULL, NULL, NULL))                       { return 0; }

    y_key   = EC_KEY_new();
    if (0 == EC_KEY_set_group(y_key, this->ec_group))                                           { return 0; }
    if (0 == EC_KEY_set_private_key(y_key, y_bn))                                               { return 0; }
    if (0 == EC_KEY_set_public_key(y_key, y_pub))                                               { return 0; }

    /* set the signer id and the signer keys */
    signer_tmp = new Signer(this->signer_id);
    signer_tmp->setSignerKeys(this->ec_group, y_key);

    *signer = signer_tmp;


    return 1;
}


/**
 * Function Name: init_enclave
 *
 * Description:
 * Initialize the enclave
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_enclave(sgx_enclave_id_t* enclave_id)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, enclave_id, NULL);
    if (ret != SGX_SUCCESS)                                                                     { return 0; }
    

    return 1;
}


/**
 * Function Name: destroy_enclave
 *
 * Description:
 * Destory the SGX enclave
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::destroy_enclave(sgx_enclave_id_t enclave_id)
{
    sgx_status_t ret = SGX_SUCCESS;
    
    ret = sgx_destroy_enclave(enclave_id);
    if (ret != SGX_SUCCESS)                                                                     { return 0; }

    return 1;
}


/**
 * Function Name: sendMSK
 *
 * Description:
 * Send the Authority's master key
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::sendMSK(sgx_enclave_id_t enclave_id)
{
    if (0 != send_msk(enclave_id, this->msk, HASH_SIZE, this->signer_id))                                { return 0; }

    return 1;
}


/**
 * Function Name: sendDP
 *
 * Description:
 * Send the domain parameters for the EC curve
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::sendDP(sgx_enclave_id_t enclave_id)
{
    BIGNUM          *p_nb, *a_nb, *b_nb, *order_bn, *cofactor_bn, *gx_bn, *gy_bn;
    uint8_t         *a, *b, *p, *gx, *gy, *order, *cofactor;
    size_t          alen, blen, plen, gxlen, gylen, orderlen, cofactorlen;
    EC_POINT        *G;
    BN_CTX          *ctx;

    p_nb        = BN_new();
    a_nb        = BN_new();
    b_nb        = BN_new();
    gx_bn       = BN_new();
    gy_bn       = BN_new();
    order_bn    = BN_new();
    cofactor_bn = BN_new();
    ctx         = BN_CTX_new();

    G           = (EC_POINT*) EC_GROUP_get0_generator(this->ec_group);
    order_bn    = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    cofactor_bn = (BIGNUM*) EC_GROUP_get0_cofactor(this->ec_group);
    if (0 == EC_GROUP_get_curve(this->ec_group, p_nb, a_nb, b_nb, ctx))                         { return 0; }    
    if (0 == EC_POINT_get_affine_coordinates(this->ec_group, G, gx_bn, gy_bn, ctx))             { return 0; }
    if (G == NULL || order_bn == NULL || cofactor_bn == NULL)                                   { return 0; }

    if (0 == encodeBN(p_nb, &p, &plen))                                                         { return 0; }
    if (0 == encodeBN(a_nb, &a, &alen))                                                         { return 0; }
    if (0 == encodeBN(b_nb, &b, &blen))                                                         { return 0; }
    if (0 == encodeBN(gx_bn, &gx, &gxlen))                                                      { return 0; }
    if (0 == encodeBN(gy_bn, &gy, &gylen))                                                      { return 0; }
    if (0 == encodeBN(order_bn, &order, &orderlen))                                             { return 0; }
    if (0 == encodeBN(cofactor_bn, &cofactor, &cofactorlen))                                    { return 0; }


    if (0 != send_dp(enclave_id,
                     p, plen,
                     a, alen,
                     b, blen,
                     gx, gxlen,
                     gy, gylen,
                     order, orderlen,
                     cofactor, cofactorlen))                                                    { return 0; }


    return 1;
}
