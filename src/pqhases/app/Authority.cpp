
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
    this->msk = new unsigned char[MSK_SIZE];

    if (0 == RAND_bytes(this->msk, MSK_SIZE))                                                   { return 0; }


    return 1;
}


/**
 * Function Name: init_parties
 *
 * Description:
 * Initialize HORS's signer and HORS's verifer
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
    unsigned char          y[SK_SIZE], prior_hash[1000];
    size_t                 prior_hash_len = 0;
    Signer*                signer_tmp;

    memset(y, 0, SEED_SIZE);
    memset(prior_hash, 0, sizeof(prior_hash));

    // concatenate Msk || ID
    memcpy(prior_hash, this->msk, MSK_SIZE);
    prior_hash_len = MSK_SIZE;
    memcpy(prior_hash + prior_hash_len, (uint8_t*) &(this->signer_id), sizeof(this->signer_id));
    prior_hash_len += sizeof(this->signer_id);
    if (0 == sha256_i(prior_hash, prior_hash_len, y, 0))                                         { return 0; }
   
    // set the signer id and the signer keys
    signer_tmp = new Signer(this->signer_id);
    signer_tmp->setSignerKeys(y);

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
    if (0 != send_msk(enclave_id, this->msk, MSK_SIZE, this->signer_id))                                { return 0; }

    return 1;
}
