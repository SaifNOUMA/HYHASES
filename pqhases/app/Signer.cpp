
#include "Signer.h"
#include <openssl/sha.h>

Signer::Signer(int id)
{
    this->ID        = id;
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
int Signer::setSignerKeys(uint8_t* sk)
{
    memcpy(this->sk, sk, sizeof(this->sk));
    this->counter = 0;

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
int Signer::sign_message(uint8_t* msg, size_t msglen,
                         uint8_t* sig, size_t* siglen,
                         size_t* counter)
{   
    int     h_subs[K];
    uint8_t hash[HASH_SIZE];
    uint8_t sig_tmp[K * HASH_SIZE];
    uint8_t ex_hash[HASH_SIZE + sizeof(int)];
    std::bitset<HASH_SIZE * 8> hash_bits;

    if (0 == sha256_i(msg, msglen, hash, 0))                                                        { return 0; }       /* h = H(msg) */

    for (int i = 0 ; i < (int) sizeof(hash) ; i++) {
        for (int j = 0 ; j < 8 ; j++) {
            hash_bits[8 * i + j] = hash[i] & (1 << j) ? 1 : 0;
        }
    }

    for (int i = 0 ; i < K ; i++) {                                                                                     /* compute indices {i_k} */
        std::bitset<10> hsub;
        for (int j = 0 ; j < 10 ; j++) {
            hsub[j] = hash_bits[i * 10 + j];
        }
        h_subs[i] = hsub.to_ulong();
    }

    memcpy(ex_hash, this->sk, HASH_SIZE);
    for (int i = 0 ; i < (int) K ; i++) {                                                                               /* compute sig {s_k} */
        memcpy(ex_hash + HASH_SIZE, (uint8_t*) &(h_subs[i]), sizeof(h_subs[i]));
        if (0 == sha256_i(ex_hash, HASH_SIZE + sizeof(h_subs[i]), sig_tmp + i * HASH_SIZE, 1))      { return 0; }
    }


    memcpy(sig, sig_tmp, K * HASH_SIZE);
    *siglen = K * HASH_SIZE;
    *counter = this->counter;
    this->counter ++;
    this->update_keys();


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

/**
 * Function Name: update_keys
 *
 * Description:
 * Update the signer keys when signing occurs
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::update_keys()
{
    sha256_i(this->sk, HASH_SIZE, this->sk, 2);

    return 1;
}
