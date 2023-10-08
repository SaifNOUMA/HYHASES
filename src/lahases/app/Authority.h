
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "conf.h"
#include "Signer.h"

class Authority
{
private:

    unsigned char*    msk;
    int               signer_id;
    EC_GROUP*         ec_group;

public:
    Authority();
    ~Authority();

    /* Initialization */
    int init();
    int init_parties(sgx_enclave_id_t* verifier_id, Signer** signer);
    
    int init_signer(Signer** signer);
    
    int init_enclave(sgx_enclave_id_t* enclave_id);
    int sendMSK(sgx_enclave_id_t enclave_id);
    int sendDP(sgx_enclave_id_t enclave_id);
    int destroy_enclave(sgx_enclave_id_t enclave_id);


    EC_POINT*       Y_public;
};
