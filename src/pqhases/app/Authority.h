
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "conf.h"
#include "Signer.h"

class Authority
{
private:

    unsigned char*    msk;
    int               signer_id;

public:
    Authority();
    ~Authority();

    int init();
    int init_parties(sgx_enclave_id_t* verifier_id, Signer** signer);
    int init_signer(Signer** signer);
    int init_enclave(sgx_enclave_id_t* enclave_id);
    int sendMSK(sgx_enclave_id_t enclave_id);
    int destroy_enclave(sgx_enclave_id_t enclave_id);
};
