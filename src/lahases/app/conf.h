#include "string.h"
#include "math.h"
#include "string.h"
#include "stdlib.h"
#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <sgx_urts.h>

# define MAX_PATH FILENAME_MAX

#define EC_POINT_SIZE 32
#define HASH_SIZE 32

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.so"
