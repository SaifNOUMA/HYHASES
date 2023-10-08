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

#define MSK_SIZE 256
#define HASH_SIZE 32
#define T 1024
#define K 16
#define SEED_SIZE HASH_SIZE
#define SK_SIZE (T * HASH_SIZE)
#define PK_SIZE (T * HASH)

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.so"
