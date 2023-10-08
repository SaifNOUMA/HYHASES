
#include "util.h"
#include "conf.h"
#include "App.h"
#include "Enclave_u.h"
#include <ctime>


int verify_signature(size_t enclave_id,
                     uint8_t* sig, size_t siglen,
                     uint8_t* message, size_t messagelen,
                     size_t signer_id, size_t counter, int* result, double *req_time)
{
    unsigned char   hash[HASH_SIZE], hash_sig[K * HASH_SIZE], pk[T * HASH_SIZE];
    size_t          count, i, h_subs[K], pk_len;
    std::clock_t    t0, t1;
    std::bitset<HASH_SIZE * 8> hash_bits;


    t0 = clock();
    if (0 != request_keys(enclave_id,                                                                                           /* request pk */
                          pk, &pk_len,
                          signer_id, counter))                                                                  { return 0; }
    t1 = clock();
    *req_time = t1 - t0;


    if (0 == sha256_i(message, messagelen, hash, 0))                                                            { return 0; }   /* h = H(msg) */


    for (int i = 0 ; i < (int) sizeof(hash) ; i++) {
        for (int j = 0 ; j < 8 ; j++) {
            hash_bits[8 * i + j] = hash[i] & (1 << j) ? 1 : 0;
        }
    }

    for (int i = 0 ; i < K ; i++) {                                                                                             /* compute indices {i_k} */
        std::bitset<10> hsub;
        for (int j = 0 ; j < 10 ; j++) {
            hsub[j] = hash_bits[i * 10 + j];
        }
        h_subs[i] = hsub.to_ulong();
    }


    *result = 0;                                                                                                                /* verify sig {s_k} */
    for (int k = 0 ; k < K ; k++) {
        if (0 == sha256_i(sig + k * HASH_SIZE, HASH_SIZE, hash_sig + k * HASH_SIZE, 0))                  { return 0; }

        *result = memcmp(hash_sig + k * HASH_SIZE, pk + h_subs[k] * HASH_SIZE, HASH_SIZE);
        if (*result != 0)                                                                                       { return 0; }
    }


    return 1;
}
