#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#define BENCH_LOOPS 100


using namespace std;

void menu();
int get_algo_id();
OQS_SIG* get_algo(int);


int main(int argc, char *argv[]) {
    OQS_SIG     *sig_alg = NULL;
    size_t      msgsize, siglen, iter, algorithm_id;
    uint8_t     *sig, *sk, *pk, *msg;
    clock_t     t0, t1;
    double      sign_time = 0, ver_time = 0;
	OQS_STATUS  rc, ret = OQS_ERROR;

    
    // choose the message
    printf("Insert the message size: ");
    cin >> msgsize;
    msg = new uint8_t[msgsize];
    if (0 == RAND_bytes(msg, msgsize))                   { goto err; }

    // context initialization
    algorithm_id = get_algo_id();
    sig_alg = get_algo(algorithm_id);
	if (sig_alg == NULL) {
		fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
		goto err;
	}

    // key generation phase
    sig = (uint8_t*) malloc(sig_alg->length_signature);
    sk  = (uint8_t*) malloc(sig_alg->length_secret_key);
    pk  = (uint8_t*) malloc(sig_alg->length_public_key);
    rc = OQS_SIG_keypair(sig_alg, pk, sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}
    // printf("DEUBG: [sizes]\n\t sk=%lu \n\t pk=%lu \n\t sig=%lu\n", sig_alg->length_secret_key, sig_alg->length_public_key, sig_alg->length_signature);
    printf("INFO: start benchmarking ....\n");

    // signing benchmark
    for (iter = 0 ; iter < BENCH_LOOPS ; iter++) {
        t0 = clock();
        rc = OQS_SIG_sign(sig_alg, sig, &siglen, msg, sizeof(msg), sk);
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
            goto err;
        }
        t1 = clock();
        sign_time += (t1 - t0);
    }

    // verifying benchmark
    for (iter = 0 ; iter < BENCH_LOOPS ; iter++) {
        t0 = clock();
        rc = OQS_SIG_verify(sig_alg, msg, sizeof(msg), sig, siglen, pk);
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
            goto err;
        }
        t1 = clock();
        ver_time += (t1 - t0);
    }

    printf("INFO: sign runs in .... %6.2f us\n", (sign_time * 1000 * 1000) / ((int64_t) BENCH_LOOPS * (int64_t) CLOCKS_PER_SEC));
    printf("INFO: ver  runs in .... %6.2f us\n", (ver_time * 1000 * 1000) / ((int64_t) BENCH_LOOPS * (int64_t) CLOCKS_PER_SEC));


    goto cleanup;
err:
    printf("INFO: Task completed with failure!\n");
    free(msg);
    return 1;
cleanup:
    printf("INFO: Task completed successfully.\n");
    free(msg);
    return 0;
}



/* ****************************************************************************************************************************************************************** */
void menu(){
    printf("Select one of the following scheme to be run: \n");
    printf("(1) Dilithium-II\n");
    printf("(2) Falcon-512\n");
    printf("(3) SPHINCS+\n");
    printf("(4) Exit\n\n");
}

int get_algo_id() {
    int id;
    while (1) {
        menu();
        cin >> id;
        if (id >= 1 & id <= 4) {
            break;
        }
    }

    return id;
}


OQS_SIG* get_algo(int algo_id) {
    OQS_SIG *sig_alg;

    switch (algo_id)
    {
    case 1:
        sig_alg = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        break;
    case 2:
        sig_alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        break;
    case 3:
        sig_alg = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple);
        break;
    default:
        sig_alg = NULL;
        break;
    }


    return sig_alg;
}
