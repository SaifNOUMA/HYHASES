/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "App.h"
#include "conf.h"
#include "Authority.h"
#include "verify.cpp"
#include "Enclave_u.h"
#define J 100
#define N 1024
// #define INFO
#define DEBUG

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


/* OCall functions */
void ocall_uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


/* Application entry */
int main(int argc, char *argv[])
{
    Authority*      authority;
    Signer*         signer = NULL;
    uint8_t         *msg[N], *sig;
    size_t          count, siglen, msglen;
    clock_t         t0, t1;
    int             res, status;
    double          req_temp, req_t = 0.0, sig_gen = 0.0, sig_ver = 0.0;

    // Initialization
    msglen = atoi(argv[1]);
    authority = new Authority();
    authority->init();
    authority->init_parties(&global_eid, &signer);

    // Generate the messages to be signed
    for (int i = 0 ; i < N ; i++) {
        msg[i] = new uint8_t[msglen];
        if (0 == RAND_bytes(msg[i], msglen)) {
#ifdef INFO
            printf("INFO: message generation is failed\n");
#endif
            return 1;
        }
    }
    for (int i = 0 ; i < J ; i++) {
        // signature generation
        t0 = clock();
        // status = signer->sign_message(msg, msglen, &sig, &siglen, &count);
        status = signer->sign_batch_msg(msg, msglen, N, &sig, &siglen, &count);
        t1 = clock();
        sig_gen += t1 - t0;
        if (status == 1) {
#ifdef INFO
            printf("INFO [j=%d]: signature generation passed successfully\n", i);
#endif
        } else {
#ifdef INFO
            printf("INFO: signature generation failed\n");
#endif
            return 1;
        }

        // signature verification
        t0 = clock();
        // ver_sig(global_eid, sig, siglen, msg, msglen,
        //         signer->ec_group, signer->Y, count, &res);
        ver_batch_msg(global_eid, sig, siglen, msg, msglen, N,
                      signer->ec_group, signer->Y, count, &res, &req_temp);
        t1 = clock();
        sig_ver += t1 - t0 - req_temp;
        req_t += req_temp;
        if (res == 0) {
#ifdef INFO
            printf("INFO: Signature is valid\n");
#endif
        } else {
#ifdef INFO
            printf("INFO: Signature is denied\n");
#endif
            return 1;
        }
    }


#ifdef DEBUG
    printf("DEBUG: average sig-gen: %.2f us\n", sig_gen / J);
    printf("DEBUG: average sig-ver: %.2f us\n", sig_ver / J);
    printf("DEBUG: average comcons: %.2f us\n", req_t / J);
#endif

    return 0;
}
