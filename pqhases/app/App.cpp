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
#include <iostream>
#include <fstream>
#define J 1000000
// #define INFO
#define DEBUG



using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t    global_eid = 0;


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
    uint8_t         *msg, sig[1000];
    size_t          counter, siglen;
    int             msglen, status, res = -1;
    double          req_t, avg_req = 0.0, sig_time = 0.0, ver_time = 0.0;
    clock_t         t0, t1;


    // Initialization
    msglen = atoi(argv[1]);
    authority = new Authority();
    authority->init();
    authority->init_parties(&global_eid, &signer);


    for (int i = 0 ; i < J ; i++) {
        // message generation
        msg = new uint8_t[msglen];
        if (0 == RAND_bytes(msg, msglen)) {
#ifdef INFO
            printf("INFO: message generation is failed\n");
#endif
            return 1;
        }

        // signature generation
        t0 = clock();
        status = signer->sign_message(msg, msglen, sig, &siglen, &counter);
        t1 = clock();
        sig_time += t1 - t0;
        if (status == 1) {
#ifdef INFO
            printf("INFO: signature generation successfully finished\n");
#endif
        } else {
#ifdef INFO
            printf("INFO: signature generation failed\n");
#endif
            return 1;
        }

        // signature verification
        t0 = clock();
        status = verify_signature(global_eid, sig, siglen, msg, msglen,
                                  signer->ID, counter, &res, &req_t);
        t1 = clock();
        avg_req += req_t;
        ver_time += t1 - t0 - req_t;

        if (res == 0) {
#ifdef INFO
            printf("INFO: signature verification successfully finished\n");
#endif
        } else {
#ifdef INFO
            printf("INFO: signature verification failed\n");
#endif
            return 1;
        }
    }

#ifdef DEBUG
    printf("DEBUG: avg sig-gen  = %.2f us\n", sig_time / J);
    printf("DEBUG: avg sig-ver  = %.2f us\n", ver_time / J);
    printf("DEBUG: avg pkconst  = %.2f us\n", avg_req / J);
#endif


    return 0;
}
