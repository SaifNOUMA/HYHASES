
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "util.h"
#include "conf.h"

class Signer
{
private:
    int             ID;
    size_t          counter;
    BIGNUM*         y;


public:
    Signer(int id);
    ~Signer();

    int setSignerKeys(EC_GROUP* ec_group, EC_KEY* y_key);

    int sign_message(uint8_t* message, size_t messagelen,
                     uint8_t** sig, size_t* siglen,
                     size_t* counter);

    int sign_batch_msg(uint8_t* messages[], size_t messageslen, size_t num_messages,
                            uint8_t** sig, size_t* siglen,
                            size_t* counter);

    int send_signature(unsigned char* sig, size_t siglen);


    EC_POINT*       Y;
    EC_GROUP*       ec_group;
};
