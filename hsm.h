#ifndef __HSM_H__
#define __HSM_H__

#include <openssl/engine.h>

ENGINE *hsm_init();
void hsm_free(ENGINE *engine);
EVP_PKEY *get_privkey_from_hsm(ENGINE *engine, const char *pkcs11_uri);
EVP_PKEY *get_pubkey_from_hsm(ENGINE *engine, const char *pkcs11_uri);
void key_free(EVP_PKEY *key);

#endif
