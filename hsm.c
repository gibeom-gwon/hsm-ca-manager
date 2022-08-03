#include "hsm.h"

ENGINE *hsm_init()
{
	ENGINE *engine = NULL;

	if(!OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL))
		return NULL;
	if((engine = ENGINE_by_id("pkcs11")) == NULL)
		return NULL;

	/*
	ENGINE_ctrl_cmd_string(engine,"SO_PATH","/usr/lib/engines-1.1/pkcs11.so",0);
	ENGINE_ctrl_cmd_string(engine,"ID","pkcs11",0);
	ENGINE_ctrl_cmd_string(engine,"LOAD",NULL,0);
	ENGINE_ctrl_cmd_string(engine,"MODULE_PATH","/usr/lib/libp11-kit-proxy.so",0);
	*/

	if(!ENGINE_init(engine))
	{
		ENGINE_free(engine);
		return NULL;
	}
	return engine;
}

void hsm_free(ENGINE *engine)
{
	ENGINE_finish(engine);
	ENGINE_free(engine);
}

EVP_PKEY *get_privkey_from_hsm(ENGINE *engine, const char *pkcs11_uri)
{
	return ENGINE_load_private_key(engine,pkcs11_uri,NULL,NULL);
}

EVP_PKEY *get_pubkey_from_hsm(ENGINE *engine, const char *pkcs11_uri)
{
	return ENGINE_load_public_key(engine,pkcs11_uri,NULL,NULL);
}

void key_free(EVP_PKEY *key)
{
	EVP_PKEY_free(key);
}
