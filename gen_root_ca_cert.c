#include <stdio.h>
#include "openssl.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 100

#define CERT_C "KR"
#define CERT_O "test org"
#define CERT_CN "test root CA"

int main()
{
	int ret = 0;

	X509 *cert = NULL;
	ENGINE *engine = NULL;
	EVP_PKEY *pubkey = NULL,*privkey = NULL;

	if(!init_crypto_with_dynamic_engine())
		goto fail;

	if((cert = x509_new()) == NULL)
		goto fail;

	if((engine = init_pkcs11_engine()) == NULL)
		goto fail;

	if((pubkey = get_pubkey_from_pkcs11(engine,PKCS11_URI)) == NULL)
		goto fail;

	if(!set_version3(cert))
		goto fail;

	if(!set_serialnumber(cert,1))
		goto fail;

	if(!set_expire_date(cert,DAYS_AFTER_EXPIRE))
		goto fail;

	if(!set_pubkey(cert,pubkey))
		goto fail;

	X509_NAME *name = set_subject_name(cert,CERT_C,CERT_O,CERT_CN);
	if(!name)
		goto fail;
	if(!set_issuer_name(cert,name))
		goto fail;

	if(!set_skid(cert))
		goto fail;

	if(!set_extension_basic_constraints(cert,1))
		goto fail;

	if(!set_extension_key_usage(cert,KEY_USAGE_KEY_CERT_SIGN|KEY_USAGE_CRL_SIGN))
		goto fail;

	privkey = get_privkey_from_pkcs11(engine,PKCS11_URI);
	if(privkey == NULL)
		goto fail;

	if(!sign_x509(cert,privkey))
		goto fail;

	if(!export_x509_to_der_file("root_ca.der",cert))
		goto fail;

	if(!export_x509_to_pem_file("root_ca.pem",cert))
		goto fail;

	cleanup:
	if(privkey)
		key_free(privkey);
	if(pubkey)
		key_free(pubkey);
	if(engine)
		engine_free(engine);
	if(cert)
		x509_free(cert);
	return ret;

	fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	ret = -1;
	goto cleanup;
}
