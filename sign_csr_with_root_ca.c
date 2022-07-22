#include <stdio.h>
#include "openssl.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 30
#define CSR_FILE "req.csr"
#define CA_CERT_FILE "root_ca.pem"

int main()
{
	int ret = 0;

	X509 *ca_cert = NULL, *result_cert = NULL;
	X509_REQ *cert_req = NULL;
	ENGINE *engine = NULL;
	EVP_PKEY *privkey = NULL;

	if(!init_crypto_with_dynamic_engine())
		goto fail;

	if((result_cert = x509_new()) == NULL)
		goto fail;

	if((engine = init_pkcs11_engine()) == NULL)
		goto fail;

	if((cert_req = load_csr(CSR_FILE)) == NULL)
		goto fail;

	if((ca_cert = load_x509(CA_CERT_FILE)) == NULL)
		goto fail;

	if(!set_version3(result_cert))
		goto fail;

	if(!set_subject_name_from_csr(result_cert,cert_req))
		goto fail;

	if(!set_issuer_name_from_x509(result_cert,ca_cert))
		goto fail;

	if(!set_expire_date(result_cert,DAYS_AFTER_EXPIRE))
		goto fail;

	if(!copy_pubkey_from_csr(result_cert,cert_req))
		goto fail;

	if(!copy_extensions_from_csr(result_cert,cert_req))
		goto fail;

	if(!set_skid(result_cert))
		goto fail;

	if(!set_akid_from_x509_skid(result_cert,ca_cert))
		goto fail;

	privkey = get_privkey_from_pkcs11(engine,PKCS11_URI);
	if(privkey == NULL)
		goto fail;

	if(!sign_x509(result_cert,privkey))
		goto fail;

	if(!export_x509_to_pem_file("cert.pem",result_cert))
		goto fail;

	cleanup:
	if(cert_req)
		csr_free(cert_req);
	if(privkey)
		key_free(privkey);
	if(engine)
		engine_free(engine);
	if(ca_cert)
		x509_free(ca_cert);
	if(result_cert)
		x509_free(result_cert);
	return ret;

	fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	ret = -1;
	goto cleanup;
}

	/*
	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if(!akid)
		goto fail;
	akid->keyid = ASN1_STRING_new();
	if(!akid->keyid)
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	if(!ASN1_STRING_set(akid->keyid,pubkey_hash,SHA_DIGEST_LENGTH))
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	if(X509_add1_ext_i2d(cert,NID_authority_key_identifier,akid,0,0) < 1)
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	AUTHORITY_KEYID_free(akid);
	*/

	/*
	ASN1_OBJECT *obj;
	EXTENDED_KEY_USAGE* extku = EXTENDED_KEY_USAGE_new();
	obj = OBJ_nid2obj(NID_server_auth);
	sk_ASN1_OBJECT_push(extku,obj);
	obj = OBJ_nid2obj(NID_client_auth);
	sk_ASN1_OBJECT_push(extku,obj);
	X509_add1_ext_i2d(cert,NID_ext_key_usage,extku,0,0);
	EXTENDED_KEY_USAGE_free(extku);
	*/
