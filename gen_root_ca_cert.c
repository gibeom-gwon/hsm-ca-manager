#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 100

#define CERT_C "KR"
#define CERT_O "test org"
#define CERT_CN "test root CA"

int main()
{
	int ret = 0;
	int engine_initialized = 0;

	X509 *cert = NULL;
	ENGINE *engine = NULL;
	EVP_PKEY *pubkey = NULL,*privkey = NULL;

	if(!OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL))
		goto fail;

	if((cert = X509_new()) == NULL)
		goto fail;

	if((engine = ENGINE_by_id("pkcs11")) == NULL)
		goto fail;
	/*
	ENGINE_ctrl_cmd_string(engine,"SO_PATH","/usr/lib/engines-1.1/pkcs11.so",0);
	ENGINE_ctrl_cmd_string(engine,"ID","pkcs11",0);
	ENGINE_ctrl_cmd_string(engine,"LOAD",NULL,0);
	ENGINE_ctrl_cmd_string(engine,"MODULE_PATH","/usr/lib/libp11-kit-proxy.so",0);
	*/

	if(!ENGINE_init(engine))
		goto fail;
	engine_initialized = 1;

	if((pubkey = ENGINE_load_public_key(engine,PKCS11_URI,NULL,NULL)) == NULL)
		goto fail;

	if(!X509_set_version(cert,2))
		goto fail;

	ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
	if(!serialNumber)
		goto fail;
	if(!ASN1_INTEGER_set(serialNumber,1))
		goto fail;

	ASN1_TIME *notBefore = X509_getm_notBefore(cert);
	if(!notBefore)
		goto fail;
	if(!X509_gmtime_adj(notBefore,0))
		goto fail;
	ASN1_TIME *notAfter = X509_getm_notAfter(cert);
	if(!notAfter)
		goto fail;
	if(!X509_gmtime_adj(notAfter,60 * 60 * 24 * DAYS_AFTER_EXPIRE))
		goto fail;

	if(!X509_set_pubkey(cert,pubkey))
		goto fail;

	X509_NAME *name = X509_get_subject_name(cert);
	if(!name)
		goto fail;
	if(!X509_NAME_add_entry_by_txt(name,"C",MBSTRING_ASC,(unsigned char*)CERT_C,-1,-1,0))
		goto fail;
	if(!X509_NAME_add_entry_by_txt(name,"O",MBSTRING_ASC,(unsigned char*)CERT_O,-1,-1,0))
		goto fail;
	if(!X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)CERT_CN,-1,-1,0))
		goto fail;

	if(!X509_set_issuer_name(cert,name))
		goto fail;

	BASIC_CONSTRAINTS *bcons = BASIC_CONSTRAINTS_new();
	if(!bcons)
		goto fail;
	bcons->ca = 1;
	if(!X509_add1_ext_i2d(cert,NID_basic_constraints,bcons,1,0))
		goto fail;
	BASIC_CONSTRAINTS_free(bcons);

	unsigned char pubkey_hash[SHA_DIGEST_LENGTH];
	unsigned int len;
	ASN1_STRING *oct_string = ASN1_STRING_new();
	if(!oct_string)
		goto fail;
	if(!X509_pubkey_digest(cert,EVP_sha1(),pubkey_hash,&len))
	{
		ASN1_STRING_free(oct_string);
		goto fail;
	}
	if(!ASN1_STRING_set(oct_string,pubkey_hash,SHA_DIGEST_LENGTH))
	{
		ASN1_STRING_free(oct_string);
		goto fail;
	}
	if(X509_add1_ext_i2d(cert,NID_subject_key_identifier,oct_string,0,0) < 1)
	{
		ASN1_STRING_free(oct_string);
		goto fail;
	}
	ASN1_STRING_free(oct_string);

	ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
	if(!bs)
		goto fail;
	if(!ASN1_BIT_STRING_set_bit(bs,5,1))
	{
		ASN1_BIT_STRING_free(bs);
		goto fail;
	}
	if(!ASN1_BIT_STRING_set_bit(bs,6,1))
	{
		ASN1_BIT_STRING_free(bs);
		goto fail;
	}
	if(X509_add1_ext_i2d(cert,NID_key_usage,bs,1,0) < 1)
	{
		ASN1_BIT_STRING_free(bs);
		goto fail;
	}
	ASN1_BIT_STRING_free(bs);

	privkey = ENGINE_load_private_key(engine,PKCS11_URI,NULL,NULL);
	if(privkey == NULL)
		goto fail;

	if(!X509_sign(cert,privkey,EVP_sha256()))
		goto fail;

	FILE *f = fopen("root_ca.der","wb");
	if(!f)
		goto fail;
	if(!i2d_X509_fp(f,cert))
	{
		fclose(f);
		goto fail;
	}
	fclose(f);

	f = fopen("root_ca.pem","wb");
	if(!f)
		goto fail;
	if(!PEM_write_X509(f,cert))
	{
		fclose(f);
		goto fail;
	}
	fclose(f);

	cleanup:
	if(privkey)
		EVP_PKEY_free(privkey);
	if(pubkey)
		EVP_PKEY_free(pubkey);
	if(engine)
	{
		if(engine_initialized)
			ENGINE_finish(engine);
		ENGINE_free(engine);
	}
	if(cert)
		X509_free(cert);
	return ret;

	fail:
	fprintf(stderr,"openssl error: %s\n",ERR_reason_error_string(ERR_get_error()));
	ret = -1;
	goto cleanup;
}
