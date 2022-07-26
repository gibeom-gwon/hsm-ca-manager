#include "openssl.h"
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

int init_crypto_with_dynamic_engine()
{
	return OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL);
}

ENGINE *init_pkcs11_engine()
{
	ENGINE *engine = NULL;
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

X509_REQ *load_csr(const char *filepath)
{
	X509_REQ *cert_req = NULL;
	FILE *csr_file = fopen(filepath,"rb");
	if(csr_file == NULL)
		return NULL;
	if(PEM_read_X509_REQ(csr_file,&cert_req,NULL,NULL) == NULL)
	{
		fclose(csr_file);
		return NULL;
	}
	fclose(csr_file);
	return cert_req;
}

X509 *load_x509(const char *filepath)
{
	X509 *cert = NULL;
	FILE *ca_cert_file = fopen(filepath,"rb");
	if(ca_cert_file == NULL)
		return NULL;
	if(PEM_read_X509(ca_cert_file,&cert,NULL,NULL) == NULL)
	{
		fclose(ca_cert_file);
		return NULL;
	}
	fclose(ca_cert_file);
	return cert;
}

int set_version3(X509 *cert)
{
	return X509_set_version(cert,2);
}

int set_serialNumber(X509 *cert, long serial)
{
	ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
	if(!serialNumber)
		return 0;
	if(!ASN1_INTEGER_set(serialNumber,serial))
		return 0;
	return 1;
}

X509_NAME *set_subject_name(X509 *cert, const char *C, const char *O, const char *OU, const char *CN)
{
	X509_NAME *name = X509_get_subject_name(cert);
	if(!name)
		return NULL;
	if(C != NULL)
	{
		if(!X509_NAME_add_entry_by_txt(name,"C",MBSTRING_ASC,(unsigned char*)C,-1,-1,0))
			return NULL;
	}
	if(O != NULL)
	{
		if(!X509_NAME_add_entry_by_txt(name,"O",MBSTRING_ASC,(unsigned char*)O,-1,-1,0))
			return NULL;
	}
	if(OU != NULL)
	{
		if(!X509_NAME_add_entry_by_txt(name,"OU",MBSTRING_ASC,(unsigned char*)OU,-1,-1,0))
			return NULL;
	}
	if(CN != NULL)
	{
		if(!X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)CN,-1,-1,0))
			return NULL;
	}
	return name;
}

int set_issuer_name(X509 *cert, X509_NAME *name)
{
	return X509_set_issuer_name(cert,name);
}

int set_subject_name_from_csr(X509 *to, X509_REQ *from)
{
	X509_NAME *name = X509_REQ_get_subject_name(from);
	if(!X509_set_subject_name(to,name))
		return 0;
	return 1;
}

int set_issuer_name_from_x509(X509 *to, X509 *from)
{
	X509_NAME *name = X509_get_subject_name(from);
	if(!X509_set_issuer_name(to,name))
		return 0;
	return 1;
}

int set_expire_date(X509 *cert, unsigned int after_days)
{
	ASN1_TIME *notBefore = X509_getm_notBefore(cert);
	if(!X509_gmtime_adj(notBefore,0))
		return 0;
	ASN1_TIME *notAfter = X509_getm_notAfter(cert);
	if(!X509_gmtime_adj(notAfter,60 * 60 * 24 * after_days))
		return 0;
	return 1;
}

int set_pubkey(X509 *cert, EVP_PKEY *key)
{
	return X509_set_pubkey(cert,key);
}

int copy_pubkey_from_csr(X509 *cert, X509_REQ *csr)
{
	EVP_PKEY *req_pubkey = X509_REQ_get0_pubkey(csr);
	if(req_pubkey == NULL)
		return 0;
	if(!X509_set_pubkey(cert,req_pubkey))
		return 0;
	return 1;
}

int copy_extensions_from_csr(X509 *cert, X509_REQ *csr)
{
	const STACK_OF(X509_EXTENSION) *req_extensions = X509_REQ_get_extensions(csr);
	int extension_num = sk_X509_EXTENSION_num(req_extensions);
	int *extension_nid_list = malloc(sizeof(int) * extension_num);

	for(int i = 0;i < extension_num;i++)
	{
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(req_extensions,i);
		int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
		extension_nid_list[i] = nid;
	}

	for(int i = 0;i < extension_num;i++)
	{
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(req_extensions,i);
		for(int j = i + 1;j < extension_num;j++)
		{
			if(extension_nid_list[i] == extension_nid_list[j])
				return 0;
		}
		if(!X509_add_ext(cert,ext,-1))
			return 0;
	}

	free(extension_nid_list);
	return 1;
}

int set_extension_basic_constraints(X509 *cert, int ca)
{
	BASIC_CONSTRAINTS *bcons = BASIC_CONSTRAINTS_new();
	if(!bcons)
		return 0;
	bcons->ca = ca;
	if(!X509_add1_ext_i2d(cert,NID_basic_constraints,bcons,1,0))
		return 0;
	BASIC_CONSTRAINTS_free(bcons);
	return 1;
}

int set_extension_key_usage(X509 *cert, int key_usage)
{
	ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
	if(!bs)
		return 0;

	int bit = 0;
	while(key_usage)
	{
		if(key_usage & 0x01)
		{
			if(!ASN1_BIT_STRING_set_bit(bs,bit,1))
			{
				ASN1_BIT_STRING_free(bs);
				return 0;
			}
		}
		key_usage >>= 1;
		bit++;
	}
	if(X509_add1_ext_i2d(cert,NID_key_usage,bs,1,0) < 1)
	{
		ASN1_BIT_STRING_free(bs);
		return 0;
	}
	ASN1_BIT_STRING_free(bs);
	return 1;
}

int set_skid(X509 *cert)
{
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH];
	unsigned int len;
	ASN1_STRING *oct_string = ASN1_STRING_new();
	if(!oct_string)
		return 0;
	if(!X509_pubkey_digest(cert,EVP_sha1(),pubkey_hash,&len))
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	if(!ASN1_STRING_set(oct_string,pubkey_hash,SHA_DIGEST_LENGTH))
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	if(X509_add1_ext_i2d(cert,NID_subject_key_identifier,oct_string,0,X509V3_ADD_REPLACE) < 1)
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	ASN1_STRING_free(oct_string);
	return 1;
}

int set_akid_from_x509_skid(X509 *to, X509 *from)
{
	int ext_loc = X509_get_ext_by_NID(from,NID_subject_key_identifier,-1);
	if(ext_loc == -1)
		return 0;
	X509_EXTENSION *root_ca_subject_key_id = X509_get_ext(from,ext_loc);
	if(root_ca_subject_key_id == NULL)
		return 0;
	ASN1_STRING *ext_data = X509_EXTENSION_get_data(root_ca_subject_key_id);
	const unsigned char *data = ASN1_STRING_get0_data(ext_data);
	ASN1_STRING *issuer_subject_key_id = NULL;
	if(d2i_ASN1_OCTET_STRING(&issuer_subject_key_id,&data,ASN1_STRING_length(ext_data)) == NULL)
		return 0;

	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if(!akid)
		return 0;
	akid->keyid = issuer_subject_key_id;
	if(X509_add1_ext_i2d(to,NID_authority_key_identifier,akid,0,X509V3_ADD_REPLACE) < 1)
	{
		AUTHORITY_KEYID_free(akid);
		return 0;
	}
	AUTHORITY_KEYID_free(akid);
	return 1;
}

EVP_PKEY *get_privkey_from_pkcs11(ENGINE *engine, const char *pkcs11_uri)
{
	return ENGINE_load_private_key(engine,pkcs11_uri,NULL,NULL);
}

EVP_PKEY *get_pubkey_from_pkcs11(ENGINE *engine, const char *pkcs11_uri)
{
	return ENGINE_load_public_key(engine,pkcs11_uri,NULL,NULL);
}

int sign_x509(X509 *cert, EVP_PKEY *key)
{
	return X509_sign(cert,key,EVP_sha256());
}

int export_x509_to_der_file(const char *filepath, X509 *cert)
{
	FILE *f = fopen("root_ca.der","wb");
	if(!f)
		return 0;
	if(!i2d_X509_fp(f,cert))
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

int export_x509_to_pem_file(const char *filepath, X509 *cert)
{
	FILE *file = fopen(filepath,"wb");
	if(!file)
		return 0;
	if(!PEM_write_X509(file,cert))
	{
		fclose(file);
		return 0;
	}
	fclose(file);
	return 1;
}

int print_x509_pem(X509 *cert)
{
	return PEM_write_X509(stdout,cert);
}

void csr_free(X509_REQ *csr)
{
	X509_REQ_free(csr);
}

void key_free(EVP_PKEY *key)
{
	EVP_PKEY_free(key);
}

void engine_free(ENGINE *engine)
{
	ENGINE_finish(engine);
	ENGINE_free(engine);
}

X509 *x509_new()
{
	return X509_new();
}

void x509_free(X509 *cert)
{
	X509_free(cert);
}

const char *ssl_get_error_string()
{
	return ERR_reason_error_string(ERR_get_error());
}
