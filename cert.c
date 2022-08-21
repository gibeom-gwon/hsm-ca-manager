#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "cert.h"

int set_version3(X509 *cert)
{
	if(!X509_set_version(cert,2))
		return -1;
	return 0;
}

int set_serialNumber(X509 *cert, long serial)
{
	ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
	if(serialNumber == NULL)
		return -1;
	if(!ASN1_INTEGER_set(serialNumber,serial))
		return -1;
	return 0;
}

int set_random_serialNumber(X509 *cert)
{
	ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
	if(serialNumber == NULL)
		return -1;
	unsigned char buf[18];
	if(!RAND_bytes(buf,sizeof(buf)))
		return -1;
	BIGNUM *bn = BN_bin2bn(buf,sizeof(buf),NULL);
	if(bn == NULL)
		return -1;
	if(BN_to_ASN1_INTEGER(bn,serialNumber) == NULL)
	{
		BN_free(bn);
		return -1;
	}
	BN_free(bn);
	return 0;
}

X509_NAME *make_simple_subject_name(X509 *cert, const char *C, const char *O, const char *OU, const char *CN)
{
	X509_NAME *name = X509_get_subject_name(cert);
	if(name == NULL)
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

int set_subject_name_to_csr(X509_REQ *csr, X509_NAME *name)
{
	if(!X509_REQ_set_subject_name(csr,name))
		return -1;
	return 0;
}

int set_issuer_name(X509 *cert, X509_NAME *name)
{
	if(!X509_set_issuer_name(cert,name))
		return -1;
	return 0;
}

int set_subject_name_from_csr(X509 *to, X509_REQ *from)
{
	X509_NAME *name = X509_REQ_get_subject_name(from);
	if(!X509_set_subject_name(to,name))
		return -1;
	return 0;
}

int set_issuer_name_from_x509(X509 *to, X509 *from)
{
	X509_NAME *name = X509_get_subject_name(from);
	if(!X509_set_issuer_name(to,name))
		return -1;
	return 0;
}

int set_expire_date(X509 *cert, unsigned int after_days)
{
	ASN1_TIME *notBefore = X509_getm_notBefore(cert);
	if(notBefore == NULL)
		return -1;
	if(!X509_gmtime_adj(notBefore,0))
		return -1;
	ASN1_TIME *notAfter = X509_getm_notAfter(cert);
	if(notAfter == NULL)
		return -1;
	if(!X509_gmtime_adj(notAfter,60 * 60 * 24 * after_days))
		return -1;
	return 0;
}

int set_pubkey(X509 *cert, EVP_PKEY *key)
{
	if(!X509_set_pubkey(cert,key))
		return -1;
	return 0;
}

int set_pubkey_to_csr(X509_REQ *csr, EVP_PKEY *key)
{
	if(!X509_REQ_set_pubkey(csr,key))
		return -1;
	return 0;
}

int copy_pubkey_from_csr(X509 *cert, X509_REQ *csr)
{
	EVP_PKEY *req_pubkey = X509_REQ_get0_pubkey(csr);
	if(req_pubkey == NULL)
		return -1;
	if(!X509_set_pubkey(cert,req_pubkey))
		return -1;
	return 0;
}

int sign_x509(X509 *cert, EVP_PKEY *key)
{
	if(!X509_sign(cert,key,EVP_sha256()))
		return -1;
	return 0;
}

int sign_csr(X509_REQ *csr, EVP_PKEY *key)
{
	if(!X509_REQ_sign(csr,key,EVP_sha256()))
		return -1;
	return 0;
}

void csr_free(X509_REQ *csr)
{
	X509_REQ_free(csr);
}

X509 *x509_new()
{
	return X509_new();
}

void x509_free(X509 *cert)
{
	X509_free(cert);
}

X509_REQ *csr_new()
{
	return X509_REQ_new();
}

X509_NAME *x509_name_new()
{
	return X509_NAME_new();
}

void x509_name_free(X509_NAME *name)
{
	X509_NAME_free(name);
}

int x509_name_add_entry(X509_NAME *name, const char *field, const char *value)
{
	if(!X509_NAME_add_entry_by_txt(name,field,MBSTRING_UTF8,(const unsigned char*)value,-1,-1,0))
		return -1;
	return 0;
}

int verify_csr(X509_REQ *csr)
{
	EVP_PKEY *pubkey = X509_REQ_get0_pubkey(csr);
	if(pubkey == NULL)
		return -1;
	if(!X509_REQ_verify(csr,pubkey))
		return -1;
	return 0;
}
