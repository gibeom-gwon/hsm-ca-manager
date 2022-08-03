#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "cert.h"

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

int set_random_serialNumber(X509 *cert)
{
	ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
	if(!serialNumber)
		return 0;
	unsigned char buf[18];
	if(!RAND_bytes(buf,sizeof(buf)))
		return 0;
	BIGNUM *bn = BN_bin2bn(buf,sizeof(buf),NULL);
	if(bn == NULL)
		return 0;
	if(BN_to_ASN1_INTEGER(bn,serialNumber) == NULL)
	{
		BN_free(bn);
		return 0;
	}
	BN_free(bn);
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

int sign_x509(X509 *cert, EVP_PKEY *key)
{
	return X509_sign(cert,key,EVP_sha256());
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
