#ifndef __CERT_H__
#define __CERT_H__

#include "cert_io.h"
#include "cert_ext.h"

int set_version3(X509 *cert);
int set_serialNumber(X509 *cert, long serial);
int set_random_serialNumber(X509 *cert);
X509_NAME *make_simple_subject_name(X509 *cert, const char *C, const char *O, const char *OU, const char *CN);
int set_subject_name_from_csr(X509 *to, X509_REQ *from);
int set_subject_name_to_csr(X509_REQ *csr, X509_NAME *name);
int set_issuer_name(X509 *to, X509_NAME *name);
int set_issuer_name_from_x509(X509 *to, X509 *from);
int set_expire_date(X509 *cert, unsigned int after_days);
int set_pubkey(X509 *cert, EVP_PKEY *key);
int set_pubkey_to_csr(X509_REQ *csr, EVP_PKEY *key);
int copy_pubkey_from_csr(X509 *cert, X509_REQ *csr);
int sign_x509(X509 *cert, EVP_PKEY *key);
int sign_csr(X509_REQ *csr, EVP_PKEY *key);
void csr_free(X509_REQ *csr);
X509 *x509_new();
void x509_free(X509 *cert);
X509_REQ *csr_new();
X509_NAME *x509_name_new();
void x509_name_free(X509_NAME *name);
int x509_name_add_entry(X509_NAME *name, const char *field, const char *value);

#endif
