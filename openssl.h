#ifndef __OPENSSL_H__
#define __OPENSSL_H__

#include <openssl/x509v3.h>
#include <openssl/err.h>

#define KEY_USAGE_DIGITAL_SIGNATURE (1)
#define KEY_USAGE_NON_REPUDIATION (1 << 1)
#define KEY_USAGE_KEY_ENCIPHERMENT (1 << 2)
#define KEY_USAGE_KEY_DATA_ENCIPHERMENT (1 << 3)
#define KEY_USAGE_KEY_AGREEMENT (1 << 4)
#define KEY_USAGE_KEY_CERT_SIGN (1 << 5)
#define KEY_USAGE_CRL_SIGN (1 << 6)
#define KEY_USAGE_ENCIPHER_ONLY (1 << 7)
#define KEY_USAGE_DECIPHER_ONLY (1 << 8)

int init_crypto_with_dynamic_engine();
ENGINE *init_pkcs11_engine();
X509_REQ *load_csr(const char *filepath);
X509 *load_x509(const char *filepath);
int set_version3(X509 *cert);
int set_serialNumber(X509 *cert, long serial);
X509_NAME *set_subject_name(X509 *cert, const char *C, const char *O, const char *OU, const char *CN);
int set_subject_name_from_csr(X509 *to, X509_REQ *from);
int set_issuer_name(X509 *to, X509_NAME *name);
int set_issuer_name_from_x509(X509 *to, X509 *from);
int set_expire_date(X509 *cert, unsigned int after_days);
int set_pubkey(X509 *cert, EVP_PKEY *key);
int copy_pubkey_from_csr(X509 *cert, X509_REQ *csr);
int copy_extensions_from_csr(X509 *cert, X509_REQ *csr);
int set_extension_basic_constraints(X509 *cert, int ca, long pathlen);
int set_extension_key_usage(X509 *cert, int key_usage);
int set_skid(X509 *cert);
int set_akid_from_x509_skid(X509 *to, X509 *from);
EVP_PKEY *get_privkey_from_pkcs11(ENGINE *engine, const char *pkcs11_uri);
EVP_PKEY *get_pubkey_from_pkcs11(ENGINE *engine, const char *pkcs11_uri);
int sign_x509(X509 *cert, EVP_PKEY *key);
int export_x509_to_der_file(const char *filepath, X509 *cert);
int export_x509_to_pem_file(const char *filepath, X509 *cert);
int print_x509_pem(X509 *cert);
void csr_free(X509_REQ *csr);
void key_free(EVP_PKEY *key);
void engine_free(ENGINE *engine);
X509 *x509_new();
void x509_free(X509 *cert);
const char *ssl_get_error_string();

#endif
