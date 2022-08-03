#ifndef __CERT_IO_H__
#define __CERT_IO_H__

#include <openssl/x509v3.h>

X509_REQ *load_csr(const char *filepath);
X509 *load_x509(const char *filepath);
int export_x509_to_der_file(const char *filepath, X509 *cert);
int export_x509_to_pem_file(const char *filepath, X509 *cert);
int print_x509_pem(X509 *cert);

#endif
