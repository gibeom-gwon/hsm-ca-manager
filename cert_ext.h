#ifndef __CERT_EXT_H__
#define __CERT_EXT_H__

#include <openssl/x509v3.h>

#define SAN_TYPE_DNS GEN_DNS
#define SAN_TYPE_EMAIL GEN_EMAIL
#define SAN_TYPE_URI GEN_URI
#define SAN_TYPE_IPV4 254
#define SAN_TYPE_IPV6 255

struct basic_constraints {
	int ca;
	int pathlen;
};

struct subject_alt_name {
	int type;
	char *value;
};

int parse_arg_basic_constraints(const char *arg, struct basic_constraints *opt);
unsigned int parse_arg_key_usage(const char *arg);
unsigned int parse_arg_extended_key_usage(const char *arg);
int parse_arg_subject_alt_name(const char *arg, struct subject_alt_name **list, int *list_num);

int copy_extensions_from_csr(X509 *cert, X509_REQ *csr);
int set_extension_basic_constraints(X509 *cert, struct basic_constraints basic_constraints);
int request_extension_basic_constraints(X509_REQ *csr, struct basic_constraints basic_constraints);
int set_extension_key_usage(X509 *cert, unsigned int key_usage);
int request_extension_key_usage(X509_REQ *csr, unsigned int key_usage);
unsigned int get_extension_key_usage_bit_by_name(const char *name);
int set_extension_extended_key_usage(X509 *cert, unsigned int extended_key_usage);
int request_extension_extended_key_usage(X509_REQ *csr, unsigned int extended_key_usage);
unsigned get_extension_extended_key_usage_bit_by_name(const char *name);
int set_extension_subject_alt_name(X509 *cert, struct subject_alt_name *list,int num);
int set_skid(X509 *cert);
int set_akid_from_x509_skid(X509 *to, X509 *from);

#endif
