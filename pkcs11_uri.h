#ifndef __PKCS11_URI_H__
#define __PKCS11_URI_H__

typedef struct pkcs11_uri PKCS11_URI;

PKCS11_URI *pkcs11_uri_parse(const char *uri_string);
char *pkcs11_uri_to_str(PKCS11_URI *pkcs11);
int pkcs11_uri_set_pin(PKCS11_URI *pkcs11, const char *pin);
void pkcs11_uri_free(PKCS11_URI *pkcs11);

#endif
