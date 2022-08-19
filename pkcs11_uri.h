#ifndef __PKCS11_URI_H__
#define __PKCS11_URI_H__

typedef struct pkcs11_uri PKCS11_URI;

int pkcs11_uri_parse(const char *uri_string, PKCS11_URI **pkcs11_out);
int pkcs11_uri_to_str(PKCS11_URI *pkcs11, char **str_out);
int pkcs11_uri_set_pin(PKCS11_URI *pkcs11, const char *pin);
int pkcs11_uri_set_id(PKCS11_URI *pkcs11, const char *id);
int pkcs11_uri_set_serial(PKCS11_URI *pkcs11, const char *serial);
void pkcs11_uri_free(PKCS11_URI *pkcs11);

#endif
