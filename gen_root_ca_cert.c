#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "openssl.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 100

#define CERT_C "KR"
#define CERT_O "test org"
#define CERT_CN "test root CA"

const char *arg_pkcs11_uri = NULL;
int arg_expires = 0;
const char *arg_C = NULL;
const char *arg_O = NULL;
const char *arg_OU = NULL;
const char *arg_CN = NULL;

void print_help(const char *exec_name)
{
	const char *basename = strrchr(exec_name,'/');
	if(basename)
		basename++;
	else
		basename = exec_name;

	printf( "Usage: %s [OPTIONS...]\n\n"
			"Options:\n"
			"-p --pkcs11-uri=PKCS11_URI PKCS11 URI of HSM\n"
			"-e --expires=DAYS          Expire certificate after DAYS days\n"
			"--C=C                      Country code of the certificate\n"
			"--O=O                      Organization of the certificate\n"
			"--OU=OU                    Organization Unit of the certificate\n"
			"--CN=CN                    Canonical Name of the certificate\n"
			"-h --help                  Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"expires",required_argument,0,'e'},
		{"C",required_argument,0,'c'},
		{"O",required_argument,0,'o'},
		{"OU",required_argument,0,'O'},
		{"CN",required_argument,0,'n'},
		{"help",no_argument,0,'h'},
		{NULL,0,0,0}
	};

	int opt_idx = 0;
	int r = 0;
	while((r = getopt_long(argc,argv,"p:e:h",opts,&opt_idx)) > 0)
	{
		switch(r)
		{
			case 'p':
				arg_pkcs11_uri = optarg;
				if(strncmp(arg_pkcs11_uri,"pkcs11:",7) != 0)
				{
					fprintf(stderr,"malformed pkcs11 URI\n");
					return 0;
				}
				break;
			case 'e':
				arg_expires = atoi(optarg);
				if(arg_expires < 1)
					return 0;
				break;
			case 'c':
				arg_C = optarg;
				break;
			case 'o':
				arg_O = optarg;
				break;
			case 'O':
				arg_OU = optarg;
				break;
			case 'n':
				arg_CN = optarg;
				break;
			case 'h':
				print_help(argv[0]);
				return 0;
			case '?':
			default:
				return 0;
		}
		if(r == '?')
			return 0;
	}

	if(arg_pkcs11_uri == NULL)
		arg_pkcs11_uri = PKCS11_URI;
	if(arg_expires < 1)
		arg_expires = DAYS_AFTER_EXPIRE;
	if(arg_CN == NULL)
		arg_CN = CERT_CN;

	return 1;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if(!set_args(argc,argv))
		return -1;

	X509 *cert = NULL;
	ENGINE *engine = NULL;
	EVP_PKEY *pubkey = NULL,*privkey = NULL;

	if(!init_crypto_with_dynamic_engine())
		goto fail;

	if((cert = x509_new()) == NULL)
		goto fail;

	if((engine = init_pkcs11_engine()) == NULL)
		goto fail;

	if((pubkey = get_pubkey_from_pkcs11(engine,arg_pkcs11_uri)) == NULL)
		goto fail;

	if(!set_version3(cert))
		goto fail;

	if(!set_serialNumber(cert,1))
		goto fail;

	if(!set_expire_date(cert,arg_expires))
		goto fail;

	if(!set_pubkey(cert,pubkey))
		goto fail;

	X509_NAME *name = set_subject_name(cert,arg_C,arg_O,arg_OU,arg_CN);
	if(!name)
		goto fail;
	if(!set_issuer_name(cert,name))
		goto fail;

	if(!set_skid(cert))
		goto fail;

	if(!set_extension_basic_constraints(cert,1))
		goto fail;

	if(!set_extension_key_usage(cert,KEY_USAGE_KEY_CERT_SIGN|KEY_USAGE_CRL_SIGN))
		goto fail;

	privkey = get_privkey_from_pkcs11(engine,arg_pkcs11_uri);
	if(privkey == NULL)
		goto fail;

	if(!sign_x509(cert,privkey))
		goto fail;

	if(!export_x509_to_der_file("root_ca.der",cert))
		goto fail;

	if(!export_x509_to_pem_file("root_ca.pem",cert))
		goto fail;

	cleanup:
	if(privkey)
		key_free(privkey);
	if(pubkey)
		key_free(pubkey);
	if(engine)
		engine_free(engine);
	if(cert)
		x509_free(cert);
	return ret;

	fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	ret = -1;
	goto cleanup;
}
