#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "openssl.h"
#include "pkcs11_uri.h"
#include "hexstring.h"

#define DAYS_AFTER_EXPIRE 30

char *arg_pkcs11_uri = NULL;
const char *arg_pkcs11_pin = NULL;
const char *arg_pkcs11_serial = NULL;
int arg_expires = 0;
int arg_ignore_requested_extensions = 0;
unsigned int arg_key_usage_flag = 0;
unsigned int arg_extended_key_usage_flag = 0;
const char *arg_csr = NULL;
const char *arg_ca_cert = NULL;
const char *arg_output = NULL;
struct subject_alt_name *arg_subject_alt_name = NULL;
int arg_subject_alt_name_num = 0;

struct basic_constraints arg_basic_constraints = { .ca = -1, .pathlen = -1 };

void print_help(const char *exec_name)
{
	const char *basename = strrchr(exec_name,'/');
	if(basename)
		basename++;
	else
		basename = exec_name;

	printf( "Usage: %s [OPTIONS...]\n\n"
			"Options:\n"
			"-p --pkcs11-uri=PKCS11_URI                  PKCS11 URI of HSM\n"
			"   --pin=PIN                                Pin of HSM\n"
			"   --id=HEXSTRING                           Id of HSM\n"
			"   --serial=SERIAL                          Serial of HSM\n"
			"-e --expires=DAYS                           Expire certificate after DAYS days\n"
			"-c --ca-cert=CA_CERT_PATH                   PEM certificate file path of CA. If not set,\n"
			"                                            create self signed certificate\n"
			"-X                                          Ignore requested extensions\n"
			"   --basic-constraints=True[:PATHLEN]|False Add basic constraints extension\n"
			"   --key-usage=KEY_USAGE_TYPE[,KEY_USAGE_TYPE]\n"
			"                                            Add key usage extension\n"
			"   --extended-key-usage=KEY_USAGE_TYPE[,KEY_USAGE_TYPE]\n"
			"                                            Add extended key usage extension\n"
			"   --subject-alt-name=TYPE:ALT_NAME[,TYPE:ALT_NAME]\n"
			"                                            Add subject alt name extension\n"
			"   --root-ca-ext                            Shortcut of --basic-constraints=True\n"
			"                                            --key-usage=keyCertSign,cRLSign option\n"
			"-i --csr=CSR_PATH                           CSR file path\n"
			"-o --output=CERT_PATH                       Certificate output path. If not set, print to stdin\n"
			"-h --help                                   Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	int ret = 0;
	const char *pkcs11_uri_input = NULL;
	const char *pkcs11_id_hexstring = NULL;

	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"pin",required_argument,0,'P'},
		{"id",required_argument,0,'I'},
		{"serial",required_argument,0,'S'},
		{"expires",required_argument,0,'e'},
		{"ca-cert",required_argument,0,'c'},
		{"basic-constraints",required_argument,0,'b'},
		{"key-usage",required_argument,0,'k'},
		{"extended-key-usage",required_argument,0,'K'},
		{"subject-alt-name",required_argument,0,'s'},
		{"root-ca-ext",no_argument,0,'r'},
		{"csr",required_argument,0,'i'},
		{"output",required_argument,0,'o'},
		{"help",no_argument,0,'h'},
		{NULL,0,0,0}
	};

	int opt_idx = 0;
	int r = 0;
	while((r = getopt_long(argc,argv,"p:e:c:Xi:o:h",opts,&opt_idx)) > 0)
	{
		switch(r)
		{
			case 'p':
				pkcs11_uri_input = optarg;
				break;
			case 'P':
				arg_pkcs11_pin = optarg;
				break;
			case 'I':
				pkcs11_id_hexstring = optarg;
				break;
			case 'S':
				arg_pkcs11_serial = optarg;
				break;
			case 'e':
				arg_expires = atoi(optarg);
				if(arg_expires < 1)
					return -1;
				break;
			case 'c':
				arg_ca_cert = optarg;
				break;
			case 'X':
				arg_ignore_requested_extensions = 1;
				break;
			case 'b':
				if((ret = parse_arg_basic_constraints(optarg,&arg_basic_constraints)) < 0)
					return ret;
				break;
			case 'k':
				int key_usage_flag = 0;
				if(!(key_usage_flag = parse_arg_key_usage(optarg)))
					return -1;
				arg_key_usage_flag |= key_usage_flag;
				break;
			case 'K':
				int extended_key_usage_flag = 0;
				if(!(extended_key_usage_flag = parse_arg_extended_key_usage(optarg)))
					return -1;
				arg_extended_key_usage_flag |= extended_key_usage_flag;
				break;
			case 's':
				if((ret = parse_arg_subject_alt_name(optarg,&arg_subject_alt_name,&arg_subject_alt_name_num)) < 0)
				{
					switch(ret)
					{
						case -ENOMEM:
							fprintf(stderr,"Out of memory\n");
						break;
						case -EINVAL:
							fprintf(stderr,"Invalid IP address\n");
						break;
						case -EBADR:
							fprintf(stderr,"Unknown subject alt name type\n");
						break;
					}
					return ret;
				}
				break;
			case 'r':
				if((ret = parse_arg_basic_constraints("True",&arg_basic_constraints)) < 0)
					return ret;
				if(!(key_usage_flag = parse_arg_key_usage("keyCertSign,cRLSign")))
					return -1;
				arg_key_usage_flag |= key_usage_flag;
				break;
			case 'i':
				arg_csr = optarg;
				break;
			case 'o':
				arg_output = optarg;
				break;
			case 'h':
				print_help(argv[0]);
			case '?':
			default:
				return -1;
		}
	}

	if(arg_pkcs11_pin == NULL)
		arg_pkcs11_pin = getenv("PKCS11_PIN");

	if(arg_pkcs11_serial == NULL)
		arg_pkcs11_serial = getenv("PKCS11_SERIAL");

	if(pkcs11_uri_input == NULL)
		pkcs11_uri_input = getenv("PKCS11_URI");

	if(pkcs11_uri_input == NULL)
		pkcs11_uri_input = "pkcs11:";

	PKCS11_URI *pkcs11_uri = NULL;
	if((ret = pkcs11_uri_parse(pkcs11_uri_input, &pkcs11_uri)) < 0)
	{
		switch(ret)
		{
			case -ENOMEM:
				fprintf(stderr,"Out of memory\n");
				break;
			case -EINVAL:
				fprintf(stderr,"Invalid PKCS11 URI input\n");
				break;
			case -EEXIST:
				fprintf(stderr,"Duplicated path attribute\n");
				break;
		}
		return ret;
	}

	if(arg_pkcs11_pin)
	{
		if((ret = pkcs11_uri_set_pin(pkcs11_uri,arg_pkcs11_pin)) < 0)
		{
			pkcs11_uri_free(pkcs11_uri);
			if(ret == -ENOMEM)
				fprintf(stderr,"Out of memory\n");
			return ret;
		}
	}

	if(arg_pkcs11_serial)
	{
		if((ret = pkcs11_uri_set_serial(pkcs11_uri,arg_pkcs11_serial)) < 0)
		{
			pkcs11_uri_free(pkcs11_uri);
			switch(ret)
			{
				case -ENOMEM:
					fprintf(stderr,"Out of memory\n");
					break;
				case -EEXIST:
					fprintf(stderr,"Duplicated serial path attribute\n");
					break;
			}
			return ret;
		}
	}

	if(pkcs11_id_hexstring == NULL)
		pkcs11_id_hexstring = getenv("PKCS11_ID");

	if(pkcs11_id_hexstring)
	{
		if(!is_hexstring(pkcs11_id_hexstring))
		{
			fprintf(stderr,"Invalid PKCS11 id hexstring\n");
			pkcs11_uri_free(pkcs11_uri);
			return -1;
		}
		char *pkcs11_id_uri_encoded = hexstring_to_uri_encoded(pkcs11_id_hexstring);
		if(pkcs11_id_uri_encoded == NULL)
		{
			pkcs11_uri_free(pkcs11_uri);
			return -1;
		}
		if((ret = pkcs11_uri_set_id(pkcs11_uri,pkcs11_id_uri_encoded)) < 0)
		{
			free(pkcs11_id_uri_encoded);
			pkcs11_uri_free(pkcs11_uri);
			switch(ret)
			{
				case -ENOMEM:
					fprintf(stderr,"Out of memory\n");
					break;
				case -EEXIST:
					fprintf(stderr,"Duplicated id path attribute\n");
					break;
			}
			return ret;
		}
		free(pkcs11_id_uri_encoded);
	}

	if((ret = pkcs11_uri_to_str(pkcs11_uri, &arg_pkcs11_uri)) < 0)
	{
		pkcs11_uri_free(pkcs11_uri);
		if(ret == -ENOMEM)
			fprintf(stderr,"Out of memory\n");
		return ret;
	}

	pkcs11_uri_free(pkcs11_uri);

	if(arg_expires < 1)
		arg_expires = DAYS_AFTER_EXPIRE;

	if(arg_csr == NULL)
	{
		fprintf(stderr,"--csr option required\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	X509 *ca_cert = NULL, *result_cert = NULL;
	X509_REQ *cert_req = NULL;
	ENGINE *hsm = NULL;
	EVP_PKEY *privkey = NULL;

	if((ret = set_args(argc,argv)) < 0)
		goto cleanup;

	if((hsm = hsm_init()) == NULL)
	{
		ret = -1;
		goto openssl_fail;
	}

	if((result_cert = x509_new()) == NULL)
	{
		ret = -1;
		goto openssl_fail;
	}

	if((cert_req = load_csr(arg_csr)) == NULL)
	{
		ret = -1;
		goto openssl_fail;
	}

	if((ret = verify_csr(cert_req)) < 0)
		goto openssl_fail;

	if(arg_ca_cert != NULL && (ca_cert = load_x509(arg_ca_cert)) == NULL)
	{
		ret = -1;
		goto openssl_fail;
	}

	if((ret = set_version3(result_cert)) < 0)
		goto openssl_fail;

	if((ret = set_random_serialNumber(result_cert)) < 0)
		goto openssl_fail;

	if((ret = set_subject_name_from_csr(result_cert,cert_req)) < 0)
		goto openssl_fail;

	if(ca_cert != NULL)
	{
		if((ret = set_issuer_name_from_x509(result_cert,ca_cert)) < 0)
			goto openssl_fail;
	}
	else
	{
		if((ret = set_issuer_name_from_x509(result_cert,result_cert)) < 0)
			goto openssl_fail;
	}

	if((ret = set_expire_date(result_cert,arg_expires)) < 0)
		goto openssl_fail;

	if((ret = copy_pubkey_from_csr(result_cert,cert_req)) < 0)
		goto openssl_fail;

	if(!arg_ignore_requested_extensions && (ret = copy_extensions_from_csr(result_cert,cert_req)) < 0)
		goto openssl_fail;

	if(arg_basic_constraints.ca != -1)
	{
		if((ret = set_extension_basic_constraints(result_cert,arg_basic_constraints)) < 0)
			goto openssl_fail;
	}

	if(arg_key_usage_flag && (ret = set_extension_key_usage(result_cert,arg_key_usage_flag)) < 0)
		goto openssl_fail;

	if(arg_extended_key_usage_flag && (ret = set_extension_extended_key_usage(result_cert,arg_extended_key_usage_flag)) < 0)
		goto openssl_fail;

	if(arg_subject_alt_name && (ret = set_extension_subject_alt_name(result_cert,arg_subject_alt_name,arg_subject_alt_name_num)) < 0)
		goto openssl_fail;

	if((ret = set_skid(result_cert)) < 0)
		goto openssl_fail;

	if(ca_cert != NULL && (ret = set_akid_from_x509_skid(result_cert,ca_cert)) < 0)
		goto openssl_fail;

	privkey = get_privkey_from_hsm(hsm,arg_pkcs11_uri);
	if(privkey == NULL)
	{
		ret = -1;
		goto openssl_fail;
	}

	if((ret = sign_x509(result_cert,privkey)) < 0)
		goto openssl_fail;

	if(arg_output != NULL)
	{
		if((ret = export_x509_to_pem_file(arg_output,result_cert)) < 0)
		{
			fprintf(stderr,"Export certificate to file failed\n");
			goto openssl_fail;
		}
	}
	else
	{
		if((ret = print_x509_pem(result_cert)) < 0)
		{
			fprintf(stderr,"Certificate PEM print failed\n");
			goto openssl_fail;
		}
	}

	cleanup:
	if(arg_pkcs11_uri)
		free(arg_pkcs11_uri);
	if(arg_subject_alt_name)
	{
		for(int i = 0;i < arg_subject_alt_name_num;i++)
			if(arg_subject_alt_name[i].value != NULL)
				free(arg_subject_alt_name[i].value);
		free(arg_subject_alt_name);
	}
	if(cert_req)
		csr_free(cert_req);
	if(privkey)
		key_free(privkey);
	if(hsm)
		hsm_free(hsm);
	if(ca_cert)
		x509_free(ca_cert);
	if(result_cert)
		x509_free(result_cert);
	return ret;

	openssl_fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	goto cleanup;
}
