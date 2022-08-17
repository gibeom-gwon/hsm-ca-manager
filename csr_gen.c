#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "openssl.h"
#include "pkcs11_uri.h"

#define PKCS11_URI_DEFAULT "pkcs11:manufacturer=www.CardContact.de;id=%10"

char *arg_pkcs11_uri = NULL;
const char *arg_pkcs11_pin = NULL;
X509_NAME *arg_name_entries = NULL;
const char *arg_output = NULL;

struct basic_constraints arg_basic_constraints = { .ca = -1, .pathlen = -1 };
unsigned int arg_key_usage_flag = 0;
unsigned int arg_extended_key_usage_flag = 0;
struct subject_alt_name *arg_subject_alt_name = NULL;
int arg_subject_alt_name_num = 0;

int parse_arg_name_entries(char *arg)
{
	char *str = strdup(arg);
	char *saveptr1 = NULL;
	char *tok = strtok_r(str,",",&saveptr1);
	while(tok != NULL)
	{
		char *saveptr2 = NULL;
		char *field = strtok_r(tok,":",&saveptr2);
		char *value = strtok_r(NULL,"",&saveptr2);
		if(value == NULL)
		{
			free(str);
			return 0;
		}

		if(arg_name_entries == NULL)
		{
			arg_name_entries = x509_name_new();
			if(arg_name_entries == NULL)
			{
				free(str);
				return 0;
			}
		}

		if(!x509_name_add_entry(arg_name_entries,field,value))
		{
			free(str);
			return 0;
		}

		tok = strtok_r(NULL,",",&saveptr1);
	}

	free(str);

	return 1;
}

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
			"-n --name=TYPE:VALUE[,TYPE:VALUE]           Set certificate subject name\n"
			"   --basic-constraints=True[:PATHLEN]|False Add basic constraints extension\n"
			"   --key-usage=KEY_USAGE_TYPE[,KEY_USAGE_TYPE]\n"
			"                                            Add key usage extension\n"
			"   --extended-key-usage=KEY_USAGE_TYPE[,KEY_USAGE_TYPE]\n"
			"                                            Add extended key usage extension\n"
			"   --subject-alt-name=TYPE:ALT_NAME[,TYPE:ALT_NAME]\n"
			"                                            Add subject alt name extension\n"
			"-o --output=CSR_PATH                        Certificate request output path. If not set, print to stdin\n"
			"-h --help                                   Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	const char *pkcs11_uri_input = NULL;

	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"pin",required_argument,0,'P'},
		{"name",required_argument,0,'n'},
		{"basic-constraints",required_argument,0,'b'},
		{"key-usage",required_argument,0,'k'},
		{"extended-key-usage",required_argument,0,'K'},
		{"subject-alt-name",required_argument,0,'s'},
		{"output",required_argument,0,'o'},
		{"help",no_argument,0,'h'},
		{NULL,0,0,0}
	};

	int opt_idx = 0;
	int r = 0;
	while((r = getopt_long(argc,argv,"p:n:o:h",opts,&opt_idx)) > 0)
	{
		switch(r)
		{
			case 'p':
				pkcs11_uri_input = optarg;
				break;
			case 'P':
				arg_pkcs11_pin = optarg;
				break;
			case 'n':
				if(!parse_arg_name_entries(optarg))
				{
					fprintf(stderr,"malformed name entry\n");
					return 0;
				}
				break;
			case 'b':
				if(!parse_arg_basic_constraints(optarg,&arg_basic_constraints))
					return 0;
				break;
			case 'k':
				int key_usage_flag = 0;
				if(!(key_usage_flag = parse_arg_key_usage(optarg)))
					return 0;
				arg_key_usage_flag |= key_usage_flag;
				break;
			case 'K':
				int extended_key_usage_flag = 0;
				if(!(extended_key_usage_flag = parse_arg_extended_key_usage(optarg)))
					return 0;
				arg_extended_key_usage_flag |= extended_key_usage_flag;
				break;
			case 's':
				if(!parse_arg_subject_alt_name(optarg,&arg_subject_alt_name,&arg_subject_alt_name_num))
					return 0;
				break;
			case 'o':
				arg_output = optarg;
				break;
			case 'h':
				print_help(argv[0]);
			case '?':
			default:
				return 0;
		}
	}

	if(arg_pkcs11_pin == NULL)
		arg_pkcs11_pin = getenv("PKCS11_PIN");

	if(pkcs11_uri_input == NULL)
		pkcs11_uri_input = getenv("PKCS11_URI");

	if(pkcs11_uri_input == NULL)
		pkcs11_uri_input = PKCS11_URI_DEFAULT;

	PKCS11_URI *pkcs11_uri = pkcs11_uri_parse(pkcs11_uri_input);
	if(pkcs11_uri == NULL)
		return 0;

	if(arg_pkcs11_pin)
	{
		if(!pkcs11_uri_set_pin(pkcs11_uri,arg_pkcs11_pin))
			return 0;
	}

	arg_pkcs11_uri = pkcs11_uri_to_str(pkcs11_uri);
	if(arg_pkcs11_uri == NULL)
		return 0;

	pkcs11_uri_free(pkcs11_uri);
	return 1;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	ENGINE *hsm = NULL;
	X509_REQ *csr = NULL;
	EVP_PKEY *pubkey = NULL, *privkey = NULL;

	if(!set_args(argc,argv))
		goto fail;

	if((hsm = hsm_init()) == NULL)
		goto openssl_fail;

	if((csr = csr_new()) == NULL)
		goto openssl_fail;

	if((pubkey = get_pubkey_from_hsm(hsm,arg_pkcs11_uri)) == NULL)
		goto openssl_fail;

	if(!set_pubkey_to_csr(csr,pubkey))
		goto openssl_fail;

	if(arg_name_entries == NULL)
	{
		fprintf(stderr,"Subject name is not set\n");
		goto fail;
	}
	if(!set_subject_name_to_csr(csr,arg_name_entries))
		goto openssl_fail;

	if(arg_basic_constraints.ca != -1)
	{
		if(!request_extension_basic_constraints(csr,arg_basic_constraints))
			goto openssl_fail;
	}

	if(arg_key_usage_flag && !request_extension_key_usage(csr,arg_key_usage_flag))
		goto openssl_fail;

	if(arg_extended_key_usage_flag && !request_extension_extended_key_usage(csr,arg_extended_key_usage_flag))
		goto openssl_fail;

	if(arg_subject_alt_name && !request_extension_subject_alt_name(csr,arg_subject_alt_name,arg_subject_alt_name_num))
		goto openssl_fail;

	if((privkey = get_privkey_from_hsm(hsm,arg_pkcs11_uri)) == NULL)
		goto openssl_fail;

	if(!sign_csr(csr,privkey))
		goto openssl_fail;

	if(arg_output != NULL)
	{
		if(!export_csr_to_pem_file(arg_output,csr))
			goto openssl_fail;
	}
	else
	{
		if(!print_csr_pem(csr))
			goto openssl_fail;
	}

	cleanup:
	if(arg_pkcs11_uri)
		free(arg_pkcs11_uri);
	if(arg_name_entries)
		x509_name_free(arg_name_entries);
	if(pubkey)
		key_free(pubkey);
	if(privkey)
		key_free(privkey);
	if(csr)
		csr_free(csr);
	if(hsm)
		hsm_free(hsm);
	return ret;
	openssl_fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	fail:
	ret = -1;
	goto cleanup;
}
