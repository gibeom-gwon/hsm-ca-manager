#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "openssl.h"
#include "pkcs11_uri.h"
#include "hexstring.h"

char *arg_pkcs11_uri = NULL;
const char *arg_pkcs11_pin = NULL;
const char *arg_pkcs11_serial = NULL;
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
	if(str == NULL)
		return -1;

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
			return -1;
		}

		if(arg_name_entries == NULL)
		{
			arg_name_entries = x509_name_new();
			if(arg_name_entries == NULL)
			{
				free(str);
				return -1;
			}
		}

		if(x509_name_add_entry(arg_name_entries,field,value) < 0)
		{
			free(str);
			return -1;
		}

		tok = strtok_r(NULL,",",&saveptr1);
	}

	free(str);
	return 0;
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
			"   --id=HEXSTRING                           Id of HSM\n"
			"   --serial=SERIAL                          Serial of HSM\n"
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
	int ret = 0;
	const char *pkcs11_uri_input = NULL;
	const char *pkcs11_id_hexstring = NULL;

	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"pin",required_argument,0,'P'},
		{"id",required_argument,0,'I'},
		{"serial",required_argument,0,'S'},
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
			case 'I':
				pkcs11_id_hexstring = optarg;
				break;
			case 'S':
				arg_pkcs11_serial = optarg;
				break;
			case 'n':
				if(parse_arg_name_entries(optarg) < 0)
				{
					fprintf(stderr,"malformed name entry\n");
					return -1;
				}
				break;
			case 'b':
				if(parse_arg_basic_constraints(optarg,&arg_basic_constraints) < 0)
					return -1;
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
					return -1;
				}
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
		return -1;
	}

	if(arg_pkcs11_pin)
	{
		if((ret = pkcs11_uri_set_pin(pkcs11_uri,arg_pkcs11_pin)) < 0)
		{
			pkcs11_uri_free(pkcs11_uri);
			if(ret == -ENOMEM)
				fprintf(stderr,"Out of memory\n");
			return -1;
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
			return -1;
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
			return -1;
		}
		free(pkcs11_id_uri_encoded);
	}

	if((ret = pkcs11_uri_to_str(pkcs11_uri, &arg_pkcs11_uri)) < 0)
	{
		pkcs11_uri_free(pkcs11_uri);
		if(ret == -ENOMEM)
			fprintf(stderr,"Out of memory\n");
		return -1;
	}

	pkcs11_uri_free(pkcs11_uri);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	ENGINE *hsm = NULL;
	X509_REQ *csr = NULL;
	EVP_PKEY *pubkey = NULL, *privkey = NULL;

	if(set_args(argc,argv) < 0)
		goto fail;

	if((hsm = hsm_init()) == NULL)
		goto openssl_fail;

	if((csr = csr_new()) == NULL)
		goto openssl_fail;

	if((pubkey = get_pubkey_from_hsm(hsm,arg_pkcs11_uri)) == NULL)
		goto openssl_fail;

	if(set_pubkey_to_csr(csr,pubkey) < 0)
		goto openssl_fail;

	if(arg_name_entries == NULL)
	{
		fprintf(stderr,"Subject name is not set\n");
		goto fail;
	}
	if(set_subject_name_to_csr(csr,arg_name_entries) < 0)
		goto openssl_fail;

	if(arg_basic_constraints.ca != -1)
	{
		if(request_extension_basic_constraints(csr,arg_basic_constraints) < 0)
			goto openssl_fail;
	}

	if(arg_key_usage_flag && request_extension_key_usage(csr,arg_key_usage_flag) < 0)
		goto openssl_fail;

	if(arg_extended_key_usage_flag && request_extension_extended_key_usage(csr,arg_extended_key_usage_flag) < 0)
		goto openssl_fail;

	if(arg_subject_alt_name && request_extension_subject_alt_name(csr,arg_subject_alt_name,arg_subject_alt_name_num) < 0)
		goto openssl_fail;

	if((privkey = get_privkey_from_hsm(hsm,arg_pkcs11_uri)) == NULL)
		goto openssl_fail;

	if(sign_csr(csr,privkey) < 0)
		goto openssl_fail;

	if(arg_output != NULL)
	{
		if(export_csr_to_pem_file(arg_output,csr) < 0)
		{
			fprintf(stderr,"Export CSR to file failed\n");
			goto openssl_fail;
		}
	}
	else
	{
		if(print_csr_pem(csr) < 0)
		{
			fprintf(stderr,"CSR PEM print failed\n");
			goto openssl_fail;
		}
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
