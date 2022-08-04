#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "openssl.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"

const char *arg_pkcs11_uri = NULL;
X509_NAME *arg_name_entries = NULL;
const char *arg_output = NULL;

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
			"-p --pkcs11-uri=PKCS11_URI        PKCS11 URI of HSM\n"
			"-n --name=TYPE:VALUE[,TYPE:VALUE] Set certificate subject name\n"
			"-o --output=CSR_PATH              Certificate request output path. If not set, print to stdin\n"
			"-h --help                         Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"name",required_argument,0,'n'},
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
				arg_pkcs11_uri = optarg;
				if(strncmp(arg_pkcs11_uri,"pkcs11:",7) != 0)
				{
					fprintf(stderr,"malformed pkcs11 URI\n");
					return 0;
				}
				break;
			case 'n':
				if(!parse_arg_name_entries(optarg))
				{
					fprintf(stderr,"malformed name entry\n");
					return 0;
				}
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

	if(arg_pkcs11_uri == NULL)
		arg_pkcs11_uri = PKCS11_URI;

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

	if(!set_subject_name_to_csr(csr,arg_name_entries))
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
