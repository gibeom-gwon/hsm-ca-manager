#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "openssl.h"
#include "ip.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 30

const char *arg_pkcs11_uri = NULL;
int arg_expires = 0;
int arg_ignore_requested_extensions = 0;
unsigned int arg_key_usage_flag = 0;
unsigned int arg_extended_key_usage_flag = 0;
const char *arg_csr = NULL;
const char *arg_ca_cert = NULL;
const char *arg_output = NULL;
struct subject_alt_name *arg_subject_alt_name = NULL;
int arg_subject_alt_name_num = 0;

int arg_extension_basic_constraints_bool = -1;
long arg_extension_basic_constraints_pathlen = -1;

int parse_arg_basic_constraints(const char *arg)
{
	if(strcasecmp(arg,"false") == 0)
	{
		arg_extension_basic_constraints_bool = 0;
		arg_extension_basic_constraints_pathlen = -1;
	}
	else if(strcasecmp(arg,"true") >= 0)
	{
		arg_extension_basic_constraints_bool = 1;
		if(arg[4] == 0)
			arg_extension_basic_constraints_pathlen = -1;
		else if(arg[4] == ':')
		{
			const char *pathlen = arg + 5;
			char *endptr = NULL;
			errno = 0;
			arg_extension_basic_constraints_pathlen = strtol(pathlen,&endptr,10);
			if(arg_extension_basic_constraints_pathlen < 0 || errno != 0 || *endptr != 0)
			{
				fprintf(stderr,"Invalid syntax of --basic-constraints argument\n");
				return 0;
			}
		}
	}
	else
	{
		fprintf(stderr,"Invalid syntax of --basic-constraints argument\n");
		return 0;
	}
	return 1;
}

int parse_arg_key_usage(const char *arg)
{
	unsigned int flag = 0;
	char *str = strdup(arg);
	char *tok = strtok(str,",");

	while(tok != NULL)
	{
		int bit = get_extension_key_usage_bit_by_name(tok);
		if(bit == 0)
		{
			fprintf(stderr,"invalid --key-usage argument '%s'.\n",tok);
			free(str);
			return 0;
		}
		flag |= bit;
		tok = strtok(NULL,",");
	}
	free(str);

	arg_key_usage_flag = flag;
	return 1;
}

int parse_arg_extended_key_usage(const char *arg)
{
	unsigned int flag = 0;
	char *str = strdup(arg);
	char *tok = strtok(str,",");

	while(tok != NULL)
	{
		int bit = get_extension_extended_key_usage_bit_by_name(tok);
		if(bit == 0)
		{
			fprintf(stderr,"invalid --extended-key-usage argument '%s'.\n",tok);
			free(str);
			return 0;
		}
		flag |= bit;
		tok = strtok(NULL,",");
	}
	free(str);

	arg_extended_key_usage_flag = flag;
	return 1;
}

int parse_arg_subject_alt_name(const char *arg)
{
	char *str = strdup(arg);
	char *saveptr1 = NULL;
	char *tok = strtok_r(str,",",&saveptr1);
	while(tok != NULL)
	{
		char *saveptr2 = NULL;
		char *type = strtok_r(tok,":",&saveptr2);
		char *value = strtok_r(NULL,"",&saveptr2);
		if(value == NULL)
		{
			free(str);
			return 0;
		}

		void *buff = NULL;
		if(arg_subject_alt_name == NULL)
			buff = malloc(sizeof(struct subject_alt_name));
		else
			buff = realloc(arg_subject_alt_name,sizeof(struct subject_alt_name) * (arg_subject_alt_name_num + 1));

		if(buff == NULL)
		{
			free(str);
			return 0;
		}
		arg_subject_alt_name = buff;
		arg_subject_alt_name_num++;

		struct subject_alt_name *san = &arg_subject_alt_name[arg_subject_alt_name_num - 1];
		san->value = NULL;

		if(strcasecmp(type,"dns") == 0)
		{
			san->type = SAN_TYPE_DNS;
			san->value = strdup(value);
		}
		else if(strcasecmp(type,"EMAIL") == 0)
		{
			san->type = SAN_TYPE_EMAIL;
			san->value = strdup(value);
		}
		else if(strcasecmp(type,"URI") == 0)
		{
			san->type = SAN_TYPE_URI;
			san->value = strdup(value);
		}
		else if(strcasecmp(type,"IP") == 0)
		{
			if(strchr(value,'.'))
			{
				san->type = SAN_TYPE_IPV4;
				san->value = (char*)parse_ipv4(value);
			}
			else if(strchr(value,':'))
			{
				san->type = SAN_TYPE_IPV6;
				san->value = (char*)parse_ipv6(value);
			}
			else
			{
				fprintf(stderr,"invalid IP address syntax\n");
				return 0;
			}

			if(san->value == NULL)
			{
				fprintf(stderr,"invalid IP address syntax\n");
				return 0;
			}
		}
		else
		{
			fprintf(stderr,"unknown subject alt name type '%s'. Supported types: DNS, EMAIL, URI\n",type);
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
	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
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
				arg_ca_cert = optarg;
				break;
			case 'X':
				arg_ignore_requested_extensions = 1;
				break;
			case 'b':
				if(!parse_arg_basic_constraints(optarg))
					return 0;
				break;
			case 'k':
				if(!parse_arg_key_usage(optarg))
					return 0;
				break;
			case 'K':
				if(!parse_arg_extended_key_usage(optarg))
					return 0;
				break;
			case 's':
				if(!parse_arg_subject_alt_name(optarg))
					return 0;
				break;
			case 'r':
				if(!parse_arg_basic_constraints("True"))
					return 0;
				if(!parse_arg_key_usage("keyCertSign,cRLSign"))
					return 0;
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
				return 0;
		}
	}

	if(arg_pkcs11_uri == NULL)
		arg_pkcs11_uri = PKCS11_URI;
	if(arg_expires < 1)
		arg_expires = DAYS_AFTER_EXPIRE;

	if(arg_csr == NULL)
	{
		fprintf(stderr,"--csr option required\n");
		return 0;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	X509 *ca_cert = NULL, *result_cert = NULL;
	X509_REQ *cert_req = NULL;
	ENGINE *hsm = NULL;
	EVP_PKEY *privkey = NULL;

	if(!set_args(argc,argv))
		goto fail;

	if((hsm = hsm_init()) == NULL)
		goto openssl_fail;

	if((result_cert = x509_new()) == NULL)
		goto openssl_fail;

	if((cert_req = load_csr(arg_csr)) == NULL)
		goto openssl_fail;

	if(!verify_csr(cert_req))
		goto openssl_fail;

	if(arg_ca_cert != NULL && (ca_cert = load_x509(arg_ca_cert)) == NULL)
		goto openssl_fail;

	if(!set_version3(result_cert))
		goto openssl_fail;

	if(!set_random_serialNumber(result_cert))
		goto openssl_fail;

	if(!set_subject_name_from_csr(result_cert,cert_req))
		goto openssl_fail;

	if(ca_cert != NULL)
	{
		if(!set_issuer_name_from_x509(result_cert,ca_cert))
			goto openssl_fail;
	}
	else
	{
		if(!set_issuer_name_from_x509(result_cert,result_cert))
			goto openssl_fail;
	}

	if(!set_expire_date(result_cert,arg_expires))
		goto openssl_fail;

	if(!copy_pubkey_from_csr(result_cert,cert_req))
		goto openssl_fail;

	if(!arg_ignore_requested_extensions && !copy_extensions_from_csr(result_cert,cert_req))
		goto openssl_fail;

	if(arg_extension_basic_constraints_bool != -1)
	{
		if(!set_extension_basic_constraints(result_cert,arg_extension_basic_constraints_bool,arg_extension_basic_constraints_pathlen))
			goto openssl_fail;
	}

	if(arg_key_usage_flag && !set_extension_key_usage(result_cert,arg_key_usage_flag))
		goto openssl_fail;

	if(arg_extended_key_usage_flag && !set_extension_extended_key_usage(result_cert,arg_extended_key_usage_flag))
		goto openssl_fail;

	if(arg_subject_alt_name && !set_extension_subject_alt_name(result_cert,arg_subject_alt_name,arg_subject_alt_name_num))
		goto openssl_fail;

	if(!set_skid(result_cert))
		goto openssl_fail;

	if(ca_cert != NULL && !set_akid_from_x509_skid(result_cert,ca_cert))
		goto openssl_fail;

	privkey = get_privkey_from_hsm(hsm,arg_pkcs11_uri);
	if(privkey == NULL)
		goto openssl_fail;

	if(!sign_x509(result_cert,privkey))
		goto openssl_fail;

	if(arg_output != NULL)
	{
		if(!export_x509_to_pem_file(arg_output,result_cert))
			goto openssl_fail;
	}
	else
	{
		if(!print_x509_pem(result_cert))
			goto openssl_fail;
	}

	cleanup:
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
	fail:
	ret = -1;
	goto cleanup;
}
