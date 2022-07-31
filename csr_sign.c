#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "openssl.h"

#define PKCS11_URI "pkcs11:manufacturer=www.CardContact.de;id=%10"
#define DAYS_AFTER_EXPIRE 30

const char *arg_pkcs11_uri = NULL;
int arg_expires = 0;
int arg_ignore_requested_extensions = 0;
unsigned int arg_key_usage_flag = 0;
const char *arg_csr = NULL;
const char *arg_ca_cert = NULL;
const char *arg_output = NULL;

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

void print_help(const char *exec_name)
{
	const char *basename = strrchr(exec_name,'/');
	if(basename)
		basename++;
	else
		basename = exec_name;

	printf( "Usage: %s [OPTIONS...]\n\n"
			"Options:\n"
			"-p --pkcs11-uri=PKCS11_URI                     PKCS11 URI of HSM\n"
			"-e --expires=DAYS                              Expire certificate after DAYS days\n"
			"-c --ca-cert=CA_CERT_PATH                      PEM certificate file path of CA. If not set,\n"
			"                                               create self signed certificate\n"
			"-X                                             Ignore requested extensions\n"
			"   --basic-constraints=True[:PATHLEN]|False    Add basic constraints extension\n"
			"   --key-usage=KEY_USAGE_TYPE[,KEY_USAGE_TYPE] Add basic constraints extension\n"
			"-i --csr=CSR_PATH                              CSR file path\n"
			"-o --output=CERT_PATH                          Certificate output path. If not set, print to stdin\n"
			"-h --help                                      Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"expires",required_argument,0,'e'},
		{"ca-cert",required_argument,0,'c'},
		{"basic-constraints",required_argument,0,'b'},
		{"key-usage",required_argument,0,'k'},
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

	if(!set_args(argc,argv))
		return -1;

	X509 *ca_cert = NULL, *result_cert = NULL;
	X509_REQ *cert_req = NULL;
	ENGINE *engine = NULL;
	EVP_PKEY *privkey = NULL;

	if(!init_crypto_with_dynamic_engine())
		goto fail;

	if((result_cert = x509_new()) == NULL)
		goto fail;

	if((engine = init_pkcs11_engine()) == NULL)
		goto fail;

	if((cert_req = load_csr(arg_csr)) == NULL)
		goto fail;

	if(arg_ca_cert != NULL && (ca_cert = load_x509(arg_ca_cert)) == NULL)
		goto fail;

	if(!set_version3(result_cert))
		goto fail;

	if(!set_subject_name_from_csr(result_cert,cert_req))
		goto fail;

	if(ca_cert != NULL)
	{
		if(!set_issuer_name_from_x509(result_cert,ca_cert))
			goto fail;
	}
	else
	{
		if(!set_issuer_name_from_x509(result_cert,result_cert))
			goto fail;
	}

	if(!set_expire_date(result_cert,arg_expires))
		goto fail;

	if(!copy_pubkey_from_csr(result_cert,cert_req))
		goto fail;

	if(!arg_ignore_requested_extensions && !copy_extensions_from_csr(result_cert,cert_req))
		goto fail;

	if(arg_extension_basic_constraints_bool != -1)
	{
		if(set_extension_basic_constraints(result_cert,arg_extension_basic_constraints_bool,arg_extension_basic_constraints_pathlen))
			goto fail;
	}

	if(arg_key_usage_flag && !set_extension_key_usage(result_cert,arg_key_usage_flag))
		goto fail;

	if(!set_skid(result_cert))
		goto fail;

	if(ca_cert != NULL && !set_akid_from_x509_skid(result_cert,ca_cert))
		goto fail;

	privkey = get_privkey_from_pkcs11(engine,arg_pkcs11_uri);
	if(privkey == NULL)
		goto fail;

	if(!sign_x509(result_cert,privkey))
		goto fail;

	if(arg_output != NULL)
	{
		if(!export_x509_to_pem_file(arg_output,result_cert))
			goto fail;
	}
	else
	{
		if(!print_x509_pem(result_cert))
			goto fail;
	}

	cleanup:
	if(cert_req)
		csr_free(cert_req);
	if(privkey)
		key_free(privkey);
	if(engine)
		engine_free(engine);
	if(ca_cert)
		x509_free(ca_cert);
	if(result_cert)
		x509_free(result_cert);
	return ret;

	fail:
	fprintf(stderr,"openssl error: %s\n",ssl_get_error_string());
	ret = -1;
	goto cleanup;
}

	/*
	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if(!akid)
		goto fail;
	akid->keyid = ASN1_STRING_new();
	if(!akid->keyid)
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	if(!ASN1_STRING_set(akid->keyid,pubkey_hash,SHA_DIGEST_LENGTH))
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	if(X509_add1_ext_i2d(cert,NID_authority_key_identifier,akid,0,0) < 1)
	{
		AUTHORITY_KEYID_free(akid);
		goto fail;
	}
	AUTHORITY_KEYID_free(akid);
	*/

	/*
	ASN1_OBJECT *obj;
	EXTENDED_KEY_USAGE* extku = EXTENDED_KEY_USAGE_new();
	obj = OBJ_nid2obj(NID_server_auth);
	sk_ASN1_OBJECT_push(extku,obj);
	obj = OBJ_nid2obj(NID_client_auth);
	sk_ASN1_OBJECT_push(extku,obj);
	X509_add1_ext_i2d(cert,NID_ext_key_usage,extku,0,0);
	EXTENDED_KEY_USAGE_free(extku);
	*/
