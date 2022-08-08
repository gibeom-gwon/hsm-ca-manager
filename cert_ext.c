#include <string.h>
#include <errno.h>
#include "cert_ext.h"

struct key_usage_type {
	unsigned int bit;
	const char* name;
};

static struct key_usage_type key_usage_list[] = {
	{1 << 0,"digitalSignature"},
	{1 << 1,"nonRepudiation"},
	{1 << 1,"contentCommitment"}, // renamed
	{1 << 2,"keyEncipherment"},
	{1 << 3,"dataEncipherment"},
	{1 << 4,"keyAgreement"},
	{1 << 5,"keyCertSign"},
	{1 << 6,"cRLSign"},
	{1 << 7,"encipherOnly"},
	{1 << 8,"decipherOnly"},
};

static const int key_usage_list_num = sizeof(key_usage_list) / sizeof(struct key_usage_type);

static struct key_usage_type extended_key_usage_list[] = {
	{1 << 0,"serverAuth"},
	{1 << 1,"clientAuth"},
	{1 << 2,"codeSigning"},
	{1 << 3,"emailProtection"},
	{1 << 4,"timeStamping"},
	{1 << 5,"OCSPSigning"},
};

static const int extended_key_usage_list_num = sizeof(extended_key_usage_list) / sizeof(struct key_usage_type);

int parse_arg_basic_constraints(const char *arg, struct basic_constraints *opt)
{
	if(strcasecmp(arg,"false") == 0)
	{
		opt->ca = 0;
		opt->pathlen = -1;
	}
	else if(strcasecmp(arg,"true") >= 0)
	{
		opt->ca = 1;
		if(arg[4] == 0)
			opt->pathlen = -1;
		else if(arg[4] == ':')
		{
			const char *pathlen = arg + 5;
			char *endptr = NULL;
			errno = 0;
			opt->pathlen = strtol(pathlen,&endptr,10);
			if(opt->pathlen < 0 || errno != 0 || *endptr != 0)
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

	return flag;
}

int copy_extensions_from_csr(X509 *cert, X509_REQ *csr)
{
	const X509_EXTENSIONS *req_extensions = X509_REQ_get_extensions(csr);
	int extension_num = sk_X509_EXTENSION_num(req_extensions);
	int *extension_nid_list = malloc(sizeof(int) * extension_num);

	for(int i = 0;i < extension_num;i++)
	{
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(req_extensions,i);
		int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
		extension_nid_list[i] = nid;
	}

	for(int i = 0;i < extension_num;i++)
	{
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(req_extensions,i);
		for(int j = i + 1;j < extension_num;j++)
		{
			if(extension_nid_list[i] == extension_nid_list[j])
				return 0;
		}
		if(!X509_add_ext(cert,ext,-1))
			return 0;
	}

	free(extension_nid_list);
	return 1;
}

X509_EXTENSIONS *get_csr_extensions(X509_REQ *csr)
{
	X509_EXTENSIONS *exts = X509_REQ_get_extensions(csr);
// https://github.com/openssl/openssl/pull/18926
#if OPENSSL_VERSION_NUMBER > 0x1010111FL // OPENSSL_VERSION > 1.1.1q
	if(exts == NULL)
		return NULL;
#else // OPENSSL_VERSION <= 1.1.1q
	if(exts == NULL)
	{
		exts = sk_X509_EXTENSION_new_null();
		if(exts == NULL)
			return NULL;
	}
#endif
	return exts;
}

int remove_csr_extensions(X509_REQ *csr)
{
	int ext_req_attr_loc = X509_REQ_get_attr_by_NID(csr,NID_ext_req,-1);
	if(ext_req_attr_loc != -1)
	{
		X509_ATTRIBUTE *attr = X509_REQ_delete_attr(csr,ext_req_attr_loc);
		if(attr == NULL)
			return 0;
		X509_ATTRIBUTE_free(attr);
	}
	return 1;
}

BASIC_CONSTRAINTS *create_basic_constraints_internal(struct basic_constraints basic_constraints)
{
	BASIC_CONSTRAINTS *bcons = BASIC_CONSTRAINTS_new();
	if(!bcons)
		return 0;
	if(basic_constraints.ca == 1)
		bcons->ca = 1;
	else
		bcons->ca = 0;
	if(basic_constraints.pathlen >= 0)
	{
		ASN1_INTEGER *plen = ASN1_INTEGER_new();
		if(plen == NULL)
		{
			BASIC_CONSTRAINTS_free(bcons);
			return 0;
		}
		if(!ASN1_INTEGER_set(plen,basic_constraints.pathlen))
		{
			BASIC_CONSTRAINTS_free(bcons);
			return 0;
		}
		bcons->pathlen = plen;
	}
	return bcons;
}

int set_extension_basic_constraints(X509 *cert, struct basic_constraints basic_constraints)
{
	BASIC_CONSTRAINTS *bcons = create_basic_constraints_internal(basic_constraints);
	if(!X509_add1_ext_i2d(cert,NID_basic_constraints,bcons,1,X509V3_ADD_REPLACE))
	{
		BASIC_CONSTRAINTS_free(bcons);
		return 0;
	}
	BASIC_CONSTRAINTS_free(bcons);
	return 1;
}

int request_extension_basic_constraints(X509_REQ *csr, struct basic_constraints basic_constraints)
{
	BASIC_CONSTRAINTS *bcons = create_basic_constraints_internal(basic_constraints);
	X509_EXTENSIONS *exts = get_csr_extensions(csr);
	if(exts == NULL)
	{
		BASIC_CONSTRAINTS_free(bcons);
		return 0;
	}

	if(!remove_csr_extensions(csr))
	{
		sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
		BASIC_CONSTRAINTS_free(bcons);
		return 0;
	}

	if(!X509V3_add1_i2d(&exts,NID_basic_constraints,bcons,1,X509V3_ADD_REPLACE))
	{
		sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
		BASIC_CONSTRAINTS_free(bcons);
		return 0;
	}

	if(!X509_REQ_add_extensions(csr,exts))
	{
		sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
		BASIC_CONSTRAINTS_free(bcons);
		return 0;
	}

	sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
	BASIC_CONSTRAINTS_free(bcons);
	return 1;
}

int set_extension_key_usage(X509 *cert, unsigned int key_usage)
{
	int max_flag = (1 << key_usage_list_num) - 1;
	if(max_flag < key_usage)
		return 0;

	ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
	if(!bs)
		return 0;

	int bit = 0;
	while(key_usage)
	{
		if(key_usage & 0x01)
		{
			if(!ASN1_BIT_STRING_set_bit(bs,bit,1))
			{
				ASN1_BIT_STRING_free(bs);
				return 0;
			}
		}
		key_usage >>= 1;
		bit++;
	}
	if(X509_add1_ext_i2d(cert,NID_key_usage,bs,1,X509V3_ADD_REPLACE) < 1)
	{
		ASN1_BIT_STRING_free(bs);
		return 0;
	}
	ASN1_BIT_STRING_free(bs);
	return 1;
}

unsigned int get_extension_key_usage_bit_by_name(const char *name)
{
	for(int i = 0;i < key_usage_list_num;i++)
	{
		if(strcasecmp(name,key_usage_list[i].name) == 0)
			return key_usage_list[i].bit;
	}
	return 0;
}

int set_extension_extended_key_usage(X509 *cert, unsigned int extended_key_usage)
{
	int max_flag = (1 << extended_key_usage_list_num) - 1;
	if(max_flag < extended_key_usage)
		return 0;

	EXTENDED_KEY_USAGE* extku = EXTENDED_KEY_USAGE_new();
	int idx = 0;
	while(extended_key_usage)
	{
		if(extended_key_usage & 0x1)
		{
			ASN1_OBJECT *obj = OBJ_txt2obj(extended_key_usage_list[idx].name,0);
			sk_ASN1_OBJECT_push(extku,obj);
			ASN1_OBJECT_free(obj);
		}
		idx++;
		extended_key_usage >>= 1;
	}

	X509_add1_ext_i2d(cert,NID_ext_key_usage,extku,0,X509V3_ADD_REPLACE);
	EXTENDED_KEY_USAGE_free(extku);

	return 1;
}

unsigned get_extension_extended_key_usage_bit_by_name(const char *name)
{
	for(int i = 0;i < extended_key_usage_list_num;i++)
	{
		if(strcasecmp(name,extended_key_usage_list[i].name) == 0)
			return extended_key_usage_list[i].bit;
	}
	return 0;
}

int set_extension_subject_alt_name(X509 *cert, struct subject_alt_name *list,int num)
{
	GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
	if(gens == NULL)
		return 0;

	for(int i = 0;i < num;i++)
	{
		GENERAL_NAME *gen = GENERAL_NAME_new();
		if(gen == NULL)
		{
			sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
			return 0;
		}

		ASN1_OCTET_STRING *oct_str = NULL;
		switch(list[i].type)
		{
			case SAN_TYPE_DNS:
			case SAN_TYPE_EMAIL:
			case SAN_TYPE_URI:
				ASN1_IA5STRING *str = ASN1_IA5STRING_new();
				if(str == NULL)
				{
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				if(!ASN1_STRING_set(str,list[i].value,strlen(list[i].value)))
				{
					ASN1_IA5STRING_free(str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				GENERAL_NAME_set0_value(gen,list[i].type,str);
				if(!sk_GENERAL_NAME_push(gens,gen))
				{
					ASN1_IA5STRING_free(str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
			break;
			case SAN_TYPE_IPV4:
				oct_str = ASN1_OCTET_STRING_new();
				if(str == NULL)
				{
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				if(!ASN1_OCTET_STRING_set(oct_str,(unsigned char*)list[i].value,4))
				{
					ASN1_OCTET_STRING_free(oct_str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				GENERAL_NAME_set0_value(gen,GEN_IPADD,oct_str);
				if(!sk_GENERAL_NAME_push(gens,gen))
				{
					ASN1_OCTET_STRING_free(oct_str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
			break;
			case SAN_TYPE_IPV6:
				oct_str = ASN1_OCTET_STRING_new();
				if(str == NULL)
				{
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				if(!ASN1_OCTET_STRING_set(oct_str,(unsigned char*)list[i].value,16))
				{
					ASN1_OCTET_STRING_free(oct_str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
				GENERAL_NAME_set0_value(gen,GEN_IPADD,oct_str);
				if(!sk_GENERAL_NAME_push(gens,gen))
				{
					ASN1_OCTET_STRING_free(oct_str);
					sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
					return 0;
				}
			break;
			default:
				sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
				return 0;
		}
	}

	if(!X509_add1_ext_i2d(cert,NID_subject_alt_name,gens,0,X509V3_ADD_REPLACE))
	{
		sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
		return 0;
	}

	sk_GENERAL_NAME_pop_free(gens,GENERAL_NAME_free);
	return 1;
}

int set_skid(X509 *cert)
{
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH];
	unsigned int len;
	ASN1_STRING *oct_string = ASN1_STRING_new();
	if(!oct_string)
		return 0;
	if(!X509_pubkey_digest(cert,EVP_sha1(),pubkey_hash,&len))
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	if(!ASN1_STRING_set(oct_string,pubkey_hash,SHA_DIGEST_LENGTH))
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	if(X509_add1_ext_i2d(cert,NID_subject_key_identifier,oct_string,0,X509V3_ADD_REPLACE) < 1)
	{
		ASN1_STRING_free(oct_string);
		return 0;
	}
	ASN1_STRING_free(oct_string);
	return 1;
}

int set_akid_from_x509_skid(X509 *to, X509 *from)
{
	int ext_loc = X509_get_ext_by_NID(from,NID_subject_key_identifier,-1);
	if(ext_loc == -1)
		return 0;
	X509_EXTENSION *root_ca_subject_key_id = X509_get_ext(from,ext_loc);
	if(root_ca_subject_key_id == NULL)
		return 0;
	ASN1_STRING *ext_data = X509_EXTENSION_get_data(root_ca_subject_key_id);
	const unsigned char *data = ASN1_STRING_get0_data(ext_data);
	ASN1_STRING *issuer_subject_key_id = NULL;
	if(d2i_ASN1_OCTET_STRING(&issuer_subject_key_id,&data,ASN1_STRING_length(ext_data)) == NULL)
		return 0;

	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if(!akid)
		return 0;
	akid->keyid = issuer_subject_key_id;
	if(X509_add1_ext_i2d(to,NID_authority_key_identifier,akid,0,X509V3_ADD_REPLACE) < 1)
	{
		AUTHORITY_KEYID_free(akid);
		return 0;
	}
	AUTHORITY_KEYID_free(akid);
	return 1;
}

