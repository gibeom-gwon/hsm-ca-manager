#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>
#include "pkcs11_uri.h"
#include "hexstring.h"

char *arg_pkcs11_uri = NULL;
const char *arg_pkcs11_pin = NULL;
const char *arg_pkcs11_serial = NULL;
const char *arg_pkcs11_id = NULL;

int parse_pkcs11_uri(const char *uri, P11KitUri **out)
{
	if(out == NULL)
		return -EFAULT;

	P11KitUri *p11_uri = NULL;
	if(*out == NULL)
	{
		p11_uri = p11_kit_uri_new();
		if(p11_uri == NULL)
			return -ENOMEM;
	}
	else
		p11_uri = *out;

	if(p11_kit_uri_parse(uri,P11_KIT_URI_FOR_ANY,p11_uri) != P11_KIT_URI_OK)
	{
		if(*out == NULL)
			p11_kit_uri_free(p11_uri);
		return -EINVAL;
	}

	if(*out == NULL)
		*out = p11_uri;

	return 0;
}

int iterate_slots(CK_FUNCTION_LIST *module, P11KitUri *uri, CK_SLOT_ID *ret_slot)
{
	CK_SLOT_ID *slot_list = NULL;
	CK_ULONG slot_count = 0;
	int slot_found = 0;
	CK_SLOT_ID found_slot;

	if(module->C_GetSlotList(1,NULL,&slot_count) != CKR_OK)
		return -EAGAIN;
	slot_list = malloc(sizeof(CK_SLOT_ID) * slot_count);
	if(slot_list == NULL)
		return -EAGAIN;
	if(module->C_GetSlotList(1,slot_list,&slot_count) != CKR_OK)
	{
		free(slot_list);
		return -EAGAIN;
	}

	for(int i = 0;i < slot_count;i++)
	{
		CK_SLOT_INFO slot_info;
		if(module->C_GetSlotInfo(slot_list[i],&slot_info) != CKR_OK)
			continue;
		if(!p11_kit_uri_match_slot_info(uri,&slot_info))
			continue;

		CK_TOKEN_INFO token_info;
		if(module->C_GetTokenInfo(slot_list[i],&token_info) != CKR_OK)
			continue;
		if(!p11_kit_uri_match_token_info(uri,&token_info))
			continue;

		if(slot_found)
		{
			free(slot_list);
			return -ENOTUNIQ;
		}
		slot_found = 1;
		found_slot = slot_list[i];
	}

	free(slot_list);
	if(slot_found)
	{
		*ret_slot = found_slot;
		return 0;
	}
	return -EAGAIN;
}

int find_match_slot(CK_FUNCTION_LIST **modules, P11KitUri *uri, CK_FUNCTION_LIST **ret_module, CK_SLOT_ID *ret_slot)
{
	int ret = 0;
	int slot_found = 0;
	CK_FUNCTION_LIST *found_module = NULL;
	CK_SLOT_ID found_slot;
	CK_FUNCTION_LIST **module = modules;

	while(*module != NULL)
	{
		CK_INFO module_info;
		if((*module)->C_GetInfo(&module_info) != CKR_OK)
		{
			module++;
			continue;
		}
		if(!p11_kit_uri_match_module_info(uri,&module_info))
		{
			module++;
			continue;
		}

		if((ret = iterate_slots(*module,uri,&found_slot)) == 0)
		{
			if(!slot_found)
			{
				found_module = *module;
				slot_found = 1;
			}
			else
				return -ENOTUNIQ;
		}
		else if(ret == -EAGAIN)
		{
			module++;
			continue;
		}
		else
			return ret;
		module++;
	}

	if(!slot_found)
		return -ENOKEY;
	else
	{
		*ret_slot = found_slot;
		*ret_module = found_module;
	}
	return 0;
}

int start_session(CK_FUNCTION_LIST *module, CK_SLOT_ID slot, int rw, CK_SESSION_HANDLE *session)
{
	CK_FLAGS flag = CKF_SERIAL_SESSION;
	if(rw)
		flag |= CKF_RW_SESSION;
	if(module->C_OpenSession(slot,flag,NULL,NULL,session) != CKR_OK)
		return -ENOTSUP;
	return 0;
}

int end_session(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session)
{
	if(module->C_CloseSession(session) != CKR_OK)
		return -ENOTSUP;
	return 0;
}

int user_login(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session, const char *pin, int pin_size)
{
	int ret = 0;
	if((ret = module->C_Login(session,CKU_USER,(CK_UTF8CHAR*)pin,pin_size)) != CKR_OK)
	{
		if(ret == CKR_PIN_LOCKED)
			fprintf(stderr,"PIN locked\n");
		else if(ret == CKR_PIN_INCORRECT)
			fprintf(stderr,"Wrong PIN\n");
		else if(ret == CKR_PIN_LEN_RANGE)
			fprintf(stderr,"Invalid PIN length\n");
		else
			fprintf(stderr,"other error %x\n",ret);
		return -EPERM;
	}

	return 0;
}

int logout(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session)
{
	if(module->C_Logout(session) != CKR_OK)
	{
		fprintf(stderr,"Logout failed\n");
		return -ENOTSUP;
	}

	return 0;
}

int create_attribute_list_from_pre_list(CK_ATTRIBUTE **list, CK_ULONG *count, CK_ATTRIBUTE *pre_list, CK_ULONG pre_list_num)
{
	if(list == NULL || pre_list == NULL || pre_list_num == 0)
		return -EFAULT;

	CK_ATTRIBUTE *buff = malloc(sizeof(CK_ATTRIBUTE) * pre_list_num);
	if(buff == NULL)
		return -ENOMEM;

	for(*count = 0;*count < pre_list_num;(*count)++)
		buff[*count] = pre_list[*count];

	*list = buff;
	return 0;
}

int append_attribute(CK_ATTRIBUTE **list, CK_ULONG *count, CK_ATTRIBUTE attr)
{
	if(list == NULL || count == NULL)
		return -EFAULT;

	CK_ATTRIBUTE *buff = NULL;
	if(*list == NULL)
		buff = malloc(sizeof(CK_ATTRIBUTE));
	else
		buff = realloc(*list,sizeof(CK_ATTRIBUTE) * (*count + 1));
	if(buff == NULL)
		return -ENOMEM;

	if(*list == NULL)
		*count = 1;
	else
		(*count)++;

	buff[*count - 1] = attr;
	*list = buff;
	return 0;
}

int generate_keypair(P11KitUri *uri)
{
	int ret = 0;
	CK_FUNCTION_LIST **modules = p11_kit_modules_load_and_initialize(0);
	if(modules == NULL)
		return -ENOTSUP;

	CK_FUNCTION_LIST *module = NULL;
	CK_SLOT_ID slot = 0;
	if((ret = find_match_slot(modules,uri,&module,&slot)) < 0)
	{
		if(ret == -ENOKEY)
			fprintf(stderr,"Token is not available\n");
		else if(ret == -ENOTUNIQ)
			fprintf(stderr,"Multiple tokens matched\n");
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	CK_SESSION_HANDLE session;
	if((ret = start_session(module,slot,1,&session)) < 0)
	{
		fprintf(stderr,"Session start failed\n");
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	const char* pin = arg_pkcs11_pin;
	if(pin == NULL)
		pin = "";

	if((ret = user_login(module,session,pin,strlen(pin))) < 0)
	{
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	CK_OBJECT_HANDLE public_key, private_key;
	CK_ULONG bit = 1024;
	CK_BYTE public_exponent[] = { 0x01,0x00,0x01 };
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		0
	};
	CK_BBOOL t = CK_TRUE;
	CK_BBOOL f = CK_FALSE;

	CK_ULONG public_template_attr_count = 0;
	CK_ULONG private_template_attr_count = 0;
	CK_ATTRIBUTE *public_template = NULL;
	CK_ATTRIBUTE *private_template = NULL;

	CK_ATTRIBUTE public_pre_list[] = {
		{CKA_ENCRYPT,&t,sizeof(t)},
		{CKA_VERIFY,&t,sizeof(t)},
	};

	CK_BYTE *id = NULL;
	CK_ULONG id_len= 0;

	if(arg_pkcs11_id)
	{
		if((ret = hexstring_to_list(arg_pkcs11_id,&id)) < 0)
		{
			logout(module,session);
			end_session(module,session);
			p11_kit_modules_finalize_and_release(modules);
			return ret;
		}
		id_len = ret;
	}

	if((ret = create_attribute_list_from_pre_list(
						&public_template,
						&public_template_attr_count,
						public_pre_list,
						sizeof(public_pre_list) / sizeof(CK_ATTRIBUTE))) < 0)
	{
		logout(module,session);
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	CK_ATTRIBUTE attr = {CKA_MODULUS_BITS,&bit,sizeof(bit)};
	if((ret = append_attribute(&public_template,&public_template_attr_count,attr)) < 0)
	{
		free(public_template);
		logout(module,session);
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return  ret;
	}

	attr = (CK_ATTRIBUTE){CKA_PUBLIC_EXPONENT,&public_exponent,sizeof(public_exponent)};
	if((ret = append_attribute(&public_template,&public_template_attr_count,attr)) < 0)
	{
		free(public_template);
		logout(module,session);
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return  ret;
	}

	CK_ATTRIBUTE private_pre_list[] = {
		{CKA_SENSITIVE,&f,sizeof(f)},
		{CKA_ALWAYS_SENSITIVE,&f,sizeof(f)},
		{CKA_DECRYPT,&t,sizeof(t)},
		{CKA_SIGN,&t,sizeof(t)},
	};

	if((ret = create_attribute_list_from_pre_list(
						&private_template,
						&private_template_attr_count,
						private_pre_list,
						sizeof(private_pre_list) / sizeof(CK_ATTRIBUTE))) < 0)
	{
		free(public_template);
		logout(module,session);
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	if(id)
	{
		attr = (CK_ATTRIBUTE){CKA_ID,id,id_len};
		if((ret = append_attribute(&private_template,&private_template_attr_count,attr)) < 0)
		{
			free(public_template);
			free(private_template);
			logout(module,session);
			end_session(module,session);
			p11_kit_modules_finalize_and_release(modules);
			return  ret;
		}
	}

	if((ret = module->C_GenerateKeyPair(
							session,
							&mechanism,
							public_template,
							public_template_attr_count,
							private_template,
							private_template_attr_count,
							&public_key,
							&private_key)) != CKR_OK)
	{
		fprintf(stderr,"Key pair generation failed %x\n",ret);
		free(public_template);
		free(private_template);
		logout(module,session);
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return -ENOTSUP;
	}

	if(id)
		free(id);
	free(public_template);
	free(private_template);

	if((ret = logout(module,session)) < 0)
	{
		end_session(module,session);
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	if((ret = end_session(module,session)) < 0)
	{
		fprintf(stderr,"End session failed\n");
		p11_kit_modules_finalize_and_release(modules);
		return ret;
	}

	p11_kit_modules_finalize_and_release(modules);
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
			"-p --pkcs11-uri=PKCS11_URI PKCS11 URI of HSM token\n"
			"   --pin=PIN               Pin of HSM\n"
			"   --id=HEXSTRING          Id of key object\n"
			"   --serial=SERIAL         Serial of HSM token\n"
			"-h --help                  Show this help\n",basename);
}

int set_args(int argc, char *argv[])
{
	int ret = 0;
	const char *pkcs11_uri_input = NULL;

	struct option opts[] = {
		{"pkcs11-uri",required_argument,0,'p'},
		{"pin",required_argument,0,'P'},
		{"id",required_argument,0,'I'},
		{"serial",required_argument,0,'S'},
		{"help",no_argument,0,'h'},
		{NULL,0,0,0}
	};

	int opt_idx = 0;
	int r = 0;
	while((r = getopt_long(argc,argv,"p:h",opts,&opt_idx)) > 0)
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
				arg_pkcs11_id = optarg;
				break;
			case 'S':
				arg_pkcs11_serial = optarg;
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

	if(arg_pkcs11_id == NULL)
		arg_pkcs11_id = getenv("PKCS11_ID");

	if(arg_pkcs11_id)
	{
		if(!is_hexstring(arg_pkcs11_id))
		{
			fprintf(stderr,"PKCS11 id is not hexstring\n");
			pkcs11_uri_free(pkcs11_uri);
			return -1;
		}
	}

	if((ret = pkcs11_uri_to_str(pkcs11_uri, &arg_pkcs11_uri)) < 0)
	{
		pkcs11_uri_free(pkcs11_uri);
		if(ret == -ENOMEM)
			fprintf(stderr,"Out of memory\n");
		return ret;
	}

	pkcs11_uri_free(pkcs11_uri);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	if((ret = set_args(argc, argv)) < 0)
		return ret;

	P11KitUri *p11_uri = NULL;
	if((ret = parse_pkcs11_uri(arg_pkcs11_uri,&p11_uri)) < 0)
		goto cleanup;

	if(generate_keypair(p11_uri) < 0)
		goto cleanup;

	cleanup:
	if(p11_uri)
		p11_kit_uri_free(p11_uri);
	if(arg_pkcs11_uri)
		free(arg_pkcs11_uri);
	return ret;
}
