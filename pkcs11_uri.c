#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs11_uri.h"

struct pkcs11_kv
{
	char *key;
	char *value;
};

struct pkcs11_uri
{
	struct pkcs11_kv **path_list;
	unsigned int path_count;
	struct pkcs11_kv **query_list;
	unsigned int query_count;
};

int add_kv_to_list(struct pkcs11_kv ***list , unsigned int *len, const char *key, const char *value)
{
	struct pkcs11_kv **new_list = NULL;
	if(list == NULL)
		return 0;

	struct pkcs11_kv *kv = malloc(sizeof(struct pkcs11_kv));
	if(kv == NULL)
		return 0;

	kv->key = strdup(key);
	if(kv->key == NULL)
	{
		free(kv);
		return 0;
	}
	kv->value = strdup(value);
	if(kv->value == NULL)
	{
		free(kv->key);
		free(kv);
		return 0;
	}

	if(*list == NULL)
		new_list = malloc(sizeof(struct pkcs11_kv **));
	else
		new_list = realloc(*list,sizeof(struct pkcs11_kv **) * (*len + 1));
	if(new_list == NULL)
	{
		free(kv->key);
		free(kv->value);
		free(kv);
		return 0;
	}
	*list = new_list;

	(*list)[(*len)++] = kv;
	return 1;
}

int add_path(PKCS11_URI *pkcs11, const char *key, const char *value)
{
	for(unsigned int i = 0;i < pkcs11->path_count;i++)
	{
		if(strcmp(key,pkcs11->path_list[i]->key) == 0)
			return 0;
	}

	if(!add_kv_to_list(&pkcs11->path_list,&pkcs11->path_count,key,value))
		return 0;

	return 1;
}

int add_query(PKCS11_URI *pkcs11, const char *key, const char *value)
{
	if(!add_kv_to_list(&pkcs11->query_list,&pkcs11->query_count,key,value))
		return 0;

	return 1;
}

int parse_uri_path(PKCS11_URI *pkcs11, const char *path_str)
{
	size_t idx = 0;
	int is_key = 1;
	size_t key_start_idx = 0;
	size_t key_end_idx = 0;
	size_t value_start_idx = 0;
	size_t value_end_idx = 0;

	while(path_str[idx] != 0)
	{
		if(is_key)
		{
			if(path_str[idx] == '=')
			{
				is_key = 0;
				if(key_start_idx == key_end_idx)
					return 0;
				value_start_idx = value_end_idx = idx + 1;
			}
			else if(path_str[idx] == ';' && key_start_idx == key_end_idx)
				key_start_idx = key_end_idx = idx;
			else if(
				path_str[idx] == '-' || path_str[idx] == '_' ||
				('a' <= path_str[idx] && path_str[idx] <= 'z') ||
				('A' <= path_str[idx] && path_str[idx] <= 'Z') ||
				('A' <= path_str[idx] && path_str[idx] <= 'Z') ||
				('0' <= path_str[idx] && path_str[idx] <= '9'))
			{
				key_end_idx = idx;
			}
			else
				return 0;
		}
		else
		{
			if(path_str[idx] == ';')
			{
				is_key = 1;

				char *key = strndup(path_str + key_start_idx,key_end_idx - key_start_idx + 1);
				char *value = strndup(path_str + value_start_idx,value_end_idx - value_start_idx + 1);

				if(!add_path(pkcs11,key,value))
				{
					free(key);
					free(value);
					return 0;
				}

				free(key);
				free(value);

				key_start_idx = key_end_idx = idx + 1;
			}
			else
				value_end_idx = idx;
		}
		idx++;
	}

	if(is_key == 0 && key_start_idx != key_end_idx)
	{
		char *key = strndup(path_str + key_start_idx,key_end_idx - key_start_idx + 1);
		char *value = strdup(path_str + value_start_idx);

		if(!add_path(pkcs11,key,value))
		{
			free(key);
			free(value);
			return 0;
		}

		free(key);
		free(value);
	}
	else if(is_key == 1 && key_start_idx != key_end_idx)
		return 0;

	return 1;
}

int parse_uri_query(PKCS11_URI *pkcs11, const char *query_str)
{
	size_t idx = 0;
	int is_key = 1;
	size_t key_start_idx = 0;
	size_t key_end_idx = 0;
	size_t value_start_idx = 0;
	size_t value_end_idx = 0;

	while(query_str[idx] != 0)
	{
		if(is_key)
		{
			if(query_str[idx] == '=')
			{
				is_key = 0;
				if(key_start_idx == key_end_idx)
					return 0;
				value_start_idx = value_end_idx = idx + 1;
			}
			else if(query_str[idx] == '&' && key_start_idx == key_end_idx)
				key_start_idx = key_end_idx = idx;
			else if(
				query_str[idx] == '-' || query_str[idx] == '_' ||
				('a' <= query_str[idx] && query_str[idx] <= 'z') ||
				('A' <= query_str[idx] && query_str[idx] <= 'Z') ||
				('A' <= query_str[idx] && query_str[idx] <= 'Z') ||
				('0' <= query_str[idx] && query_str[idx] <= '9'))
			{
				key_end_idx = idx;
			}
			else
				return 0;
		}
		else
		{
			if(query_str[idx] == '&')
			{
				is_key = 1;

				char *key = strndup(query_str + key_start_idx,key_end_idx - key_start_idx + 1);
				char *value = strndup(query_str + value_start_idx,value_end_idx - value_start_idx + 1);

				if(!add_query(pkcs11,key,value))
				{
					free(key);
					free(value);
					return 0;
				}

				free(key);
				free(value);

				key_start_idx = key_end_idx = idx + 1;
			}
			else
				value_end_idx = idx;
		}
		idx++;
	}

	if(is_key == 0 && key_start_idx != key_end_idx)
	{
		char *key = strndup(query_str + key_start_idx,key_end_idx - key_start_idx + 1);
		char *value = strdup(query_str + value_start_idx);

		if(!add_query(pkcs11,key,value))
		{
			free(key);
			free(value);
			return 0;
		}

		free(key);
		free(value);
	}
	else if(is_key == 1 && key_start_idx != key_end_idx)
		return 0;

	return 1;
}

PKCS11_URI *pkcs11_uri_parse(const char *uri_string)
{
	PKCS11_URI *pkcs11 = NULL;
	if(uri_string == NULL)
		return NULL;

	if(strncmp("pkcs11:",uri_string,7) != 0)
		return NULL;

	pkcs11 = malloc(sizeof(struct pkcs11_uri));
	pkcs11->path_list = NULL;
	pkcs11->path_count = 0;
	pkcs11->query_list = NULL;
	pkcs11->query_count = 0;

	char *query_start = strchr(uri_string,'?');
	if(query_start == NULL)
	{
		if(!parse_uri_path(pkcs11,uri_string + 7))
		{
			free(pkcs11);
			return NULL;
		}
	}
	else
	{
		char *path = strndup(uri_string + 7,query_start - uri_string - 7);

		if(!parse_uri_path(pkcs11,path))
		{
			free(pkcs11);
			return NULL;
		}

		free(path);

		if(!parse_uri_query(pkcs11,query_start + 1))
		{
			free(pkcs11);
			return NULL;
		}
	}

	return pkcs11;
}

char *pkcs11_uri_to_str(PKCS11_URI *pkcs11)
{
	char *str = strdup("pkcs11:");
	size_t end_idx = 7;
	if(str == NULL)
		return NULL;

	for(unsigned int i = 0;i < pkcs11->path_count;i++)
	{
		struct pkcs11_kv *kv = pkcs11->path_list[i];
		size_t realloc_size = end_idx + strlen(kv->key) + 1 + strlen(kv->value) + 1;
		if(i != 0)
			realloc_size++;
		char *new_str = realloc(str,realloc_size);
		if(new_str == NULL)
		{
			free(str);
			return NULL;
		}
		str = new_str;

		if(i != 0)
			str[end_idx++] = ';';

		size_t len = strlen(kv->key);
		memcpy(str + end_idx,kv->key,len);
		end_idx += len;
		str[end_idx++] = '=';
		len = strlen(kv->value);
		memcpy(str + end_idx,kv->value,len);
		end_idx += len;
		str[end_idx] = 0;
	}

	if(pkcs11->query_count)
		str[end_idx++] = '?';

	for(unsigned int i = 0;i < pkcs11->query_count;i++)
	{
		struct pkcs11_kv *kv = pkcs11->query_list[i];
		size_t realloc_size = end_idx + strlen(kv->key) + 1 + strlen(kv->value) + 1;
		if(i != 0)
			realloc_size++;
		char *new_str = realloc(str,realloc_size);
		if(new_str == NULL)
		{
			free(str);
			return NULL;
		}
		str = new_str;

		if(i != 0)
			str[end_idx++] = '&';

		size_t len = strlen(kv->key);
		memcpy(str + end_idx,kv->key,len);
		end_idx += len;
		str[end_idx++] = '=';
		len = strlen(kv->value);
		memcpy(str + end_idx,kv->value,len);
		end_idx += len;
		str[end_idx] = 0;
	}

	return str;
}

void pkcs11_uri_free(PKCS11_URI *pkcs11)
{
	struct pkcs11_kv **list = pkcs11->path_list;
	if(list != NULL)
	{
		for(unsigned int i = 0;i < pkcs11->path_count;i++)
		{
			free(list[i]->key);
			free(list[i]->value);
			free(list[i]);
		}
		free(list);
	}

	list = pkcs11->query_list;
	if(list != NULL)
	{
		for(unsigned int i = 0;i < pkcs11->query_count;i++)
		{
			free(list[i]->key);
			free(list[i]->value);
			free(list[i]);
		}
		free(list);
	}
	free(pkcs11);
}
