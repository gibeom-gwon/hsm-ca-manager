#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "hexstring.h"

int is_hexstring(const char *str)
{
	const char *c = str;
	while(*c)
	{
		if( ('a' > *c || 'f' < *c) &&
			('A' > *c || 'F' < *c) &&
			('0' > *c || '9' < *c))
		{
			return 0;
		}
		c++;
	}
	return 1;
}

char *hexstring_to_uri_encoded(const char *str)
{
	int padding = 0;

	if(!is_hexstring(str))
		return NULL;

	size_t alloc_size = strlen(str);
	if(alloc_size % 2)
	{
		alloc_size++;
		padding = 1;
	}
	alloc_size += (alloc_size / 2);
	alloc_size++;

	char *result = malloc(alloc_size);
	if(result == NULL)
		return NULL;

	const char *c = str;
	int idx = 0;
	if(padding)
	{
		result[0] = '%';
		result[1] = '0';
		idx = 2;
	}

	while(*c)
	{
		if(idx % 3 == 0)
			result[idx++] = '%';
		if('A' <= *c && *c <= 'Z')
			result[idx++] = *c + ('a' - 'A');
		else
			result[idx++] = *c;
		c++;
	}
	result[alloc_size - 1] = 0;

	return result;
}

int hexstring_to_list(const char *str, unsigned char **list)
{
	int idx = 0;

	if(!is_hexstring(str))
		return -EINVAL;

	size_t alloc_size = strlen(str);
	if(alloc_size % 2)
	{
		alloc_size++;
		idx = 1;
	}
	alloc_size /= 2;

	unsigned char *result = malloc(alloc_size);
	if(result == NULL)
		return -ENOMEM;
	memset(result,0,alloc_size);

	const char *c = str;
	while(*c)
	{
		int buff_idx = idx / 2;

		if('A' <= *c && *c <= 'Z')
			result[buff_idx] += (*c - 'A') + 10;
		else if('a' <= *c && *c <= 'z')
			result[buff_idx] += (*c - 'a') + 10;
		else
			result[buff_idx] += *c - '0';

		if(idx % 2 == 0)
			result[buff_idx] *= 0x10;
		idx++;
		c++;
	}

	*list = result;
	return alloc_size;
}
