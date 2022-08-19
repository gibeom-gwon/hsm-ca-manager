#include <string.h>
#include <stdlib.h>
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
