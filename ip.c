#include <stdlib.h>

unsigned char *parse_ipv4(const char *str)
{
	unsigned char *buff = malloc(sizeof(unsigned char) * 4);
	if(buff == NULL)
		return NULL;

	const char *chr = str;
	int oct = 0;
	int num = -1;
	while(*chr != 0)
	{
		if(*chr == '.')
		{
			if(oct >= 3 || num == -1)
			{
				free(buff);
				return NULL;
			}
			buff[oct++] = num;
			num = -1;
		}
		else
		{
			if(*chr < '0' || *chr > '9')
			{
				free(buff);
				return NULL;
			}
			if(num == -1)
				num = *chr - '0';
			else
			{
				num *= 10;
				num += *chr - '0';
			}

			if(num > 255)
			{
				free(buff);
				return NULL;
			}
		}
		chr++;
	}

	if(num == -1)
	{
		free(buff);
		return NULL;
	}
	buff[oct] = num;
	return buff;
}

unsigned char *parse_ipv6(const char *str)
{
	unsigned char *buff = malloc(sizeof(unsigned char) * 16);
	if(buff == NULL)
		return NULL;

	const char *chr = str;
	int oct = 0;
	int num = -1;

	int ellipsis_oct = -1;

	while(*chr != 0)
	{
		if(*chr == ':')
		{
			if(num == -1)
			{
				if(ellipsis_oct != -1)
				{
					free(buff);
					return NULL;
				}
				ellipsis_oct = oct;
				chr++;
				continue;
			}

			if(oct >= 14)
			{
				free(buff);
				return NULL;
			}
			buff[oct++] = num >> 8;
			buff[oct++] = num & 0xFF;
			num = -1;
		}
		else
		{
			int bit = 0;
			if(*chr >= '0' && *chr <= '9')
				bit = *chr - '0';
			else if(*chr >= 'a' && *chr <= 'f')
				bit = *chr - 'a' + 10;
			else if(*chr >= 'A' && *chr <= 'F')
				bit = *chr - 'A' + 10;
			else
			{
				free(buff);
				return NULL;
			}

			if(num == -1)
				num = bit;
			else
			{
				num <<= 4;
				num += bit;
			}

			if(num > 0xFFFF)
			{
				free(buff);
				return NULL;
			}
		}
		chr++;
	}

	if(num != -1)
	{
		buff[oct++] = num >> 8;
		buff[oct++] = num & 0xFF;
	}
	else
	{
		buff[oct++] = 0;
		buff[oct++] = 0;
	}

	if(ellipsis_oct != -1)
	{
		int mov_oct = 16 - oct;

		for(int i = 15; i >= ellipsis_oct;i--)
		{
			if(ellipsis_oct <= i - mov_oct)
				buff[i] = buff[i - mov_oct];
			else
				buff[i] = 0;
		}
	}
	return buff;
}
