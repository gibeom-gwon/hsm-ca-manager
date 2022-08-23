#ifndef __HEXSTRING_H__
#define __HEXSTRING_H__

int is_hexstring(const char *str);
char *hexstring_to_uri_encoded(const char *str);
int hexstring_to_list(const char *str, unsigned char **list);

#endif
