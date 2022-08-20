#ifndef __IP_H__
#define __IP_H__

int parse_ipv4(const char *str, unsigned char **out);
int parse_ipv6(const char *str, unsigned char **out);

#endif
