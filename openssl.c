#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include "openssl.h"

const char *ssl_get_error_string()
{
	return ERR_reason_error_string(ERR_get_error());
}
